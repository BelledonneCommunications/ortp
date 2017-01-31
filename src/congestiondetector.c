/*
 * The oRTP library is an RTP (Realtime Transport Protocol - rfc3550) implementation with additional features.
 * Copyright (C) 2017 Belledonne Communications SARL
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "congestiondetector.h"

#include <ortp/logging.h>
#include <math.h>

#include <ortp/rtpsession.h>

static const unsigned int congestion_pending_duration_ms = 5000;
static const float congested_clock_ratio = 0.93f;

const char *ortp_congestion_detector_state_to_string(OrtpCongestionState state){
	switch (state){
		case CongestionStateNormal:
			return "CongestionStateNormal";
		break;
		case CongestionStateSuspected:
			return "CongestionStatePending";
		break;
		case CongestionStateDetected:
			return "CongestionStateDetected";
		break;
		case CongestionStateResolving:
			return "CongestionStateResolving";
		break;
	}
	return "invalid state";
}

static bool_t ortp_congestion_detector_set_state(OrtpCongestionDetector *cd, OrtpCongestionState state){
	bool_t binary_state_changed = FALSE;
	if (state == cd->state) return FALSE;
	ortp_message("OrtpCongestionDetector: moving from state %s to state %s", 
		     ortp_congestion_detector_state_to_string(cd->state),
		     ortp_congestion_detector_state_to_string(state));
	cd->state = state;
	if (state == CongestionStateDetected){
		if (!cd->is_in_congestion){
			cd->is_in_congestion = TRUE;
			binary_state_changed = TRUE;
		}
	}else if (state == CongestionStateNormal){
		cd->start_ms = (uint64_t)-1;
		if (cd->is_in_congestion){
			cd->is_in_congestion = FALSE;
			binary_state_changed = TRUE;
		}
	}
	return binary_state_changed;
}

void ortp_congestion_detector_reset(OrtpCongestionDetector *cd) {
	cd->initialized = FALSE;
	cd->skip = FALSE;
	ortp_congestion_detector_set_state(cd, CongestionStateNormal);
}

OrtpCongestionDetector * ortp_congestion_detector_new(RtpSession *session) {
	OrtpCongestionDetector *cd = (OrtpCongestionDetector*)ortp_malloc0(sizeof(OrtpCongestionDetector));
	cd->session = session;
	ortp_congestion_detector_reset(cd);
	return cd;
}

/*
static uint32_t local_ts_to_remote_ts_rls(double clock_ratio, double offset, uint32_t local_ts){
	return (uint32_t)( (int64_t)(clock_ratio*(double)local_ts) + (int64_t)offset);
}
*/

bool_t ortp_congestion_detector_record(OrtpCongestionDetector *cd, uint32_t packet_ts, uint32_t cur_str_ts) {
	bool_t binary_state_changed = FALSE;
	bool_t clock_drift;
	JitterControl *jitterctl = &cd->session->rtp.jittctl;
	//float deviation;

	if (cd->skip) return FALSE;
	
	packet_ts -= jitterctl->remote_ts_start;
	cur_str_ts -= jitterctl->local_ts_start;
	
	if (!cd->initialized) {
		cd->initialized = TRUE;
		ortp_kalman_rls_init(&cd->rls, 1, packet_ts - cur_str_ts);
		cd->rls.lambda = 0.99f;
		if (jitterctl->params.buffer_algorithm != OrtpJitterBufferRecursiveLeastSquare){
			ortp_error("ortp congestion detection requires RLS jitter buffer algorithm.");
			cd->skip = TRUE;
		}
	}

	ortp_kalman_rls_record(&cd->rls, cur_str_ts, packet_ts);

	clock_drift = cd->rls.m < congested_clock_ratio || cd->rls.m < congested_clock_ratio * jitterctl->capped_clock_ratio || jitterctl->capped_clock_ratio < congested_clock_ratio ;
	//deviation = ((int32_t)(packet_ts - local_ts_to_remote_ts_rls(cd->rls.m, cd->rls.b, cur_str_ts))) / (float)jitterctl->clock_rate;
	//deviation = ortp_extremum_get_current(&jitterctl->max_ts_deviation)/(float)jitterctl->clock_rate;
	//has_jitter = deviation > acceptable_deviation;

	ortp_debug(
		"OrtpCongestionDetector state=%s clock=%f"
		", jb->deviation=%f, jb->capped_clock_ratio=%f"
		", down_bw=%0.f, up_bw=%0.f kbits/s"
		, ortp_congestion_detector_state_to_string(cd->state)
		, cd->rls.m
		, deviation, jitterctl->capped_clock_ratio
		, rtp_session_get_recv_bandwidth_smooth(cd->session)*1e-3, rtp_session_get_send_bandwidth_smooth(cd->session)*1e-3
	);

	switch (cd->state) {
		case CongestionStateNormal:
			if (clock_drift) {
				cd->start_ms = ortp_get_cur_time_ms();
				binary_state_changed = ortp_congestion_detector_set_state(cd, CongestionStateSuspected);
			}
		break;
		case CongestionStateSuspected:
			if (!clock_drift) {
				// congestion has maybe stopped 
				binary_state_changed = ortp_congestion_detector_set_state(cd, CongestionStateNormal);
			} else {
				// congestion continues - if it has been for longer enough, trigger congestion flag
				if (ortp_get_cur_time_ms() - cd->start_ms > congestion_pending_duration_ms) {
					binary_state_changed = ortp_congestion_detector_set_state(cd, CongestionStateDetected);
				}
			}
		break;
		case CongestionStateDetected:
			if (!clock_drift) {
				// congestion is maybe terminated, go resolving state
				binary_state_changed = ortp_congestion_detector_set_state(cd, CongestionStateResolving);
				cd->start_ms = ortp_get_cur_time_ms();
			}
		break;
		case CongestionStateResolving:
			if (clock_drift) {
				binary_state_changed = ortp_congestion_detector_set_state(cd, CongestionStateDetected);
			} else {
				if (ortp_get_cur_time_ms() - cd->start_ms > congestion_pending_duration_ms) {
					binary_state_changed = ortp_congestion_detector_set_state(cd, CongestionStateNormal);
				}
			}
		break;
	}
	return binary_state_changed;
}

void ortp_congestion_detector_destroy(OrtpCongestionDetector *obj){
	ortp_free(obj);
}

