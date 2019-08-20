/*
 * Copyright (c) 2010-2019 Belledonne Communications SARL.
 *
 * This file is part of oRTP.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "congestiondetector.h"

#include <ortp/logging.h>
#include <math.h>

#include <ortp/rtpsession.h>

static const unsigned int congestion_pending_duration_ms = 5000;
static const float return_from_suspected_max_loss_rate = 5.0;
static const float absolute_congested_clock_ratio = 0.93f;
static const float relative_congested_clock_ratio = 0.96f;
static const float rls_forgetting_factor = 0.97f;

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
	cd->too_much_loss = FALSE;
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

static float ortp_congestion_detector_get_loss_rate(OrtpCongestionDetector *cd){
	uint32_t cur_loss = (uint32_t)cd->session->stats.cum_packet_loss;
	uint32_t cur_seq = rtp_session_get_rcv_ext_seq_number(cd->session);
	uint32_t expected = cur_seq - cd->seq_begin;
	
	if (expected == 0) return 0;
	return 100.0f*(float)(cur_loss - cd->loss_begin) / (float)expected;
}

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
		cd->rls.lambda = rls_forgetting_factor;
		if (jitterctl->params.buffer_algorithm != OrtpJitterBufferRecursiveLeastSquare){
			ortp_error("ortp congestion detection requires RLS jitter buffer algorithm.");
			cd->skip = TRUE;
		}
	}

	ortp_kalman_rls_record(&cd->rls, cur_str_ts, packet_ts);

	if (cd->rls.m < 0) {
		/*
		 * This can arrive when packets arrive in a very chaotic way during the first seconds of a call.
		 * There is no usable information as long as the rls hasn't yet converged.
		 */
		return binary_state_changed;
	}
	
	clock_drift = cd->rls.m < absolute_congested_clock_ratio || jitterctl->capped_clock_ratio < absolute_congested_clock_ratio
		|| cd->rls.m < relative_congested_clock_ratio * jitterctl->capped_clock_ratio ;
	//deviation = ((int32_t)(packet_ts - local_ts_to_remote_ts_rls(cd->rls.m, cd->rls.b, cur_str_ts))) / (float)jitterctl->clock_rate;
	//deviation = ortp_extremum_get_current(&jitterctl->max_ts_deviation)/(float)jitterctl->clock_rate;
	//has_jitter = deviation > acceptable_deviation;

	/*
	if (jitterctl->clock_rate == 90000){
		ortp_message(
			"OrtpCongestionDetector state=%s clock=%f"
			", jb->capped_clock_ratio=%f"
			", down_bw=%0.f, up_bw=%0.f kbits/s"
			, ortp_congestion_detector_state_to_string(cd->state)
			, cd->rls.m
			, jitterctl->capped_clock_ratio
			, rtp_session_get_recv_bandwidth_smooth(cd->session)*1e-3, rtp_session_get_send_bandwidth_smooth(cd->session)*1e-3
		);
	}
	*/

	switch (cd->state) {
		case CongestionStateNormal:
			if (clock_drift) {
				cd->start_ms = ortp_get_cur_time_ms();
				cd->loss_begin = (uint32_t)cd->session->stats.cum_packet_loss;
				cd->seq_begin = rtp_session_get_rcv_ext_seq_number(cd->session);
				cd->last_packet_recv = cd->start_ms;
				binary_state_changed = ortp_congestion_detector_set_state(cd, CongestionStateSuspected);
			}
		break;
		case CongestionStateSuspected:
		{
			uint64_t curtime = ortp_get_cur_time_ms();
			if (!clock_drift) {
				float loss_rate = ortp_congestion_detector_get_loss_rate(cd);
				if (loss_rate >= return_from_suspected_max_loss_rate){
					if (!cd->too_much_loss){
						ortp_message("OrtpCongestionDetector: loss rate is [%f], too much for returning to CongestionStateNormal state.", loss_rate);
						cd->too_much_loss = TRUE;
					}
				}else{
					// congestion has maybe stopped 
					binary_state_changed = ortp_congestion_detector_set_state(cd, CongestionStateNormal);
				}
			} else {
				
				if (curtime - cd->last_packet_recv >= 1000){
					/*no packet received during last second ! 
					 It means that the drift measure is not very significant, and futhermore the banwdith computation will be 
					 near to zero. It makes no sense to trigger a congestion detection in this case; the network is simply not working.
					 */
					binary_state_changed = ortp_congestion_detector_set_state(cd, CongestionStateNormal);
				}else{
					// congestion continues - if it has been for longer enough, trigger congestion flag
					if (curtime - cd->start_ms > congestion_pending_duration_ms) {
						binary_state_changed = ortp_congestion_detector_set_state(cd, CongestionStateDetected);
					}
				}
			}
			cd->last_packet_recv = curtime;
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