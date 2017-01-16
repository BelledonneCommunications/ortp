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


void ortp_congestion_detector_reset(OrtpCongestionDetector *cd) {
	if (cd->state!=CongestionStateNormal) {
		ortp_message("Congestion detection from %s canceled"
				, cd->state==CongestionStatePending?"TO CONFIRM...":"IN CONGESTION!");
	}
	cd->state = CongestionStateNormal;
	cd->start_ms = (uint64_t)-1;
	cd->start_jitter_ts = 0;
}

OrtpCongestionDetector * ortp_congestion_detector_new(RtpSession *session) {
	OrtpCongestionDetector *cd = (OrtpCongestionDetector*)ortp_malloc0(sizeof(OrtpCongestionDetector));
	ortp_congestion_detector_reset(cd);
	cd->initialized = FALSE;
	cd->session = session;

	return cd;
}

bool_t ortp_congestion_detector_record(OrtpCongestionDetector *cd, uint32_t packet_ts, uint32_t cur_str_ts) {
	bool_t state_changed = FALSE;
	int64_t diff=(int64_t)packet_ts - (int64_t)cur_str_ts;
	bool_t clock_drift;
	float jitter;
	JitterControl *jitterctl = &cd->session->rtp.jittctl;
	bool_t has_jitter;

	if (!cd->initialized) {
		cd->initialized = TRUE;
		ortp_kalman_rls_init(&cd->rls, 1, (double)diff);
		cd->rls.lambda = 0.95f;
	}

	ortp_kalman_rls_record(&cd->rls, cur_str_ts, packet_ts);

	clock_drift = cd->rls.m < 0.9;
	jitter = labs((long)(diff - jitterctl->clock_offset_ts) /*cd->start_jitter_ts*/) * 1000.f / jitterctl->clock_rate;
	has_jitter = jitter > 300.f;

	ortp_debug(
		"%s clock=%f"
		", diff=%ld"
		", %f >? 300.f"
		", clock_rate=%d"
		", jb_slide=%f, jb_clock=%f"
		", down_bw=%0.f, up_bw=%0.f kbits/s"
		, cd->state==CongestionStateNormal?"":cd->state==CongestionStatePending?"TO CONFIRM...":"IN CONGESTION!"
		, cd->rls.m
		, (long)diff
		, jitter
		, jitterctl->clock_rate
		, jitterctl->kalman_rls.b, jitterctl->kalman_rls.m
		, rtp_session_get_recv_bandwidth_smooth(cd->session)*1e-3, rtp_session_get_send_bandwidth_smooth(cd->session)*1e-3
	);

	switch (cd->state) {
		case CongestionStateNormal:
			if (clock_drift) {
				cd->start_ms = ortp_get_cur_time_ms();
				cd->start_jitter_ts = (int64_t)jitterctl->kalman_rls.b;
				ortp_message("Congestion detection starts current jitter=%f...", jitterctl->kalman_rls.b);
				cd->state = CongestionStatePending;
				state_changed = TRUE;
			}
			break;
		case CongestionStatePending:
			if (!clock_drift && !has_jitter) {
				// congestion has stopped - reinit everything
				ortp_congestion_detector_reset(cd);
			} else {
				// congestion continues - if it has been for longer enough, trigger congestion flag
				if (ortp_get_cur_time_ms() - cd->start_ms > congestion_pending_duration_ms) {
					ortp_warning("In congestion for more than %d seconds, trigger flag!", congestion_pending_duration_ms / 1000);
					cd->state = CongestionStateDetected;
					state_changed = TRUE;
				}
			}
			break;
		case CongestionStateDetected:
			if (!clock_drift && !has_jitter) {
				// congestion has stopped - reinit everything
				ortp_congestion_detector_reset(cd);
				state_changed = TRUE;
			}
			break;
	}
	return state_changed;
}

void ortp_congestion_detector_destroy(OrtpCongestionDetector *obj){
	ortp_free(obj);
}

