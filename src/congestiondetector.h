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


#ifndef CONGESTIONDETECTOR_H
#define CONGESTIONDETECTOR_H

#include <ortp/port.h>
#include <ortp/utils.h>
#include <bctoolbox/list.h>
struct _JitterControl;

typedef enum _OrtpCongestionState {
	CongestionStateNormal,
	CongestionStateSuspected,
	CongestionStateDetected,
	CongestionStateResolving
} OrtpCongestionState;

typedef struct _OrtpCongestionDetector{
	OrtpKalmanRLS rls;
	uint64_t start_ms;
	uint64_t last_packet_recv;
	uint32_t loss_begin, seq_begin;
	bool_t initialized;
	bool_t is_in_congestion;
	bool_t skip;
	bool_t too_much_loss;
	OrtpCongestionState state;
	struct _RtpSession *session;
}OrtpCongestionDetector;

OrtpCongestionDetector * ortp_congestion_detector_new(struct _RtpSession *session);

/*
 * Returns TRUE if the congestion state is changed.
**/
bool_t ortp_congestion_detector_record(OrtpCongestionDetector *obj, uint32_t packet_ts, uint32_t cur_str_ts);

void ortp_congestion_detector_destroy(OrtpCongestionDetector *obj);

void ortp_congestion_detector_reset(OrtpCongestionDetector *cd);

#endif
