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


#ifndef CONGESTIONDETECTOR_H
#define CONGESTIONDETECTOR_H

#include <ortp/port.h>
#include <ortp/utils.h>
struct _JitterControl;

typedef enum _OrtpCongestionState {
	CongestionStateNormal = 1 << 0,
	CongestionStatePending = 1 << 1,
	CongestionStateDetected = 1 << 2
} OrtpCongestionState;

typedef struct _OrtpCongestionDetector{
	OrtpKalmanRLS rls;
	uint64_t start_ms;
	int64_t start_jitter_ts;
	bool_t initialized;
	bool_t pad[3];
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
