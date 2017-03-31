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
	struct _OrtpVideoBandwidthDetector *vbd;
}OrtpCongestionDetector;

typedef struct _OrtpVideoBandwidthDetectorPacket{
	unsigned int index;
	uint32_t sent_timestamp;
	struct timeval recv_first_timestamp;
	struct timeval recv_last_timestamp;
	unsigned int bytes;
	unsigned int count;
	float bitrate;
}OrtpVideoBandwidthDetectorPacket;

typedef struct _OrtpVideoBandwidthDetector{
	unsigned int packet_count_min;
	unsigned int packets_size_max;
	unsigned int trust_percentage;
	OrtpVideoBandwidthDetectorPacket *last_packet;
	bctbx_list_t *packets;
}OrtpVideoBandwidthDetector;

OrtpCongestionDetector * ortp_congestion_detector_new(struct _RtpSession *session);

/*
 * Returns TRUE if the congestion state is changed.
**/
bool_t ortp_congestion_detector_record(OrtpCongestionDetector *obj, uint32_t packet_ts, uint32_t cur_str_ts);

void ortp_congestion_detector_destroy(OrtpCongestionDetector *obj);

void ortp_congestion_detector_reset(OrtpCongestionDetector *cd);

void ortp_congestion_detector_setup_video_bandwidth_detector(OrtpCongestionDetector *cd, int count, int size_max, int trust);

void ortp_video_bandwidth_detector_process_packet(OrtpVideoBandwidthDetector *vbd, uint32_t sent_timestamp, const struct timeval *recv_timestamp, int msgsize, bool_t is_last);

int ortp_video_bandwidth_detector_get_estimated_available_bandwidth(OrtpVideoBandwidthDetector *vbd);
#endif
