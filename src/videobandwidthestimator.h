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


#ifndef VIDEOBANDWIDTHESTIMATOR_H
#define VIDEOBANDWIDTHESTIMATOR_H

#include <ortp/port.h>
#include <ortp/utils.h>
#include <bctoolbox/list.h>

typedef struct _OrtpVideoBandwidthEstimatorPacket{
	uint32_t sent_timestamp;
	struct timeval recv_first_timestamp;
	struct timeval recv_last_timestamp;
	unsigned int bytes;
	unsigned int count;
	float bitrate;
}OrtpVideoBandwidthEstimatorPacket;

typedef struct _OrtpVideoBandwidthEstimator{
	struct _RtpSession *session;
	unsigned int packet_count_min;
	unsigned int packets_size_max;
	unsigned int trust_percentage;
	OrtpVideoBandwidthEstimatorPacket *last_packet;
	bctbx_list_t *packets;
	uint32_t last_computed;
    int nb_packets_computed;
}OrtpVideoBandwidthEstimator;

OrtpVideoBandwidthEstimator * ortp_video_bandwidth_estimator_new(struct _RtpSession *session);

void ortp_video_bandwidth_estimator_destroy(OrtpVideoBandwidthEstimator *vbe);

void ortp_video_bandwidth_estimator_reset(OrtpVideoBandwidthEstimator *vbe);

/**
 * Sets the minimum number of packets with the same sent timestamp to be processed continuously before being used.
 * Default value is 7.
 */
void ortp_video_bandwidth_estimator_set_packets_count_min(OrtpVideoBandwidthEstimator *vbe, unsigned int value);

/**
 * Sets the number of packets needed to compute the available video bandwidth.
 * Default value is 30.
 */
void ortp_video_bandwidth_estimator_set_history_max_size(OrtpVideoBandwidthEstimator *vbe, unsigned int value);

/**
 * Sets the percentage for which the chosen bandwidth value in all available will be inferior.
 * Example: for 100 packets with 90% trust, bandwidth value will be the 90th after sorted.
 * Default value is 90.
 */
void ortp_video_bandwidth_estimator_set_trust(OrtpVideoBandwidthEstimator *vbe, unsigned int value);

/**
 * Gets the minimum number of packets with the same sent timestamp to be processed continuously before being used.
 * Default value is 7.
 */
unsigned int ortp_video_bandwidth_estimator_get_packets_count_min(OrtpVideoBandwidthEstimator *vbe);

/**
 * Gets the number of packets needed to compute the available video bandwidth.
 * Default value is 30.
 */
unsigned int ortp_video_bandwidth_estimator_get_history_max_size(OrtpVideoBandwidthEstimator *vbe);

/**
 * Gets the percentage for which the chosen bandwidth value in all available will be inferior.
 * Example: for 100 packets with 90% trust, bandwidth value will be the 90th after sorted.
 * Default value is 90.
 */
unsigned int ortp_video_bandwidth_estimator_get_trust(OrtpVideoBandwidthEstimator *vbe);

void ortp_video_bandwidth_estimator_process_packet(OrtpVideoBandwidthEstimator *vbe, uint32_t sent_timestamp, const struct timeval *recv_timestamp, int msgsize, bool_t is_last);

float ortp_video_bandwidth_estimator_get_estimated_available_bandwidth(OrtpVideoBandwidthEstimator *vbe);

#endif