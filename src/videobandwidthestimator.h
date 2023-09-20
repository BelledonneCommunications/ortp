/*
 * Copyright (c) 2010-2022 Belledonne Communications SARL.
 *
 * This file is part of oRTP
 * (see https://gitlab.linphone.org/BC/public/ortp).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef VIDEOBANDWIDTHESTIMATOR_H
#define VIDEOBANDWIDTHESTIMATOR_H

#include <bctoolbox/list.h>
#include <ortp/port.h>
#include <ortp/utils.h>

typedef struct _OrtpVideoBandwidthEstimator OrtpVideoBandwidthEstimator;

#ifdef __cplusplus
extern "C" {
#endif

OrtpVideoBandwidthEstimator *ortp_video_bandwidth_estimator_new(struct _RtpSession *session);

void ortp_video_bandwidth_estimator_destroy(OrtpVideoBandwidthEstimator *vbe);

void ortp_video_bandwidth_estimator_reset(OrtpVideoBandwidthEstimator *vbe);

/**
 * Sets the minimum number of packets with the same sent timestamp to be processed continuously before being used.
 *
 */
void ortp_video_bandwidth_estimator_set_packets_count_min(OrtpVideoBandwidthEstimator *vbe, unsigned int value);

/**
 * Sets the number of measurements needed to compute the available video bandwidth.
 *
 */
void ortp_video_bandwidth_estimator_set_min_measurements_count(OrtpVideoBandwidthEstimator *vbe, unsigned int value);

/**
 * Sets the percentage for which the chosen bandwidth value in all available will be inferior.
 * Example: for 100 packets with 90% trust, bandwidth value will be the 90th after sorted.
 * Default value is 90.
 */
void ortp_video_bandwidth_estimator_set_trust(OrtpVideoBandwidthEstimator *vbe, unsigned int value);

/**
 * Gets the minimum number of packets with the same sent timestamp to be processed continuously before being used.
 *
 */
unsigned int ortp_video_bandwidth_estimator_get_packets_count_min(OrtpVideoBandwidthEstimator *vbe);

/**
 * Gets the percentage for which the chosen bandwidth value in all available will be inferior.
 * Example: for 100 packets with 90% trust, bandwidth value will be the 90th after sorted.
 * Default value is 90.
 */
unsigned int ortp_video_bandwidth_estimator_get_trust(OrtpVideoBandwidthEstimator *vbe);

/**
 * Gets the number of measurements needed to compute the available video bandwidth.
 * Default value is 50.
 */
unsigned int ortp_video_bandwidth_estimator_get_min_measurements_count(OrtpVideoBandwidthEstimator *vbe);

void ortp_video_bandwidth_estimator_process_packet(OrtpVideoBandwidthEstimator *vbe,
                                                   uint32_t sent_timestamp,
                                                   const struct timeval *recv_timestamp,
                                                   int msgsize,
                                                   bool_t is_last);

float ortp_video_bandwidth_estimator_get_estimated_available_bandwidth(OrtpVideoBandwidthEstimator *vbe);

#ifdef __cplusplus
}
#endif

#endif
