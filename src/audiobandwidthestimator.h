/*
 * Copyright (c) 2010-2023 Belledonne Communications SARL.
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

#ifndef AUDIOBANDWIDTHESTIMATOR_H
#define AUDIOBANDWIDTHESTIMATOR_H

#include <bctoolbox/list.h>
#include <ortp/port.h>
#include <ortp/rtpsession.h>
#include <ortp/utils.h>

typedef struct _OrtpAudioBandwidthEstimatorPacket {
	struct timeval recv_first_timestamp;
	struct timeval recv_last_timestamp;
	unsigned int bytes;
	float bitrate;
} OrtpAudioBandwidthEstimatorPacket;

typedef struct _OrtpAudioBandwidthEstimator {
	/** Session access */
	struct _RtpSession *session;
	RtpTransportModifier *modifier;
	/** Settings */
	unsigned int packets_history_size; /**< ABE packets history size: when full, generate an estimation */
	unsigned int trust_percentage;
	unsigned int duplicated_packet_rate; /**< 1 out duplicated_packet_rate is duplicated */

	/** info on last processed RPT packet */
	struct timeval last_timestamp;
	uint16_t last_seq_number;
	uint32_t last_sent_timestamp;

	bctbx_list_t *packets;        /**< ABE packet history */
	int nb_packets_computed;      /**< ABE packet history size */
	unsigned int next_duplicated; /**< countdown to enforce the duplicated_packet_rate */
	abe_stats_t stats;            /**< statistics */
} OrtpAudioBandwidthEstimator;

OrtpAudioBandwidthEstimator *ortp_audio_bandwidth_estimator_new(struct _RtpSession *session);

void ortp_audio_bandwidth_estimator_destroy(OrtpAudioBandwidthEstimator *abe);

void ortp_audio_bandwidth_estimator_reset(OrtpAudioBandwidthEstimator *abe);

/**
 * Sets the number of rate duplicates packets are generated.
 * rate is applied as follow, with a rate of 10, every 10 RTP packets sent, one is duplicated
 * Packets are generated only when the current target_upload_bandwidth on RtpSession
 * is inferior to media_stream_set_max_network_bitrate
 * Default value is 10.
 */
void ortp_audio_bandwidth_estimator_set_duplicate_rate(OrtpAudioBandwidthEstimator *abe, unsigned int value);

/**
 * Sets the number of duplicates packets needed to compute the available audio bandwidth.
 * Using a duplicate rate of 10 one packet out of 10 is duplicated, if ptime is 100ms,
 * one duplicate is sent every second so we will collect 10 duplicates packets every 10s
 * to produce the estimate.
 * Default value is 10.
 */
void ortp_audio_bandwidth_estimator_set_history_max_size(OrtpAudioBandwidthEstimator *abe, unsigned int value);

/**
 * Sets the percentage for which the chosen bandwidth value in all available will be inferior.
 * Example: for 100 packets with 90% trust, bandwidth value will be the 90th after sorted.
 * Default value is 65.
 */
void ortp_audio_bandwidth_estimator_set_trust(OrtpAudioBandwidthEstimator *abe, unsigned int value);

/**
 * Gets the number of packets needed to compute the available audio bandwidth.
 * Default value is 10.
 */
unsigned int ortp_audio_bandwidth_estimator_get_history_max_size(OrtpAudioBandwidthEstimator *abe);

/**
 * Gets the percentage for which the chosen bandwidth value in all available will be inferior.
 * Example: for 100 packets with 90% trust, bandwidth value will be the 90th after sorted.
 * Default value is 65.
 */
unsigned int ortp_audio_bandwidth_estimator_get_trust(OrtpAudioBandwidthEstimator *abe);

/**
 * Gets the number of rate duplicates packets are generated.
 * rate is applied as follow, with a rate of 10, every 10 RTP packets sent, one is duplicated
 * Packets are generated only when the current target_upload_bandwidth on RtpSession
 * is inferior to media_stream_set_max_network_bitrate
 * Default value is 10.
 */
unsigned int ortp_audio_bandwidth_estimator_get_duplicate_rate(OrtpAudioBandwidthEstimator *abe);

float ortp_audio_bandwidth_estimator_get_estimated_available_bandwidth(OrtpAudioBandwidthEstimator *abe);

#endif
