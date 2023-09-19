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

#include "audiobandwidthestimator.h"
#include "congestiondetector.h"
#include "rtpsession_priv.h"
#include <math.h>
#include <ortp/logging.h>
#include <ortp/rtpsession.h>

// 2 micro seconds diff, we do not really need to be precise, so it is ok to use a very low
// minimal period, it will just detect that the BW is very high
#define MIN_DIFFTIME 0.000002f

static void compute_bitrate_add_to_list_and_remove_oldest_value(OrtpAudioBandwidthEstimator *abe,
                                                                OrtpAudioBandwidthEstimatorPacket *packet) {
	float difftime = (float)(packet->recv_last_timestamp.tv_sec - packet->recv_first_timestamp.tv_sec) +
	                 1e-6f * (packet->recv_last_timestamp.tv_usec - packet->recv_first_timestamp.tv_usec);

	if (difftime >= MIN_DIFFTIME) {
		packet->bitrate = (packet->bytes * 8 / difftime);
		ortp_debug("[ABE] Bitrate is %f kbits/s computed using %f timedif and %u size", packet->bitrate / 1000,
		           difftime, packet->bytes);

		abe->nb_packets_computed += 1;
		abe->packets = bctbx_list_prepend(abe->packets, packet);

		if (bctbx_list_size(abe->packets) > abe->packets_history_size) {
			void *old_data = bctbx_list_nth_data(abe->packets, abe->packets_history_size);
			abe->packets = bctbx_list_remove(abe->packets, old_data);
			ortp_free(old_data);
		}

		if (abe->nb_packets_computed % abe->packets_history_size == 0) {
			OrtpEvent *ev = ortp_event_new(ORTP_EVENT_NEW_AUDIO_BANDWIDTH_ESTIMATION_AVAILABLE);
			OrtpEventData *ed = ortp_event_get_data(ev);
			ed->info.audio_bandwidth_available = ortp_audio_bandwidth_estimator_get_estimated_available_bandwidth(abe);
			ortp_message(
			    "[ABE] Dispatching event ORTP_EVENT_NEW_AUDIO_BANDWIDTH_ESTIMATION_AVAILABLE with value %f kbits/s",
			    ed->info.audio_bandwidth_available / 1000);
			rtp_session_dispatch_event(abe->session, ev);
		}
	} else {
		ortp_free(packet);
	}
}

/**
 * Check if a packet is a duplicate we should use for bandwidth estimation
 * Duplicated packets are expected to arrive one just after another, so this
 * is just storing the last sent_timestamp and seq_number. If they match, packet is considered
 * a duplicate.
 *
 * Random duplicates created by the network may not arrive one after an other and
 * may not be detected by this simple algorithm, they are removed by rtp_putq. They may interfer
 * with this mechanism, so one should not push too high the trust percentage
 *
 * If the packet is a duplicate, create an ABE packet and add it to the history, this may trigger
 * an event with a bandwidth estimation
 *
 * @param [in]	abe		the audio bandwidth estimator engine
 * @param[in]	sent_timestamp	RTP packet sent timestamp
 * @param[in]	recv_timestamp	RTP packet recv timestamp
 * @param[in]	msgsize		RTP packet size(including IP overhead)
 * @param[in]	seq_number	RTP packet seq_number
 *
 * @return TRUE if the RTP packet is detected as a duplicate
 */
static bool_t ortp_audio_bandwidth_estimator_process_packet(OrtpAudioBandwidthEstimator *abe,
                                                            uint32_t sent_timestamp,
                                                            const struct timeval *recv_timestamp,
                                                            int msgsize,
                                                            uint16_t seq_number) {

	/* bw estimator detects duplicates sent on purpose by the other side
	 * duplicates are sent simultaneously, measure the recv timestamp difference
	 * to estimate the actuel bw */
	if (abe->last_seq_number == seq_number && abe->last_sent_timestamp == sent_timestamp) {
		/* When a congestion is currently on, do not estimate the bandwidth, it shall
		 * be increased via TMMBR anyway at the congestion end and we do not want to
		 * get some measurement from congested period as they could then be selected
		 * when we have enough measurement but after the end of it */
		if (!(abe->session->congestion_detector_enabled && abe->session->rtp.congdetect &&
		      abe->session->rtp.congdetect->is_in_congestion)) {
			OrtpAudioBandwidthEstimatorPacket *abe_packet =
			    (OrtpAudioBandwidthEstimatorPacket *)ortp_malloc0(sizeof(OrtpAudioBandwidthEstimatorPacket));
			abe->stats.recv_dup++;
			abe_packet->bytes = msgsize; // Should the second packet size be considered or just the first one?
			                             // Considering only one seems to give better results
			abe_packet->recv_first_timestamp.tv_sec = abe->last_timestamp.tv_sec;
			abe_packet->recv_first_timestamp.tv_usec = abe->last_timestamp.tv_usec;
			abe_packet->recv_last_timestamp.tv_sec = recv_timestamp->tv_sec;
			abe_packet->recv_last_timestamp.tv_usec = recv_timestamp->tv_usec;
			compute_bitrate_add_to_list_and_remove_oldest_value(abe, abe_packet);
		}
		return TRUE;
	} else {
		abe->last_sent_timestamp = sent_timestamp;
		abe->last_timestamp.tv_sec = recv_timestamp->tv_sec;
		abe->last_timestamp.tv_usec = recv_timestamp->tv_usec;
		abe->last_seq_number = seq_number;
		return FALSE;
	}
}

/**** Modifier functions: the ABE use the highest priority modifier to inject/retrieve
 * duplicated RTP packet
 */
static int ortp_abe_process_onsend(struct _RtpTransportModifier *tm, mblk_t *packet) {
	rtp_header_t *rtp = (rtp_header_t *)packet->b_rptr;
	size_t msgsize = msgdsize(packet);
	/* ignore anything not RTP */
	if (rtp->version == 2) {
		OrtpAudioBandwidthEstimator *abe = (OrtpAudioBandwidthEstimator *)tm->data;
		RtpSession *session = abe->session;
		// Send a duplicate if: the target bandwidth is not the max requested
		if ((session->audio_bandwidth_estimator_enabled &&
		     session->target_upload_bandwidth < session->max_target_upload_bandwidth)) {
			if (abe->next_duplicated == 0) {
				RtpTransport *rtpt = NULL;
				rtp_session_get_transports(session, &rtpt, NULL);
				meta_rtp_transport_modifier_inject_packet_to_send(rtpt, tm, packet, 0);
				ortp_debug("[ABE] duplicate outgoing packet on session [%p]", session);
				abe->next_duplicated = abe->duplicated_packet_rate;
				abe->stats.sent_dup++;
			} else {
				abe->next_duplicated--;
			}
		}
	}
	return (int)msgsize;
}
static int ortp_abe_process_onreceive(struct _RtpTransportModifier *tm, mblk_t *packet) {
	rtp_header_t *rtp = (rtp_header_t *)packet->b_rptr;
	size_t msgsize = msgdsize(packet);
	/* ignore anything not RTP */
	if (rtp->version == 2) {
		OrtpAudioBandwidthEstimator *abe = (OrtpAudioBandwidthEstimator *)tm->data;
		RtpSession *session = abe->session;
		int overhead = ortp_stream_is_ipv6(&session->rtp.gs) ? IP6_UDP_OVERHEAD : IP_UDP_OVERHEAD;
		if (ortp_audio_bandwidth_estimator_process_packet(abe, rtp_header_get_timestamp(rtp), &packet->timestamp,
		                                                  (int)(msgsize + overhead), rtp_header_get_seqnumber(rtp))) {
			return 0; // packet is a duplicate, drop it
		}
	}
	return (int)msgsize;
}
static void ortp_abe_modifier_destroy(RtpTransportModifier *tm) {
	ortp_free(tm);
}

OrtpAudioBandwidthEstimator *ortp_audio_bandwidth_estimator_new(RtpSession *session) {
	RtpTransport *transport = NULL;
	/* init ABE parameters */
	OrtpAudioBandwidthEstimator *abe = (OrtpAudioBandwidthEstimator *)ortp_malloc0(sizeof(OrtpAudioBandwidthEstimator));
	abe->session = session;
	abe->packets_history_size = 10;
	abe->trust_percentage = 65;
	abe->nb_packets_computed = 0;
	abe->packets = NULL;
	abe->duplicated_packet_rate = 10;
	abe->next_duplicated = 0;
	abe->last_timestamp.tv_sec = 0;
	abe->last_timestamp.tv_usec = 0;
	abe->last_seq_number = 0;
	abe->stats.sent_dup = 0;
	abe->stats.recv_dup = 0;

	/* Create transport modifiers to be able to duplicate outgoing packets\
	 * duplicated outgoing packets are sent simultaneously and used on the receiving side
	 * to measure the available bw
	 */
	rtp_session_get_transports(session, &transport, NULL);
	abe->modifier = ortp_new0(RtpTransportModifier, 1);
	abe->modifier->level = RtpTransportModifierLevelAudioBandwidthEstimator; // Use higher level, so this modifier is
	                                                                         // processed even after the FEC one
	abe->modifier->data = abe;
	abe->modifier->t_process_on_send = ortp_abe_process_onsend;
	abe->modifier->t_process_on_receive = ortp_abe_process_onreceive;
	abe->modifier->t_process_on_schedule = NULL;
	abe->modifier->t_destroy = ortp_abe_modifier_destroy;
	meta_rtp_transport_append_modifier(transport, abe->modifier);

	return abe;
}

void ortp_audio_bandwidth_estimator_destroy(OrtpAudioBandwidthEstimator *abe) {
	ortp_audio_bandwidth_estimator_reset(abe);
	ortp_free(abe);
}

void ortp_audio_bandwidth_estimator_reset(OrtpAudioBandwidthEstimator *abe) {
	abe->nb_packets_computed = 0;
	abe->last_timestamp.tv_sec = 0;
	abe->last_timestamp.tv_usec = 0;
	abe->last_seq_number = 0;
	abe->packets = bctbx_list_free_with_data(abe->packets, bctbx_free);
}

void ortp_audio_bandwidth_estimator_set_history_max_size(OrtpAudioBandwidthEstimator *abe, unsigned int value) {
	abe->packets_history_size = value;
}

void ortp_audio_bandwidth_estimator_set_trust(OrtpAudioBandwidthEstimator *abe, unsigned int value) {
	abe->trust_percentage = value;
}
void ortp_audio_bandwidth_estimator_set_duplicate_rate(OrtpAudioBandwidthEstimator *abe, unsigned int value) {
	abe->duplicated_packet_rate = value;
}

unsigned int ortp_audio_bandwidth_estimator_get_history_max_size(OrtpAudioBandwidthEstimator *abe) {
	return abe->packets_history_size;
}

unsigned int ortp_audio_bandwidth_estimator_get_trust(OrtpAudioBandwidthEstimator *abe) {
	return abe->trust_percentage;
}
unsigned int ortp_audio_bandwidth_estimator_get_duplicate_rate(OrtpAudioBandwidthEstimator *abe) {
	return abe->duplicated_packet_rate;
}

static int compare_float(const float *v1, const float *v2) {
	if (*v1 == *v2) return 0;
	if (*v1 < *v2) return 1;
	return -1;
}

float ortp_audio_bandwidth_estimator_get_estimated_available_bandwidth(OrtpAudioBandwidthEstimator *abe) {
	bctbx_list_t *bitrate_sorted = NULL;
	bctbx_list_t *elem;
	float *result = NULL;
	int index = (int)(abe->trust_percentage * abe->packets_history_size / 100);
	for (elem = abe->packets; elem != NULL; elem = bctbx_list_next(elem)) {
		OrtpAudioBandwidthEstimatorPacket *packet = (OrtpAudioBandwidthEstimatorPacket *)bctbx_list_get_data(elem);
		bitrate_sorted = bctbx_list_insert_sorted(bitrate_sorted, &packet->bitrate, (bctbx_compare_func)compare_float);
	}
	result = (float *)bctbx_list_nth_data(bitrate_sorted, index);
	bctbx_list_free(bitrate_sorted);
	return (float)*result;
}
