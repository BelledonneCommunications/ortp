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

#include "videobandwidthestimator.h"
#include <ortp/logging.h>
#include <math.h>
#include <ortp/rtpsession.h>

OrtpVideoBandwidthEstimator * ortp_video_bandwidth_estimator_new(RtpSession *session) {
	OrtpVideoBandwidthEstimator *vbe = (OrtpVideoBandwidthEstimator*)ortp_malloc0(sizeof(OrtpVideoBandwidthEstimator));
	vbe->session = session;
	vbe->packet_count_min = 5;
	vbe->packets_size_max = 30;
	vbe->trust_percentage = 90;
    vbe->nb_packets_computed = 0;
    vbe->packets = NULL;
    vbe->last_packet = NULL;
	return vbe;
}

void ortp_video_bandwidth_estimator_destroy(OrtpVideoBandwidthEstimator *vbe){
    ortp_video_bandwidth_estimator_reset(vbe);
    ortp_free(vbe);
}

void ortp_video_bandwidth_estimator_reset(OrtpVideoBandwidthEstimator *vbe) {
	ortp_free(vbe->last_packet);
    vbe->last_packet = NULL;
    vbe->nb_packets_computed = 0;
	vbe->packets = bctbx_list_free_with_data(vbe->packets, ortp_free);
}

void ortp_video_bandwidth_estimator_set_packets_count_min(OrtpVideoBandwidthEstimator *vbe, unsigned int value) {
    vbe->packet_count_min = value;
}

void ortp_video_bandwidth_estimator_set_history_max_size(OrtpVideoBandwidthEstimator *vbe, unsigned int value) {
    vbe->packets_size_max = value;
}

void ortp_video_bandwidth_estimator_set_trust(OrtpVideoBandwidthEstimator *vbe, unsigned int value) {
    vbe->trust_percentage = value;
}

unsigned int ortp_video_bandwidth_estimator_get_packets_count_min(OrtpVideoBandwidthEstimator *vbe) {
    return vbe->packet_count_min;
}

unsigned int ortp_video_bandwidth_estimator_get_history_max_size(OrtpVideoBandwidthEstimator *vbe) {
    return vbe->packets_size_max;
}

unsigned int ortp_video_bandwidth_estimator_get_trust(OrtpVideoBandwidthEstimator *vbe) {
    return vbe->trust_percentage;
}

static int compare_float(const float *v1, const float *v2) {
	if (*v1 == *v2) return 0;
	if (*v1 < *v2) return 1;
	return -1;
}

float ortp_video_bandwidth_estimator_get_estimated_available_bandwidth(OrtpVideoBandwidthEstimator *vbe) {
    bctbx_list_t *bitrate_sorted = NULL;
    bctbx_list_t *elem;
    float *result = NULL;
    int index = (int)(vbe->trust_percentage * vbe->packets_size_max / 100);
    for(elem = vbe->packets; elem != NULL; elem = bctbx_list_next(elem)) {
        OrtpVideoBandwidthEstimatorPacket *packet = (OrtpVideoBandwidthEstimatorPacket *)bctbx_list_get_data(elem);
        bitrate_sorted = bctbx_list_insert_sorted(bitrate_sorted, &packet->bitrate, (bctbx_compare_func)compare_float);
    }
    result = (float *)bctbx_list_nth_data(bitrate_sorted, index);
    bctbx_list_free(bitrate_sorted);
    return (float)*result;
}

static void compute_bitrate_add_to_list_and_remove_oldest_value(OrtpVideoBandwidthEstimator *vbe, OrtpVideoBandwidthEstimatorPacket *packet) {
	float difftime = (float)(packet->recv_last_timestamp.tv_sec - packet->recv_first_timestamp.tv_sec) 
		+ 1e-6f*(packet->recv_last_timestamp.tv_usec - packet->recv_first_timestamp.tv_usec);
	packet->bitrate = (packet->bytes * 8 / difftime);
	ortp_debug("[VBE] Bitrate is %f kbits/s computed using %f timedif and %u size", packet->bitrate / 1000, difftime, packet->bytes);

    vbe->nb_packets_computed += 1;
	vbe->packets = bctbx_list_prepend(vbe->packets, packet);

	if (bctbx_list_size(vbe->packets) > vbe->packets_size_max) {
		void *old_data = bctbx_list_nth_data(vbe->packets, vbe->packets_size_max);
		vbe->packets = bctbx_list_remove(vbe->packets, old_data);
	}

    if (vbe->nb_packets_computed % vbe->packets_size_max == 0) {
        OrtpEvent *ev = ortp_event_new(ORTP_EVENT_NEW_VIDEO_BANDWIDTH_ESTIMATION_AVAILABLE);
        OrtpEventData *ed = ortp_event_get_data(ev);
        ed->info.video_bandwidth_available = ortp_video_bandwidth_estimator_get_estimated_available_bandwidth(vbe);
        ortp_debug("[VBE] Dispatching event ORTP_EVENT_NEW_VIDEO_BANDWIDTH_ESTIMATION_AVAILABLE with value %f kbits/s", ed->info.video_bandwidth_available / 1000);
        rtp_session_dispatch_event(vbe->session, ev);
    }
}

void ortp_video_bandwidth_estimator_process_packet(OrtpVideoBandwidthEstimator *vbe, uint32_t sent_timestamp, const struct timeval *recv_timestamp, int msgsize, bool_t is_last) {
	OrtpVideoBandwidthEstimatorPacket *last_packet = vbe->last_packet;
	OrtpVideoBandwidthEstimatorPacket *current_packet = NULL;

	if (last_packet) {
		if (last_packet->sent_timestamp == sent_timestamp) {
			current_packet = last_packet;
			current_packet->count += 1;
			current_packet->bytes += msgsize;
			current_packet->recv_last_timestamp.tv_sec = recv_timestamp->tv_sec;
			current_packet->recv_last_timestamp.tv_usec = recv_timestamp->tv_usec;

			if (is_last && current_packet->count >= vbe->packet_count_min) {
				compute_bitrate_add_to_list_and_remove_oldest_value(vbe, current_packet);
				vbe->last_packet = NULL;
			}
		} else {
			// This can happen even if it's probability is quite low
			if (last_packet->count >= vbe->packet_count_min) {
				ortp_warning("[VBE] Last packet not complete but enough packet received (%u), add to packets list", last_packet->count);
				compute_bitrate_add_to_list_and_remove_oldest_value(vbe, last_packet);
			} else {
				ortp_free(vbe->last_packet);
			}
			vbe->last_packet = NULL;
		}
	}

	if (!current_packet) {
		current_packet = (OrtpVideoBandwidthEstimatorPacket*)ortp_malloc0(sizeof(OrtpVideoBandwidthEstimatorPacket));
		current_packet->count = 1;
		current_packet->bytes = msgsize;
		current_packet->sent_timestamp = sent_timestamp;
		current_packet->recv_first_timestamp.tv_sec = recv_timestamp->tv_sec;
		current_packet->recv_first_timestamp.tv_usec = recv_timestamp->tv_usec;
		vbe->last_packet = current_packet;
	}
}
