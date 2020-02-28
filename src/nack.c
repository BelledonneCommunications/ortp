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

#include "ortp/logging.h"
#include "ortp/nack.h"

#define DECREASE_JITTER_DELAY 5000

static mblk_t *find_packet_with_sequence_number(const queue_t *q, const uint16_t seq_number) {
	mblk_t *tmp;

	for (tmp = qbegin(q); !qend(q, tmp); tmp = qnext(q, tmp)) {
		if (ntohs(rtp_get_seqnumber(tmp)) == seq_number) {
			return tmp;
		}
	}

	return NULL;
}

static void generic_nack_received(const OrtpEventData *evd, OrtpNackContext *ctx) {
	if (rtcp_is_RTPFB(evd->packet) && rtcp_RTPFB_get_type(evd->packet) == RTCP_RTPFB_NACK) {
		RtpTransport *rtpt = NULL;
		rtcp_fb_generic_nack_fci_t *fci;
		uint16_t pid, blp, seq;
		mblk_t *lost_msg;

		/* get RTP transport from session */
		rtp_session_get_transports(ctx->session, &rtpt, NULL);

		fci = rtcp_RTPFB_generic_nack_get_fci(evd->packet);
		pid = rtcp_fb_generic_nack_fci_get_pid(fci);
		blp = rtcp_fb_generic_nack_fci_get_blp(fci);

		bctbx_mutex_lock(&ctx->sent_packets_mutex);

		lost_msg = find_packet_with_sequence_number(&ctx->sent_packets, pid);
		if (lost_msg != NULL) {
			meta_rtp_transport_modifier_inject_packet_to_send(rtpt, ctx->rtp_modifier, lost_msg, 0);
			ortp_message("OrtpNackContext [%p]: Resending missing packet with seq=%hu", ctx, pid);
		} else {
			ortp_warning("OrtpNackContext [%p]: Cannot find missing packet with seq=%hu", ctx, pid);
		}
		++pid;

		for (seq = blp; seq != 0; seq >>= 1, ++pid) {
			if (seq & 1) {
				lost_msg = find_packet_with_sequence_number(&ctx->sent_packets, pid);
				if (lost_msg != NULL) {
					meta_rtp_transport_modifier_inject_packet_to_send(rtpt, ctx->rtp_modifier, lost_msg, 0);
					ortp_message("OrtpNackContext [%p]: Resending missing packet with seq=%hu", ctx, pid);
				} else {
					ortp_warning("OrtpNackContext [%p]: Cannot find missing packet with seq=%hu", ctx, pid);
				}
			}
		}

		bctbx_mutex_unlock(&ctx->sent_packets_mutex);
	}
}

static int ortp_nack_rtp_process_on_send(RtpTransportModifier *t, mblk_t *msg) {
	OrtpNackContext *userData = (OrtpNackContext *) t->data;

	if (rtp_get_version(msg) == 2) {
		bctbx_mutex_lock(&userData->sent_packets_mutex);

		// Remove the oldest packet if the cache is full
		if (userData->sent_packets.q_mcount >= userData->max_packets) {
			mblk_t *erase = qbegin(&userData->sent_packets);
			remq(&userData->sent_packets, erase);

			if (erase != NULL) freemsg(erase);
		}

		// Stock the packet before sending it
		putq(&userData->sent_packets, dupmsg(msg));

		//ortp_message("OrtpNackContext [%p]: Stocking packet with pid=%hu (seq=%hu)", userData, ntohs(rtp_get_seqnumber(msg)), userData->session->rtp.snd_seq);

		bctbx_mutex_unlock(&userData->sent_packets_mutex);
	}

	return (int) msgdsize(msg);
}

static int ortp_nack_rtp_process_on_receive(RtpTransportModifier *t, mblk_t *msg) {
	return (int) msgdsize(msg);
}

static int ortp_nack_rtcp_process_on_send(RtpTransportModifier *t, mblk_t *msg) {
	mblk_t *pullmsg = dupmsg(msg);
	msgpullup(pullmsg, (size_t)-1);

	do {
		if (rtcp_is_RTPFB(pullmsg) && rtcp_RTPFB_get_type(pullmsg) == RTCP_RTPFB_NACK) {
			OrtpNackContext *userData = (OrtpNackContext *) t->data;
			OrtpEvent *ev;
			OrtpEventData *evd;
			JBParameters jitter_params;
			int rtt = (int) userData->session->rtt;

			if (rtt == 0) rtt = 200;

			rtp_session_get_jitter_buffer_params(userData->session, &jitter_params);

			if (userData->min_jitter_before_nack == 0) {
				/* We keep the min_size at the first sent NACK to know at which value it has to come back */
				userData->min_jitter_before_nack = jitter_params.min_size;
			}

			if (userData->min_jitter_before_nack + rtt != jitter_params.min_size) {
				if (userData->min_jitter_before_nack + rtt >= jitter_params.max_size) {
					jitter_params.min_size = jitter_params.max_size - 20;
				} else {
					jitter_params.min_size = userData->min_jitter_before_nack + rtt;
				}

				rtp_session_set_jitter_buffer_params(userData->session, &jitter_params);

				ortp_message("OrtpNackContext [%p]: Sending NACK... increasing jitter min size to %dms", userData, jitter_params.min_size);

				// Send an event that the video jitter has been updated so that we can update the audio too
				ev = ortp_event_new(ORTP_EVENT_JITTER_UPDATE_FOR_NACK);
				evd = ortp_event_get_data(ev);
				evd->info.jitter_min_size_for_nack = jitter_params.min_size;
				rtp_session_dispatch_event(userData->session, ev);
			}

			// Start the timer that will decrase the min jitter if no NACK is sent
			userData->decrease_jitter_timer_running = TRUE;
			userData->decrease_jitter_timer_start = ortp_get_cur_time_ms();

			break;
		}
	} while (rtcp_next_packet(pullmsg));

	freemsg(pullmsg);
	return (int) msgdsize(msg);
}

static int ortp_nack_rtcp_process_on_receive(RtpTransportModifier *t, mblk_t *msg) {
	return (int) msgdsize(msg);
}

static void ortp_nack_transport_modifier_destroy(RtpTransportModifier *tp)  {
	ortp_free(tp);
}

static void ortp_nack_transport_modifier_new(OrtpNackContext* ctx, RtpTransportModifier **rtpt, RtpTransportModifier **rtcpt ) {
	if (rtpt) {
		*rtpt = ortp_new0(RtpTransportModifier, 1);
		(*rtpt)->data = ctx; /* back link to get access to the other fields of the OrtpNackContext from the RtpTransportModifier structure */
		(*rtpt)->t_process_on_send = ortp_nack_rtp_process_on_send;
		(*rtpt)->t_process_on_receive = ortp_nack_rtp_process_on_receive;
		(*rtpt)->t_destroy = ortp_nack_transport_modifier_destroy;
	}

	if (rtcpt) {
		*rtcpt = ortp_new0(RtpTransportModifier, 1);
		(*rtcpt)->data = ctx; /* back link to get access to the other fields of the OrtpNackContext from the RtpTransportModifier structure */
		(*rtcpt)->t_process_on_send = ortp_nack_rtcp_process_on_send;
		(*rtcpt)->t_process_on_receive = ortp_nack_rtcp_process_on_receive;
		(*rtcpt)->t_destroy = ortp_nack_transport_modifier_destroy;
	}
}

static OrtpNackContext *ortp_nack_configure_context(OrtpNackContext *userData) {
	RtpTransport *rtpt = NULL, *rtcpt = NULL;
	RtpTransportModifier *rtp_modifier, *rtcp_modifier;

	rtp_session_get_transports(userData->session, &rtpt, &rtcpt);

	ortp_nack_transport_modifier_new(userData, &rtp_modifier, &rtcp_modifier);
	meta_rtp_transport_append_modifier(rtpt, rtp_modifier);
	meta_rtp_transport_prepend_modifier(rtcpt, rtcp_modifier);

	userData->rtp_modifier = rtp_modifier;
	userData->rtcp_modifier = rtcp_modifier;

	return userData;
}

OrtpNackContext *ortp_nack_context_new(OrtpEvDispatcher *evt) {
	OrtpNackContext *userData;

	userData = ortp_new0(OrtpNackContext, 1);
	userData->session = evt->session;
	userData->ev_dispatcher = evt;
	userData->max_packets = 100;

	qinit(&userData->sent_packets);
	bctbx_mutex_init(&userData->sent_packets_mutex, NULL);

	rtp_session_enable_avpf_feature(userData->session, ORTP_AVPF_FEATURE_IMMEDIATE_NACK, TRUE);

	ortp_ev_dispatcher_connect(userData->ev_dispatcher
								, ORTP_EVENT_RTCP_PACKET_RECEIVED
								, RTCP_RTPFB
								, (OrtpEvDispatcherCb)generic_nack_received
								, userData);

	return ortp_nack_configure_context(userData);
}

void ortp_nack_context_destroy(OrtpNackContext *ctx) {
	RtpTransport *rtpt = NULL, *rtcpt = NULL;

	ortp_ev_dispatcher_disconnect(ctx->ev_dispatcher
									, ORTP_EVENT_RTCP_PACKET_RECEIVED
									, RTCP_RTPFB
									, (OrtpEvDispatcherCb)generic_nack_received);

	rtp_session_enable_avpf_feature(ctx->session, ORTP_AVPF_FEATURE_IMMEDIATE_NACK, FALSE);

	rtp_session_get_transports(ctx->session, &rtpt, &rtcpt);
	meta_rtp_transport_remove_modifier(rtpt, ctx->rtp_modifier);
	meta_rtp_transport_remove_modifier(rtcpt, ctx->rtcp_modifier);
	ortp_nack_transport_modifier_destroy(ctx->rtp_modifier);
	ortp_nack_transport_modifier_destroy(ctx->rtcp_modifier);

	bctbx_mutex_lock(&ctx->sent_packets_mutex);
	flushq(&ctx->sent_packets, FLUSHALL);
	bctbx_mutex_unlock(&ctx->sent_packets_mutex);

	bctbx_mutex_destroy(&ctx->sent_packets_mutex);
	ortp_free(ctx);
}

void ortp_nack_context_set_max_packet(OrtpNackContext *ctx, int max) {
	ctx->max_packets = max;
}

void ortp_nack_context_process_timer(OrtpNackContext *ctx) {
	if (ctx->decrease_jitter_timer_running) {
		uint64_t current_time = ortp_get_cur_time_ms();
		if (current_time - ctx->decrease_jitter_timer_start >= DECREASE_JITTER_DELAY) {
			OrtpEvent *ev;
			OrtpEventData *evd;
			JBParameters jitter_params;

			ortp_message("OrtpNackContext [%p]: No NACK sent in the last %d seconds, decreasing jitter min size to %dms...", ctx, DECREASE_JITTER_DELAY / 1000, ctx->min_jitter_before_nack);

			rtp_session_get_jitter_buffer_params(ctx->session, &jitter_params);
			jitter_params.min_size = ctx->min_jitter_before_nack;
			rtp_session_set_jitter_buffer_params(ctx->session, &jitter_params);

			// Send an event that the video jitter has been updated so that we can update the audio too
			ev = ortp_event_new(ORTP_EVENT_JITTER_UPDATE_FOR_NACK);
			evd = ortp_event_get_data(ev);
			evd->info.jitter_min_size_for_nack = jitter_params.min_size;
			rtp_session_dispatch_event(ctx->session, ev);

			ctx->decrease_jitter_timer_running = FALSE;
		}
	}
}
