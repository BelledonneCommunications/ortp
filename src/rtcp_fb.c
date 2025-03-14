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

#include "ortp/ortp.h"
#include "ortp/rtcp.h"
#include "ortp/rtpsession.h"
#include "rtpsession_priv.h"

static void rtp_session_add_fb_packet_to_send(RtpSession *session, mblk_t *m) {
	if (session->rtcp.send_algo.fb_packets == NULL) {
		session->rtcp.send_algo.fb_packets = m;
	} else {
		/*
		 * CAUTION: there is no limit in the number of fb fragments that can be enqueued here.
		 * When this exceeds MAX_IOV (from rtpsession_inet.c), the end will be discarded.
		 * This may happen if the target upload bandwidth (rtp_session_set_target_upload_bandwidth() ) is too low
		 * too allow feedback packets to be sent in real time.
		 */
		concatb(session->rtcp.send_algo.fb_packets, m);
	}
}

static bool_t is_fb_packet_to_be_sent_immediately(RtpSession *session) {
	uint64_t t0;

	if (rtp_session_has_fb_packets_to_send(session) == TRUE) return FALSE;
	t0 = bctbx_get_cur_time_ms();
	if (t0 > session->rtcp.send_algo.tn) return FALSE;
	if (session->rtcp.send_algo.allow_early == FALSE) {
		if ((session->rtcp.send_algo.tn - t0) >= session->rtcp.send_algo.T_max_fb_delay) {
			/* Discard message as it is considered that it will not be useful to the sender
			   at the time it will receive it. */
			freemsg(session->rtcp.send_algo.fb_packets);
			session->rtcp.send_algo.fb_packets = NULL;
		}
		return FALSE;
	}
	return TRUE;
}

static mblk_t *make_rtcp_fb_pli(RtpSession *session) {
	int size = sizeof(rtcp_common_header_t) + sizeof(rtcp_fb_header_t);
	mblk_t *h = allocb(size, 0);
	rtcp_common_header_t *ch;
	rtcp_fb_header_t *fbh;

	/* Fill PLI */
	ch = (rtcp_common_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_common_header_t);
	fbh = (rtcp_fb_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_header_t);
	fbh->packet_sender_ssrc = htonl(rtp_session_get_send_ssrc(session));
	fbh->media_source_ssrc = htonl(rtp_session_get_recv_ssrc(session));

	/* Fill common header */
	rtcp_common_header_init(ch, session, RTCP_PSFB, RTCP_PSFB_PLI, msgdsize(h));

	return h;
}

static mblk_t *make_rtcp_fb_fir(RtpSession *session) {
	int size = sizeof(rtcp_common_header_t) + sizeof(rtcp_fb_header_t) + sizeof(rtcp_fb_fir_fci_t);
	mblk_t *h = allocb(size, 0);
	rtcp_common_header_t *ch;
	rtcp_fb_header_t *fbh;
	rtcp_fb_fir_fci_t *fci1;

	/* Fill FIR */
	ch = (rtcp_common_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_common_header_t);
	fbh = (rtcp_fb_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_header_t);
	fci1 = (rtcp_fb_fir_fci_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_fir_fci_t);

	/*
	 * See https://datatracker.ietf.org/doc/rfc4585/ section 6.1
	 * SSRC of packet sender: 32 bits
	 * 	The synchronization source identifier for the originator of this packet.
	 *
	 * SSRC of media source: 32 bits
	 * 	The synchronization source identifier of the media source that
	 * 	this piece of feedback information is related to.
	 */

	fbh->packet_sender_ssrc = htonl(rtp_session_get_send_ssrc(session));
	fbh->media_source_ssrc = htonl(rtp_session_get_recv_ssrc(session));

	/*
	 * https://www.rfc-editor.org/rfc/rfc5104.html#section-4.3.1.1
	 * SSRC (32 bits): The SSRC value of the media sender that is
	 * 	requested to send a decoder refresh point.
	 */

	fci1->ssrc = htonl(rtp_session_get_recv_ssrc(session));
	fci1->seq_nr = session->rtcp.rtcp_fb_fir_seq_nr;
	fci1->pad1 = 0;
	fci1->pad2 = 0;

	/* Fill common header */
	rtcp_common_header_init(ch, session, RTCP_PSFB, RTCP_PSFB_FIR, msgdsize(h));

	return h;
}

static mblk_t *make_rtcp_fb_sli(RtpSession *session, uint16_t first, uint16_t number, uint8_t picture_id) {
	int size = sizeof(rtcp_common_header_t) + sizeof(rtcp_fb_header_t) + sizeof(rtcp_fb_sli_fci_t);
	mblk_t *h = allocb(size, 0);
	rtcp_common_header_t *ch;
	rtcp_fb_header_t *fbh;
	rtcp_fb_sli_fci_t *fci;

	/* Fill SLI */
	ch = (rtcp_common_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_common_header_t);
	fbh = (rtcp_fb_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_header_t);
	fci = (rtcp_fb_sli_fci_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_sli_fci_t);
	fbh->packet_sender_ssrc = htonl(rtp_session_get_send_ssrc(session));
	fbh->media_source_ssrc = htonl(rtp_session_get_recv_ssrc(session));
	rtcp_fb_sli_fci_set_first(fci, first);
	rtcp_fb_sli_fci_set_number(fci, number);
	rtcp_fb_sli_fci_set_picture_id(fci, picture_id);

	/* Fill common header */
	rtcp_common_header_init(ch, session, RTCP_PSFB, RTCP_PSFB_SLI, msgdsize(h));

	return h;
}

static mblk_t *make_rtcp_fb_rpsi(RtpSession *session, uint8_t *bit_string, uint16_t bit_string_len) {
	uint16_t bit_string_len_in_bytes;
	int additional_bytes;
	int size;
	mblk_t *h;
	rtcp_common_header_t *ch;
	rtcp_fb_header_t *fbh;
	rtcp_fb_rpsi_fci_t *fci;
	int i;

	/* Calculate packet size and allocate memory. */
	bit_string_len_in_bytes = (bit_string_len / 8) + (((bit_string_len % 8) == 0) ? 0 : 1);
	additional_bytes = bit_string_len_in_bytes - 2;
	if (additional_bytes < 0) additional_bytes = 0;
	size = sizeof(rtcp_common_header_t) + sizeof(rtcp_fb_header_t) + sizeof(rtcp_fb_rpsi_fci_t) + additional_bytes;
	h = allocb(size, 0);

	/* Fill RPSI */
	ch = (rtcp_common_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_common_header_t);
	fbh = (rtcp_fb_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_header_t);
	fci = (rtcp_fb_rpsi_fci_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_rpsi_fci_t);
	fbh->packet_sender_ssrc = htonl(rtp_session_get_send_ssrc(session));
	fbh->media_source_ssrc = htonl(rtp_session_get_recv_ssrc(session));
	if (bit_string_len <= 16) {
		fci->pb = 16 - bit_string_len;
		memset(&fci->bit_string, 0, 2);
	} else {
		fci->pb = (bit_string_len - 16) % 32;
		memset(&fci->bit_string, 0, bit_string_len_in_bytes);
	}
	fci->payload_type = rtp_session_get_recv_payload_type(session) & 0x7F;
	memcpy(&fci->bit_string, bit_string, bit_string_len / 8);
	for (i = 0; i < (bit_string_len % 8); i++) {
		fci->bit_string[bit_string_len_in_bytes - 1] |= (bit_string[bit_string_len_in_bytes - 1] & (1 << (7 - i)));
	}

	/* Fill common header */
	rtcp_common_header_init(ch, session, RTCP_PSFB, RTCP_PSFB_RPSI, msgdsize(h));

	return h;
}

static mblk_t *make_rtcp_fb_generic_nack(RtpSession *session, uint16_t pid, uint16_t blp) {
	int size = sizeof(rtcp_common_header_t) + sizeof(rtcp_fb_header_t) + sizeof(rtcp_fb_generic_nack_fci_t);
	mblk_t *h = allocb(size, 0);
	rtcp_common_header_t *ch;
	rtcp_fb_header_t *fbh;
	rtcp_fb_generic_nack_fci_t *fci;

	ch = (rtcp_common_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_common_header_t);
	fbh = (rtcp_fb_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_header_t);
	fci = (rtcp_fb_generic_nack_fci_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_generic_nack_fci_t);
	fbh->packet_sender_ssrc = htonl(rtp_session_get_send_ssrc(session));
	fbh->media_source_ssrc = htonl(0);
	rtcp_fb_generic_nack_fci_set_pid(fci, pid);
	rtcp_fb_generic_nack_fci_set_blp(fci, blp);

	/* Fill common header */
	rtcp_common_header_init(ch, session, RTCP_RTPFB, RTCP_RTPFB_NACK, msgdsize(h));

	return h;
}

static mblk_t *make_rtcp_fb_tmmbr(RtpSession *session, uint64_t mxtbr, uint16_t measured_overhead) {
	int size = sizeof(rtcp_common_header_t) + sizeof(rtcp_fb_header_t) + sizeof(rtcp_fb_tmmbr_fci_t);
	mblk_t *h = allocb(size, 0);
	rtcp_common_header_t *ch;
	rtcp_fb_header_t *fbh;
	rtcp_fb_tmmbr_fci_t *fci;
	uint8_t mxtbr_exp = 0;
	uint32_t mxtbr_mantissa = 0;

	/* Compute mxtbr exp and mantissa */
	while (mxtbr >= (1 << 17)) {
		mxtbr >>= 1;
		mxtbr_exp++;
	}
	mxtbr_mantissa = mxtbr & 0x0001FFFF;

	/* Fill TMMBR */
	ch = (rtcp_common_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_common_header_t);
	fbh = (rtcp_fb_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_header_t);
	fci = (rtcp_fb_tmmbr_fci_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_tmmbr_fci_t);
	fbh->packet_sender_ssrc = htonl(rtp_session_get_send_ssrc(session));
	fbh->media_source_ssrc = htonl(0);
	fci->ssrc = htonl(rtp_session_get_recv_ssrc(session));
	rtcp_fb_tmmbr_fci_set_mxtbr_exp(fci, mxtbr_exp);
	rtcp_fb_tmmbr_fci_set_mxtbr_mantissa(fci, mxtbr_mantissa);
	rtcp_fb_tmmbr_fci_set_measured_overhead(fci, measured_overhead);

	/* Fill common header */
	rtcp_common_header_init(ch, session, RTCP_RTPFB, RTCP_RTPFB_TMMBR, msgdsize(h));

	/* Store packet to be able to retransmit. */
	if (session->rtcp.tmmbr_info.sent) freemsg(session->rtcp.tmmbr_info.sent);
	session->rtcp.tmmbr_info.sent = copymsg(h);

	return h;
}

static mblk_t *make_rtcp_fb_tmmbn(RtpSession *session, uint32_t ssrc) {
	int size = sizeof(rtcp_common_header_t) + sizeof(rtcp_fb_header_t) + sizeof(rtcp_fb_tmmbr_fci_t);
	mblk_t *h = allocb(size, 0);
	rtcp_common_header_t *ch;
	rtcp_fb_header_t *fbh;
	rtcp_fb_tmmbr_fci_t *fci;

	if (!session->rtcp.tmmbr_info.received) return NULL;

	/* Fill TMMBN */
	ch = (rtcp_common_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_common_header_t);
	fbh = (rtcp_fb_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_header_t);
	fci = (rtcp_fb_tmmbr_fci_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_tmmbr_fci_t);
	fbh->packet_sender_ssrc = htonl(rtp_session_get_send_ssrc(session));
	fbh->media_source_ssrc = htonl(0);
	memcpy(fci, rtcp_RTPFB_tmmbr_get_fci(session->rtcp.tmmbr_info.received), sizeof(rtcp_fb_tmmbr_fci_t));
	fci->ssrc = htonl(ssrc);

	/* Fill common header */
	rtcp_common_header_init(ch, session, RTCP_RTPFB, RTCP_RTPFB_TMMBN, msgdsize(h));

	return h;
}

// See https://datatracker.ietf.org/doc/html/draft-alvestrand-rmcat-remb-03
static mblk_t *make_rtcp_fb_goog_remb(RtpSession *session, uint64_t mxtbr) {
	const int size =
	    sizeof(rtcp_common_header_t) + sizeof(rtcp_fb_header_t) + sizeof(rtcp_fb_goog_remb_fci_t) + sizeof(uint32_t);
	mblk_t *h = allocb(size, 0);
	uint8_t mxtbr_exp = 0;
	uint32_t mxtbr_mantissa = 0;

	/* Compute mxtbr exp and mantissa */
	while (mxtbr >= (1 << 18)) {
		mxtbr >>= 1;
		mxtbr_exp++;
	}
	mxtbr_mantissa = mxtbr & 0x0003FFFF;

	rtcp_common_header_t *ch = (rtcp_common_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_common_header_t);

	/* Fill RTCP FB header */
	rtcp_fb_header_t *fbh = (rtcp_fb_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_header_t);

	fbh->packet_sender_ssrc = htonl(rtp_session_get_send_ssrc(session));
	fbh->media_source_ssrc = htonl(0);

	/* Fill REMB */
	rtcp_fb_goog_remb_fci_t *fci = (rtcp_fb_goog_remb_fci_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_goog_remb_fci_t);

	fci->identifier = htonl(0x52454D42); // REMB in ascii

	rtcp_fb_goog_remb_fci_set_num_ssrc(fci, 1);
	rtcp_fb_goog_remb_fci_set_mxtbr_exp(fci, mxtbr_exp);
	rtcp_fb_goog_remb_fci_set_mxtbr_mantissa(fci, mxtbr_mantissa);

	/* Fill SSRCs */
	uint32_t *ssrc = (uint32_t *)h->b_wptr;
	h->b_wptr += sizeof(uint32_t);

	*ssrc = htonl(session->rcv.ssrc);

	/* Fill common header */
	rtcp_common_header_init(ch, session, RTCP_PSFB, RTCP_PSFB_AFB, msgdsize(h));

	/* Store packet to be able to retransmit. */
	if (session->rtcp.goog_remb_info.sent) freemsg(session->rtcp.goog_remb_info.sent);
	session->rtcp.goog_remb_info.sent = copymsg(h);

	return h;
}

bool_t rtp_session_rtcp_psfb_scheduled(RtpSession *session, rtcp_psfb_type_t type) {
	mblk_t *m = session->rtcp.send_algo.fb_packets;
	while (m != NULL) {
		if ((rtcp_is_PSFB_internal(m) == TRUE) && (rtcp_PSFB_get_type(m) == type)) {
			return TRUE;
		}
		m = m->b_cont;
	}
	return FALSE;
}

bool_t rtp_session_rtcp_rtpfb_scheduled(RtpSession *session, rtcp_rtpfb_type_t type) {
	mblk_t *m = session->rtcp.send_algo.fb_packets;
	while (m != NULL) {
		if ((rtcp_is_RTPFB_internal(m) == TRUE) && (rtcp_RTPFB_get_type(m) == type)) {
			return TRUE;
		}
		m = m->b_cont;
	}
	return FALSE;
}

void rtp_session_send_rtcp_fb_generic_nack(RtpSession *session, uint16_t pid, uint16_t blp) {
	mblk_t *m;
	if ((rtp_session_avpf_enabled(session) == TRUE) &&
	    (rtp_session_avpf_feature_enabled(session, ORTP_AVPF_FEATURE_GENERIC_NACK) == TRUE)) {
		m = make_rtcp_fb_generic_nack(session, pid, blp);
		rtp_session_add_fb_packet_to_send(session, m);
		rtp_session_send_fb_rtcp_packet_and_reschedule(session);
	}
}

void rtp_session_send_rtcp_fb_pli(RtpSession *session) {
	mblk_t *m;
	if ((rtp_session_avpf_enabled(session) == TRUE) &&
	    (rtp_session_avpf_payload_type_feature_enabled(session, PAYLOAD_TYPE_AVPF_PLI) == TRUE)) {
		bool_t can_send_immediately = FALSE;
		if (rtp_session_rtcp_psfb_scheduled(session, RTCP_PSFB_PLI) != TRUE) {
			m = make_rtcp_fb_pli(session);
			can_send_immediately = is_fb_packet_to_be_sent_immediately(session);
			rtp_session_add_fb_packet_to_send(session, m);
		}
		if (can_send_immediately) {
			rtp_session_send_fb_rtcp_packet_and_reschedule(session);
		}
	}
}

void rtp_session_send_rtcp_fb_fir(RtpSession *session) {
	mblk_t *m;
	if ((rtp_session_avpf_enabled(session) == TRUE) &&
	    (rtp_session_avpf_payload_type_feature_enabled(session, PAYLOAD_TYPE_AVPF_FIR) == TRUE)) {
		bool_t can_send_immediately = FALSE;
		if (rtp_session_rtcp_psfb_scheduled(session, RTCP_PSFB_FIR) != TRUE) {
			m = make_rtcp_fb_fir(session);
			can_send_immediately = is_fb_packet_to_be_sent_immediately(session);
			rtp_session_add_fb_packet_to_send(session, m);
		}
		if (can_send_immediately) {
			rtp_session_send_fb_rtcp_packet_and_reschedule(session);
		}
	}
}

void rtp_session_send_rtcp_fb_sli(RtpSession *session, uint16_t first, uint16_t number, uint8_t picture_id) {
	mblk_t *m;
	if (rtp_session_avpf_enabled(session) == TRUE) {
		/* Only send SLI if SLI and RPSI features have been enabled. SLI without RPSI is not really useful. */
		if ((rtp_session_avpf_payload_type_feature_enabled(session, PAYLOAD_TYPE_AVPF_SLI) == TRUE) &&
		    (rtp_session_avpf_payload_type_feature_enabled(session, PAYLOAD_TYPE_AVPF_RPSI) == TRUE)) {
			/* we check first if the packet can be sent immediately. is_fb_packet_to_be_sent_immediately() will return
			 * FALSE if there are queued feedback packets, which we are going to do in
			 * rtp_session_add_fb_packet_to_send() just after.
			 */
			bool_t can_send_immediately = is_fb_packet_to_be_sent_immediately(session);
			m = make_rtcp_fb_sli(session, first, number, picture_id);
			rtp_session_add_fb_packet_to_send(session, m);
			if (can_send_immediately) {
				rtp_session_send_fb_rtcp_packet_and_reschedule(session);
			}
		} else {
			// Try to fallback to sending a PLI if the SLI feature has not been enabled.
			rtp_session_send_rtcp_fb_pli(session);
		}
	}
}

void rtp_session_send_rtcp_fb_rpsi(RtpSession *session, uint8_t *bit_string, uint16_t bit_string_len) {
	mblk_t *m;
	if ((rtp_session_avpf_enabled(session) == TRUE) &&
	    (rtp_session_avpf_payload_type_feature_enabled(session, PAYLOAD_TYPE_AVPF_RPSI) == TRUE)) {
		bool_t can_send_immediately;
		m = make_rtcp_fb_rpsi(session, bit_string, bit_string_len);
		can_send_immediately = is_fb_packet_to_be_sent_immediately(session);
		rtp_session_add_fb_packet_to_send(session, m);
		if (can_send_immediately) {
			rtp_session_send_fb_rtcp_packet_and_reschedule(session);
		}
	}
}

void rtp_session_send_rtcp_fb_tmmbr(RtpSession *session, uint64_t mxtbr) {
	mblk_t *m;
	if ((rtp_session_avpf_enabled(session) == TRUE) &&
	    (rtp_session_avpf_feature_enabled(session, ORTP_AVPF_FEATURE_TMMBR) == TRUE)) {
		if ((rtp_session_rtcp_rtpfb_scheduled(session, RTCP_RTPFB_TMMBR) != TRUE) &&
		    (rtp_session_get_recv_ssrc(session) != 0)) {
			uint16_t overhead = (session->rtp.gs.sockfamily == AF_INET6) ? IP6_UDP_OVERHEAD : IP_UDP_OVERHEAD;
			m = make_rtcp_fb_tmmbr(session, mxtbr, overhead);
			rtp_session_add_fb_packet_to_send(session, m);
			session->rtcp.send_algo.tmmbr_scheduled = TRUE;
		}
		rtp_session_send_fb_rtcp_packet_and_reschedule(session);
	}
}

void rtp_session_send_rtcp_fb_tmmbn(RtpSession *session, uint32_t ssrc) {
	mblk_t *m;
	if ((rtp_session_avpf_enabled(session) == TRUE) &&
	    (rtp_session_avpf_feature_enabled(session, ORTP_AVPF_FEATURE_TMMBR) == TRUE)) {
		m = make_rtcp_fb_tmmbn(session, ssrc);
		if (m) {
			rtp_session_add_fb_packet_to_send(session, m);
			session->rtcp.send_algo.tmmbn_scheduled = TRUE;
		}
		rtp_session_send_fb_rtcp_packet_and_reschedule(session);
	}
}

void rtp_session_send_rtcp_fb_goog_remb(RtpSession *session, uint64_t mxtbr) {
	if ((rtp_session_avpf_enabled(session) == TRUE) &&
	    (rtp_session_avpf_feature_enabled(session, ORTP_AVPF_FEATURE_GOOG_REMB) == TRUE)) {
		bool_t can_send_immediately = FALSE;
		if (rtp_session_rtcp_psfb_scheduled(session, RTCP_PSFB_AFB) != TRUE) {
			mblk_t *m = make_rtcp_fb_goog_remb(session, mxtbr);
			can_send_immediately = is_fb_packet_to_be_sent_immediately(session);
			rtp_session_add_fb_packet_to_send(session, m);
			session->rtcp.send_algo.goog_remb_scheduled = TRUE;
		}
		if (can_send_immediately) rtp_session_send_fb_rtcp_packet_and_reschedule(session);
	}
}

bool_t rtp_session_avpf_enabled(RtpSession *session) {
	PayloadType *pt = rtp_profile_get_payload(session->snd.profile, session->snd.pt);
	if (!pt) {
		ortp_warning("rtp_session_avpf_enabled(): payload type not set, unreliable result returned.");
	}
	return pt && (payload_type_get_flags(pt) & PAYLOAD_TYPE_RTCP_FEEDBACK_ENABLED);
}

bool_t rtp_session_avpf_payload_type_feature_enabled(RtpSession *session, unsigned char feature) {
	PayloadType *pt = rtp_profile_get_payload(session->snd.profile, session->snd.pt);
	PayloadTypeAvpfParams params;
	if (!pt) return FALSE;
	params = payload_type_get_avpf_params(pt);
	if (params.features & feature) return TRUE;
	return FALSE;
}

bool_t rtp_session_avpf_feature_enabled(RtpSession *session, unsigned char feature) {
	if (session->avpf_features & feature) return TRUE;
	return FALSE;
}

void rtp_session_enable_avpf_feature(RtpSession *session, unsigned char feature, bool_t enable) {
	if (enable) {
		session->avpf_features |= feature;
	} else {
		session->avpf_features &= ~feature;
	}
}

uint16_t rtp_session_get_avpf_rr_interval(RtpSession *session) {
	PayloadType *pt = rtp_profile_get_payload(session->rcv.profile, session->rcv.pt);
	PayloadTypeAvpfParams params;
	if (!pt) return RTCP_DEFAULT_REPORT_INTERVAL;
	params = payload_type_get_avpf_params(pt);
	return (uint16_t)params.trr_interval;
}

bool_t rtp_session_has_fb_packets_to_send(RtpSession *session) {
	return (session->rtcp.send_algo.fb_packets == NULL) ? FALSE : TRUE;
}
