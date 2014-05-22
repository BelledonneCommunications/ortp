/*
  The oRTP library is an RTP (Realtime Transport Protocol - rfc3550) stack.
  Copyright (C) 2011-2014 Belledonne Communications

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/


#include "ortp/ortp.h"
#include "ortp/rtpsession.h"
#include "ortp/rtcp.h"
#include "rtpsession_priv.h"


static mblk_t * rtp_session_create_rtcp_fb_pli(RtpSession *session) {
	int size = sizeof(rtcp_common_header_t) + sizeof(rtcp_fb_header_t);
	mblk_t *h= allocb(size, 0);
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

static mblk_t * rtp_session_create_rtcp_fb_fir(RtpSession *session) {
	int size = sizeof(rtcp_common_header_t) + sizeof(rtcp_fb_header_t) + sizeof(rtcp_fb_fir_fci_t);
	mblk_t *h = allocb(size, 0);
	rtcp_common_header_t *ch;
	rtcp_fb_header_t *fbh;
	rtcp_fb_fir_fci_t *fci;

	/* Fill FIR */
	ch = (rtcp_common_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_common_header_t);
	fbh = (rtcp_fb_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_header_t);
	fci = (rtcp_fb_fir_fci_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_fir_fci_t);
	fbh->packet_sender_ssrc = htonl(0);
	fbh->media_source_ssrc = htonl(rtp_session_get_recv_ssrc(session));
	fci->ssrc = htonl(rtp_session_get_send_ssrc(session));
	fci->seq_nr = session->rtcp.rtcp_fb_fir_seq_nr++;
	fci->pad1 = 0;
	fci->pad2 = 0;

	/* Fill common header */
	rtcp_common_header_init(ch, session, RTCP_PSFB, RTCP_PSFB_FIR, msgdsize(h));

	return h;
}

static mblk_t * rtp_session_create_rtcp_fb_sli(RtpSession *session, uint16_t first, uint16_t number, uint8_t picture_id) {
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

static mblk_t * rtp_session_create_rtcp_fb_rpsi(RtpSession *session, uint8_t *bit_string, uint16_t bit_string_len) {
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

void rtp_session_send_rtcp_fb_pli(RtpSession *session) {
	mblk_t *m;
	mblk_t *m_pli;
	RtpStream *st = &session->rtp;
	RtcpStream *rtcp_st = &session->rtcp;
	PayloadType *pt = rtp_profile_get_payload(session->snd.profile, session->snd.pt);

	if ((payload_type_get_flags(pt) & PAYLOAD_TYPE_RTCP_FEEDBACK_ENABLED)
		&& ((st->snd_last_ts - rtcp_st->last_rtcp_fb_pli_snt) > 1000)) {
		rtcp_st->last_rtcp_fb_pli_snt = st->snd_last_ts;
		m = NULL; //make_sr(session);
		m_pli = rtp_session_create_rtcp_fb_pli(session);
		concatb(m, m_pli);

		/* send the compound packet */
		//notify_sent_rtcp(session, m);
		ortp_message("Sending RTCP SR compound message with PLI on session [%p]", session);
		rtp_session_rtcp_send(session, m);
	}
}

void rtp_session_send_rtcp_fb_fir(RtpSession *session) {
	mblk_t *m;
	mblk_t *m_fir;
	PayloadType *pt = rtp_profile_get_payload(session->snd.profile, session->snd.pt);

	if (payload_type_get_flags(pt) & PAYLOAD_TYPE_RTCP_FEEDBACK_ENABLED) {
		m = NULL; //make_sr(session);
		m_fir = rtp_session_create_rtcp_fb_fir(session);
		concatb(m, m_fir);

		/* send the compound packet */
		//notify_sent_rtcp(session, m);
		ortp_message("Sending RTCP SR compound message with FIR on session [%p]", session);
		rtp_session_rtcp_send(session, m);
	}
}

void rtp_session_send_rtcp_fb_sli(RtpSession *session, uint16_t first, uint16_t number, uint8_t picture_id) {
	mblk_t *m;
	mblk_t *m_sli;
	PayloadType *pt = rtp_profile_get_payload(session->snd.profile, session->snd.pt);

	if (payload_type_get_flags(pt) & PAYLOAD_TYPE_RTCP_FEEDBACK_ENABLED) {
		m = NULL; //make_sr(session);
		m_sli = rtp_session_create_rtcp_fb_sli(session, first, number, picture_id);
		concatb(m, m_sli);

		/* send the compound packet */
		//notify_sent_rtcp(session, m);
		ortp_message("Sending RTCP SR compound message with SLI on session [%p]", session);
		rtp_session_rtcp_send(session, m);
	}
}

void rtp_session_send_rtcp_fb_rpsi(RtpSession *session, uint8_t *bit_string, uint16_t bit_string_len) {
	mblk_t *m;
	mblk_t *m_rpsi;
	PayloadType *pt = rtp_profile_get_payload(session->snd.profile, session->snd.pt);

	if (payload_type_get_flags(pt) & PAYLOAD_TYPE_RTCP_FEEDBACK_ENABLED) {
		m = NULL; //make_sr(session);
		m_rpsi = rtp_session_create_rtcp_fb_rpsi(session, bit_string, bit_string_len);
		concatb(m, m_rpsi);

		/* send the compound packet */
		//notify_sent_rtcp(session, m);
		ortp_message("Sending RTCP SR compound message with RPSI on session [%p]", session);
		rtp_session_rtcp_send(session, m);
	}
}
