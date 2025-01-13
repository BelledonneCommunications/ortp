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

#include "ortp_tester_utils.h"

#include <string>

#include <bctoolbox/utils.hh>

#include "rtpsession_priv.h"

bool_t ortp_tester_is_executable_installed(const char *executable, const char *resource) {
	return bctoolbox::Utils::isExecutableInstalled(std::string(executable), std::string(resource));
}

mblk_t *ortp_tester_make_dummy_rtcp_fb_pli(RtpSession *session) {
	int size = sizeof(rtcp_common_header_t) + sizeof(rtcp_fb_header_t);
	mblk_t *h = allocb(size, 0);
	rtcp_common_header_t *ch;
	rtcp_fb_header_t *fbh;

	/* Fill PLI */
	ch = (rtcp_common_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_common_header_t);
	fbh = (rtcp_fb_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_header_t);
	fbh->packet_sender_ssrc = htonl(session->rcv.ssrc);
	fbh->media_source_ssrc = htonl(session->snd.ssrc);

	/* Fill common header */
	rtcp_common_header_init(ch, session, RTCP_PSFB, RTCP_PSFB_PLI, msgdsize(h));

	return h;
}

static size_t rtcp_sr_init(RtpSession *session, uint8_t *buf, size_t size) {
	rtcp_sr_t *sr = (rtcp_sr_t *)buf;
	size_t sr_size = sizeof(rtcp_sr_t) - sizeof(report_block_t);
	if (size < sr_size) return 0;
	rtcp_common_header_init(&sr->ch, session, RTCP_SR, 0, sr_size);
	sr->ssrc = htonl(session->rcv.ssrc);
	return sr_size;
}

mblk_t *ortp_tester_make_dummy_sr(RtpSession *session) {
	mblk_t *sr = allocb(sizeof(rtcp_sr_t), 0);
	sr->b_wptr += rtcp_sr_init(session, sr->b_wptr, sizeof(rtcp_sr_t));

	// Change snd.ssrc so the wanted ssrc to test is set without touching the SDES packet
	const uint32_t snd = session->snd.ssrc;
	session->snd.ssrc = session->rcv.ssrc;

	mblk_t *sdes = rtp_session_create_rtcp_sdes_packet(session, FALSE);
	concatb(sr, sdes);

	session->snd.ssrc = snd;

	mblk_t *fb_pli = ortp_tester_make_dummy_rtcp_fb_pli(session);
	concatb(sr, fb_pli);

	return sr;
}