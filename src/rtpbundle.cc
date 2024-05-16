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

#include <algorithm>

#include <bctoolbox/defs.h>

#include "ortp/logging.h"
#include "ortp/rtpsession.h"
#include "rtpbundle.h"
#include "rtpsession_priv.h"

// C - Interface

extern "C" RtpBundle *rtp_bundle_new(void) {
	return (RtpBundle *)new RtpBundleCxx();
}

extern "C" void rtp_bundle_delete(RtpBundle *bundle) {
	delete (RtpBundleCxx *)bundle;
}

extern "C" int rtp_bundle_get_mid_extension_id(RtpBundle *bundle) {
	return ((RtpBundleCxx *)bundle)->getMidId();
}

extern "C" void rtp_bundle_set_mid_extension_id(RtpBundle *bundle, int id) {
	((RtpBundleCxx *)bundle)->setMidId(id);
}
extern "C" void rtp_bundle_add_session(RtpBundle *bundle, const char *mid, RtpSession *session) {
	((RtpBundleCxx *)bundle)->addSession(mid, session);
}
extern "C" void
rtp_bundle_add_fec_session(RtpBundle *bundle, const RtpSession *source_session, RtpSession *fec_session) {
	((RtpBundleCxx *)bundle)->addFecSession(source_session, fec_session);
}
extern "C" void rtp_bundle_remove_session_by_id(RtpBundle *bundle, const char *mid) {
	((RtpBundleCxx *)bundle)->removeSession(mid);
}

extern "C" void rtp_bundle_remove_session(RtpBundle *bundle, RtpSession *session) {
	((RtpBundleCxx *)bundle)->removeSession(session);
}

extern "C" void rtp_bundle_clear(RtpBundle *bundle) {
	((RtpBundleCxx *)bundle)->clear();
}

extern "C" RtpSession *rtp_bundle_get_primary_session(RtpBundle *bundle) {
	return ((RtpBundleCxx *)bundle)->getPrimarySession();
}

extern "C" void rtp_bundle_set_primary_session(RtpBundle *bundle, const char *mid) {
	((RtpBundleCxx *)bundle)->setPrimarySession(mid);
}

extern "C" const char *rtp_bundle_get_session_mid(RtpBundle *bundle, RtpSession *session) {
	try {
		auto &mid = ((RtpBundleCxx *)bundle)->getSessionMid(session);
		return mid.c_str();
	} catch (std::string const &e) {
		ortp_warning("RtpBundle[%p]: cannot get mid for session (%p): %s", bundle, session, e.c_str());
		return NULL;
	}
}

extern "C" bool_t rtp_bundle_dispatch(RtpBundle *bundle, bool_t is_rtp, mblk_t *m) {
	return ((RtpBundleCxx *)bundle)->dispatch(is_rtp, m);
}

extern "C" RtpSession *rtp_bundle_lookup_session_for_outgoing_packet(RtpBundle *bundle, mblk_t *m) {
	return ((RtpBundleCxx *)bundle)->checkForSession(m, true, true);
}

// C++ - Implementation

RtpBundleCxx::~RtpBundleCxx() {
	clear();
}
int RtpBundleCxx::getMidId() const {
	return midId;
}

void RtpBundleCxx::setMidId(int id) {
	midId = id;
}
void RtpBundleCxx::addSession(const std::string &mid, RtpSession *session) {
	auto it =
	    std::find_if(sessions.begin(), sessions.end(),
	                 [session](const std::pair<std::string, RtpSession *> &t) -> bool { return t.second == session; });

	if (it != sessions.end()) {
		ortp_error("RtpBundle[%p]: Cannot add session (%p) as it is already in the bundle", this, session);
		return;
	}

	sessions.emplace(mid, session);

	if (!primary) {
		primary = session;
		session->is_primary = TRUE;
	}
	rtp_session_set_bundle(session, (RtpBundle *)this);
}
void RtpBundleCxx::addFecSession(const RtpSession *sourceSession, RtpSession *fecSession) {
	auto it = std::find_if(
	    sessions.begin(), sessions.end(),
	    [sourceSession](const std::pair<std::string, RtpSession *> &t) -> bool { return t.second == sourceSession; });

	if (it == sessions.end()) {
		ortp_error("RtpBundle[%p]: Cannot add session (%p) because the associated source session isn't in the bundle",
		           this, fecSession);
		return;
	}
	std::string mid = getSessionMid(it->second);
	fec_sessions.emplace(mid, fecSession);
	rtp_session_set_bundle(fecSession, (RtpBundle *)this);
	ortp_message("Fec session [%u] added to the bundle", rtp_session_get_send_ssrc(fecSession));
}

void RtpBundleCxx::removeSession(const std::string &mid) {
	const auto session = sessions.find(mid);

	// sessions is a multimap, we need to remove all RtpSessions pointed by the mid
	if (session != sessions.end()) {
		// We have to remove the bundle from each RtpSession
		const auto range = sessions.equal_range(mid);
		for (auto i = range.first; i != range.second; ++i) {
			clearSession(i->second);
		}

		ssrcToMidMutex.lock();
		for (auto it = ssrcToMid.begin(); it != ssrcToMid.end();) {
			if (it->second == mid) {
				it = ssrcToMid.erase(it);
			} else {
				++it;
			}
		}
		ssrcToMidMutex.unlock();

		// If we still have a FecSession for this mid then remove it too
		const auto fec_session = fec_sessions.find(mid);
		if (fec_session != fec_sessions.end()) {
			rtp_session_set_bundle(fec_session->second, NULL);
			fec_sessions.erase(mid);
		}

		sessions.erase(mid);
	}
}

void RtpBundleCxx::removeSession(RtpSession *session) {
	const auto it =
	    std::find_if(sessions.begin(), sessions.end(),
	                 [session](const std::pair<std::string, RtpSession *> &t) -> bool { return t.second == session; });

	if (it != sessions.end()) {
		// If we are the only RtpSession for the mid, use the removeSession(mid) instead.
		// Else only remove the RtpSession.
		const auto count = sessions.count(it->first);
		if (count == 1) {
			removeSession(it->first);
		} else {
			clearSession(it->second);
			sessions.erase(it);
		}
	}
}

void RtpBundleCxx::clearSession(RtpSession *session) {
	rtp_session_set_bundle(session, nullptr);

	if (primary != nullptr) {
		if (session == primary) {
			primary->is_primary = FALSE;
			primary = nullptr;
		} else {
			// Remove the session from all of primary's signal tables.
			for (const bctbx_list_t *it = primary->signal_tables; it != nullptr; it = it->next) {
				const auto t = static_cast<RtpSignalTable *>(it->data);
				rtp_signal_table_remove_by_source_session(t, session);
			}
		}
	}

	if (session->fec_stream != nullptr) {
		const auto it = std::find_if(fec_sessions.begin(), fec_sessions.end(),
		                             [session](const std::pair<std::string, RtpSession *> &t) -> bool {
			                             return t.second == fec_stream_get_fec_session(session->fec_stream);
		                             });
		if (it != fec_sessions.end()) {
			rtp_session_set_bundle(it->second, nullptr);
			fec_sessions.erase(it);
		}
	}
}

void RtpBundleCxx::clear() {
	for (const auto &entry : sessions) {
		RtpSession *session = entry.second;
		session->bundle = NULL;
	}
	for (const auto &entry : fec_sessions) {
		RtpSession *session = entry.second;
		session->bundle = NULL;
	}
	primary = NULL;
	ssrcToMid.clear();
	sessions.clear();
	fec_sessions.clear();
}

RtpSession *RtpBundleCxx::getPrimarySession() const {
	return primary;
}

void RtpBundleCxx::setPrimarySession(const std::string &mid) {
	auto session = sessions.find(mid);
	if (session != sessions.end()) {
		if (primary) {
			primary->is_primary = FALSE;
		}

		primary = session->second;
		primary->is_primary = TRUE;
	}
}

const std::string &RtpBundleCxx::getSessionMid(RtpSession *session) const {
	auto it =
	    std::find_if(sessions.begin(), sessions.end(),
	                 [session](const std::pair<std::string, RtpSession *> &t) -> bool { return t.second == session; });

	if (it != sessions.end()) {
		return it->first;
	} else { // Could be a FEC session
		it = std::find_if(
		    fec_sessions.begin(), fec_sessions.end(),
		    [session](const std::pair<std::string, RtpSession *> &t) -> bool { return t.second == session; });
		if (it != sessions.end()) {
			return it->first;
		}
	}

	throw std::string("the session must be in the bundle!");
}

bool RtpBundleCxx::assignSsrcToMid(const uint32_t ssrc, const std::string &mid, bool isRtp) {
	if (const auto session = sessions.find(mid); session != sessions.end()) {
		if (ssrcToMid.find(ssrc) == ssrcToMid.end()) {
			ssrcToMid[ssrc] = mid;
			ortp_message("RtpBundle[%p] SSRC [%u] paired with mid [%s] from [%s]", this, ssrc, mid.c_str(),
			             isRtp ? "RTP" : "RTCP");
		}

		// Return true here, we don't want to return false if we already have an entry
		return true;
	}
	return false;
}

static void getSsrcFromSdes(void *userData,
                            uint32_t ssrc,
                            rtcp_sdes_type_t t,
                            BCTBX_UNUSED(const char *content),
                            BCTBX_UNUSED(uint8_t contentLen)) {
	uint32_t *value = (uint32_t *)userData;

	if (*value == 0 || t == RTCP_SDES_MID) {
		*value = ssrc;
	}
}

static uint32_t getSsrcFromMessage(const mblk_t *m, bool isRtp) {
	if (isRtp) {
		return rtp_get_ssrc(m);
	}

	const rtcp_common_header_t *ch = rtcp_get_common_header(m);
	uint32_t ssrc = 0;

	switch (rtcp_common_header_get_packet_type(ch)) {
		case RTCP_SR:
			return rtcp_SR_get_ssrc(m);
		case RTCP_RR:
			return rtcp_RR_get_ssrc(m);
		case RTCP_SDES:
			rtcp_sdes_parse(m, getSsrcFromSdes, &ssrc);
			return ssrc;
		case RTCP_BYE:
			if (rtcp_BYE_get_ssrc(m, 0, &ssrc)) {
				return ssrc;
			}
			return -1;
		case RTCP_APP:
			return rtcp_APP_get_ssrc(m);
		case RTCP_RTPFB:
			return rtcp_RTPFB_get_packet_sender_ssrc(m);
		case RTCP_PSFB:
			return rtcp_PSFB_get_packet_sender_ssrc(m);
		case RTCP_XR:
			return rtcp_XR_get_ssrc(m);
		default:
			ortp_warning("Unknown RTCP packet type (%u) while retrieving it's SSRC",
			             rtcp_common_header_get_packet_type(ch));
			break;
	}

	return -1;
}

static bool getRTCPReferedSSRC(const mblk_t *m, uint32_t *ssrc) {
	const rtcp_common_header_t *ch = rtcp_get_common_header(m);
	const report_block_t *rb;

	switch (rtcp_common_header_get_packet_type(ch)) {
		case RTCP_SR:
			if (rtcp_common_header_get_rc(ch) != 1) return false;
			rb = rtcp_SR_get_report_block(m, 0);
			if (rb) {
				*ssrc = report_block_get_ssrc(rb);
				return true;
			}
			break;
		case RTCP_RR:
			if (rtcp_common_header_get_rc(ch) != 1) return false;
			rb = rtcp_RR_get_report_block(m, 0);
			if (rb) {
				*ssrc = report_block_get_ssrc(rb);
				return true;
			}
			break;
		case RTCP_APP:
		case RTCP_SDES:
			/* no referred SSRC in a SDES or APP*/
			break;
		case RTCP_BYE:
			if (rtcp_common_header_get_rc(ch) != 1) return false;
			if (rtcp_BYE_get_ssrc(m, 0, ssrc)) {
				return true;
			}
			break;
		case RTCP_RTPFB:
			*ssrc = rtcp_RTPFB_get_media_source_ssrc(m);

			// In case of TMMBR or TMMBN, media ssrc is always 0 but we can use the ssrc in the FCI field
			if (const auto type = rtcp_RTPFB_get_type(m);
			    *ssrc == 0 && (type == RTCP_RTPFB_TMMBR || type == RTCP_RTPFB_TMMBN)) {
				if (const auto *fci = rtcp_RTPFB_tmmbr_get_fci(m); fci != nullptr)
					*ssrc = rtcp_fb_tmmbr_fci_get_ssrc(fci);
			}
			return true;
		case RTCP_PSFB:
			*ssrc = rtcp_PSFB_get_media_source_ssrc(m);
			return true;
		case RTCP_XR:
			/* not handled, but no so necessary*/
			break;
		default:
			break;
	}

	return false;
}

void RtpBundleCxx::checkForSessionSdesCallback(
    void *userData, BCTBX_UNUSED(uint32_t ssrc), rtcp_sdes_type_t t, const char *content, uint8_t contentLen) {
	auto *bundle = static_cast<RtpBundleCxx *>(userData);

	if (t == RTCP_SDES_MID) {
		bundle->sdesParseMid = std::string(content, contentLen);
	}
}
RtpSession *RtpBundleCxx::getFecSessionFromRTCP(const mblk_t *m) {

	for (auto &pair : fec_sessions) {
		if (rtp_session_get_recv_ssrc(pair.second) == getSsrcFromMessage(m, false)) {
			return pair.second;
		}
	}
	return nullptr;
}

bool RtpBundleCxx::assignmentPossible(RtpSession *session, const mblk_t *m, uint32_t ssrc, bool isRtp) {
	if (session->ssrc_set) return false;
	if (isRtp) {
		if (session->mode != RTP_SESSION_SENDONLY) {
			/* Check this blank session knows the payload type of the incoming packet - it shall
			 * not be the case for a fec pt */
			RtpProfile *profile = rtp_session_get_recv_profile(session);
			if (rtp_profile_get_payload(profile, rtp_get_payload_type(m)) != NULL) {
				ortp_message("RtpBundle[%p]: can assign incoming SSRC %u to session %p using RTP with pt %d", this,
				             ssrc, session, rtp_get_payload_type(m));
				return true;
			}
		}
	} else {
		/* RTCP case:
		 * Assign only if the SSRC in the report block matches the outgoing ssrc.
		 */
		if (session->mode == RTP_SESSION_SENDONLY) {
			uint32_t local_ssrc = 0;
			if (getRTCPReferedSSRC(m, &local_ssrc) && session->snd.ssrc == local_ssrc) {
				ortp_message("RtpBundle[%p]: can assign incoming SSRC %u to session %p using RTCP", this, ssrc,
				             session);
				return true;
			}
		}
	}
	return false;
}

std::string RtpBundleCxx::getMid(const mblk_t *m, bool isRtp) {
	if (isRtp && rtp_get_extbit(m)) {
		uint8_t *data;
		if (const size_t midSize = rtp_get_extension_header(m, midId != -1 ? midId : RTP_EXTENSION_MID, &data);
		    midSize != static_cast<size_t>(-1)) {
			return {reinterpret_cast<char *>(data), midSize};
		}
	} else {
		if (rtcp_is_SDES(m)) {
			/* The checkForSessionSdesCallback() checks for presence of mid */
			sdesParseMid.clear();
			rtcp_sdes_parse(m, checkForSessionSdesCallback, this);

			return sdesParseMid;
		}
	}

	return "";
}

RtpSession *RtpBundleCxx::checkForSession(const mblk_t *m, bool isRtp, bool isOutgoing) {
	const std::lock_guard guard(ssrcToMidMutex);

	if (isRtp && rtp_get_version(m) != 2) {
		/* STUN packet*/
		return primary;
	}

	if (!isRtp && rtcp_is_RTPFB(m) && getFecSessionFromRTCP(m) != nullptr) {
		ortp_error("[flexfec] Received an RTCP packet for flexfec session");
		return nullptr;
	}

	uint32_t ssrc = getSsrcFromMessage(m, isRtp);
	std::string mid = getMid(m, isRtp);

	if (const auto it = ssrcToMid.find(ssrc); mid.empty()) {
		// If there is no mid in the packet, check if we have it stored for this ssrc
		if (it == ssrcToMid.end()) {
			ortp_warning("RtpBundle[%p]: Packet with SSRC %u doesn't have any mid and no corresponding mid in bundle",
			             this, ssrc);
			return nullptr;
		}

		mid = it->second;
	} else if (it == ssrcToMid.end()) {
		// We have a mid in the packet, but not in the association map. Insert it if we have a corresponding session.
		if (!assignSsrcToMid(ssrc, mid, isRtp)) {
			ortp_warning("RtpBundle[%p]: SSRC %u not found and mid \"%s\" from msg (%d) does not "
			             "correspond to any sessions",
			             this, ssrc, mid.c_str(), static_cast<int>(rtp_get_seqnumber(m)));
			return nullptr;
		}
	}

	// If the RTCP packet is referring to another SSRC, then use this one instead
	if (uint32_t referredSsrc; !isRtp && getRTCPReferedSSRC(m, &referredSsrc) && referredSsrc != 0) {
		ssrc = referredSsrc;
	}

	// Return the corresponding session if we find it
	const auto [first, last] = sessions.equal_range(mid);
	if (first == last) {
		ortp_warning("RtpBundle[%p]: Unable to find session with mid %s (SSRC %u)", this, mid.c_str(), ssrc);
		return nullptr;
	}

	// TODO: change this loop into a map<SSRC, RtpSession*> lookup
	for (auto s = first; s != last; ++s) {
		const auto session = s->second;
		if (isOutgoing && session->snd.ssrc == ssrc) {
			return session;
		}

		if (!isOutgoing && session->ssrc_set) {
			/* This session already has a SSRC assigned, do they match? */
			if (session->rcv.ssrc == ssrc) {
				return session;
			}

			/* check if there is a fec session that could do */
			/* TODO: move out this in FecStream, using on_new_incoming_ssrc_in_bundle callback */
			if (session->fec_stream) {
				RtpSession *fec_session = fec_stream_get_fec_session(session->fec_stream);
				if (rtp_session_get_recv_payload_type(fec_session) == rtp_get_payload_type(m)) {
					/* payload type are matching */
					if (fec_session->ssrc_set && fec_session->rcv.ssrc == ssrc) {
						/* ssrc are matching */
						return fec_session;
					}
					if (!fec_session->ssrc_set) {
						ortp_message("RtpBundle[%p]: assign incoming SSRC %u to FEC session %p with pt %d", this, ssrc,
						             fec_session, rtp_get_payload_type(m));
						/* TODO shall we check the CSRC in the packet to check that this is the correct FEC
						 * session for the associated RTP session ?*/
						return fec_session;
					}
				}
			}
		}
	}

	// If we are here, it is because we did not found an already assigned RtpSession for this SSRC.
	// Now, lookup if one of these session can be assigned
	if (!isOutgoing) {
		for (auto s = first; s != last; ++s) {
			if (const auto session = s->second; assignmentPossible(session, m, ssrc, isRtp)) {
				session->ssrc_set = TRUE;
				session->rcv.ssrc = ssrc;
				/* TODO: insert the session into the map */
				return session;
			}
		}

		if (!isRtp) {
			for (auto s = first; s != last; ++s) {
				const auto session = s->second;
				uint32_t local_ssrc = 0;
				if (getRTCPReferedSSRC(m, &local_ssrc) && session->snd.ssrc == local_ssrc) {
					const rtcp_common_header_t *ch = rtcp_get_common_header(m);
					ortp_message("RtpBundle[%p]: RTCP msg (%d) refering to SSRC %u with unknown sender-ssrc %u "
					             "routed to session %p",
					             this, rtcp_common_header_get_packet_type(ch), local_ssrc, ssrc, session);
					return session;
				}
			}
			// ortp_warning("RtpBundle[%p]: unrouted RTCP packet with sender-ssrc %u", this, ssrc);
		}
	}

	// If we are, it means that we have no existing RtpSession for this SSRC.
	// Invoke the callbacks to let the application layer decide what to do.
	RtpSession *newRtpSession = nullptr;
	if (isRtp && !mid.empty()) { // Do not create new session for unknown RTCP or when mid is unknown
		if (isOutgoing) {
			ortp_message("RtpBundle[%p]: emit on_new_outgoing_ssrc_in_bundle on SSRC %u from session %p with pt %d",
			             this, ssrc, getPrimarySession(), rtp_get_payload_type(m));
			rtp_signal_table_emit3(&(getPrimarySession()->on_new_outgoing_ssrc_in_bundle), (void *)m, &newRtpSession);
			if (newRtpSession) {
				newRtpSession->snd.ssrc = ssrc;
			}
		} else {
			ortp_message("RtpBundle[%p]: emit on_new_incoming_ssrc_in_bundle on SSRC %u from session %p with pt %d",
			             this, ssrc, getPrimarySession(), rtp_get_payload_type(m));
			rtp_signal_table_emit3(&(getPrimarySession()->on_new_incoming_ssrc_in_bundle), (void *)m, &newRtpSession);
			if (newRtpSession) {
				/* the new session is associated to the incoming SSRC */
				newRtpSession->ssrc_set = TRUE;
				newRtpSession->rcv.ssrc = ssrc;
			}
		}

		if (newRtpSession) {
			/* TODO: insert or update the map<SSRC, RtpSession> */
			if (newRtpSession->bundle == nullptr) {
				addSession(mid, newRtpSession);
			}
		}
	}
	return newRtpSession;
}

bool RtpBundleCxx::dispatch(bool isRtp, mblk_t *m) {
	if (isRtp) {
		return dispatchRtpMessage(m);
	} else {
		return dispatchRtcpMessage(m);
	}
}

bool RtpBundleCxx::dispatchRtpMessage(mblk_t *m) {
	RtpSession *session = checkForSession(m, true);
	if (session == NULL) {
		freemsg(m);
		return true;
	}

	if (session != primary) {
		ortp_mutex_lock(&session->rtp.gs.bundleq_lock);
		putq(&session->rtp.gs.bundleq, m);
		ortp_mutex_unlock(&session->rtp.gs.bundleq_lock);
		return true;
	}

	return false;
}

bool RtpBundleCxx::dispatchRtcpMessage(mblk_t *m) {
	mblk_t *primarymsg = NULL;
	const mblk_t *m_rtcp;

	// Check if the packet contains a SDES first
	RtcpParserContext rtcp_parser_ctx;
	m_rtcp = rtcp_parser_context_init(&rtcp_parser_ctx, m);
	do {
		if (rtcp_is_SDES(m_rtcp)) {
			// call checkForSession that will update the mid table
			checkForSession(m_rtcp, false);
		}
	} while ((m_rtcp = rtcp_parser_context_next_packet(&rtcp_parser_ctx)) != NULL);

	/* Now go through the compound RTCP packet and dispatch each of its elements in streams.
	 * In order to avoid unnecessary split between SR and SDES of a same compound packet,
	 * each RTCP element belonging to same stream are aggregated.*/
	m_rtcp = rtcp_parser_context_start(&rtcp_parser_ctx);
	std::map<RtpSession *, mblk_t *> dispatchMap;
	do {
		mblk_t *tmp = dupmsg((mblk_t *)m_rtcp); /* const qualifier discarded intentionally*/
		tmp->b_wptr = tmp->b_rptr + rtcp_get_size(m_rtcp);

		// some RTCP packet can be for multiple streams (e.g. BYE)
		RtpSession *session = checkForSession(tmp, false);
		if (session) {
			auto &pendingMsg = dispatchMap[session];
			if (pendingMsg == nullptr) pendingMsg = tmp;
			else concatb(pendingMsg, tmp);
		} else {
			const rtcp_common_header_t *ch = rtcp_get_common_header(tmp);
			ortp_warning("RtpBundle[%p]: Rctp msg (%d) ssrc=%u does not correspond to any sessions", this,
			             rtcp_common_header_get_packet_type(ch), getSsrcFromMessage(tmp, false));
			freemsg(tmp);
		}
	} while ((m_rtcp = rtcp_parser_context_next_packet(&rtcp_parser_ctx)) != NULL);

	rtcp_parser_context_uninit(&rtcp_parser_ctx);

	for (auto &p : dispatchMap) {
		if (p.first == primary) {
			primarymsg = p.second;
		} else {
			RtpSession *session = p.first;
			ortp_mutex_lock(&session->rtcp.gs.bundleq_lock);
			msgpullup(p.second, (size_t)-1);
			putq(&session->rtcp.gs.bundleq, p.second);
			ortp_mutex_unlock(&session->rtcp.gs.bundleq_lock);
		}
	}

	if (primarymsg) {
		msgpullup(primarymsg, (size_t)-1);
		msgpullup(m, (size_t)-1);

		// FIXME: not so elegant to copy back to the original mblk_t.
		size_t len = primarymsg->b_wptr - primarymsg->b_rptr;
		memcpy(m->b_rptr, primarymsg->b_rptr, len);
		m->b_wptr = m->b_rptr + len;
		freemsg(primarymsg);
		return false;
	}
	freemsg(m);
	return true;
}
