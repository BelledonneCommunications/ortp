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
	return reinterpret_cast<RtpBundle *>(new RtpBundleCxx());
}

extern "C" void rtp_bundle_delete(RtpBundle *bundle) {
	delete reinterpret_cast<RtpBundleCxx *>(bundle);
}

extern "C" int rtp_bundle_get_mid_extension_id(RtpBundle *bundle) {
	return reinterpret_cast<RtpBundleCxx *>(bundle)->getMidId();
}

extern "C" void rtp_bundle_set_mid_extension_id(RtpBundle *bundle, int id) {
	reinterpret_cast<RtpBundleCxx *>(bundle)->setMidId(id);
}

extern "C" void rtp_bundle_add_session(RtpBundle *bundle, const char *mid, RtpSession *session) {
	reinterpret_cast<RtpBundleCxx *>(bundle)->addSession(mid, session);
}

extern "C" void rtp_bundle_remove_sessions_by_id(RtpBundle *bundle, const char *mid) {
	reinterpret_cast<RtpBundleCxx *>(bundle)->removeSessions(mid);
}

extern "C" void rtp_bundle_remove_session(RtpBundle *bundle, RtpSession *session) {
	reinterpret_cast<RtpBundleCxx *>(bundle)->removeSession(session);
}

extern "C" void rtp_bundle_clear(RtpBundle *bundle) {
	reinterpret_cast<RtpBundleCxx *>(bundle)->clear();
}

extern "C" void rtp_bundle_session_mode_updated(RtpBundle *bundle, RtpSession *session, RtpSessionMode previous_mode) {
	reinterpret_cast<RtpBundleCxx *>(bundle)->sessionModeUpdated(session, previous_mode);
}

extern "C" RtpSession *rtp_bundle_get_primary_session(RtpBundle *bundle) {
	return reinterpret_cast<RtpBundleCxx *>(bundle)->getPrimarySession();
}

extern "C" void rtp_bundle_set_primary_session(RtpBundle *bundle, RtpSession *session) {
	reinterpret_cast<RtpBundleCxx *>(bundle)->setPrimarySession(session);
}

extern "C" char *rtp_bundle_get_session_mid(RtpBundle *bundle, RtpSession *session) {
	try {
		auto &mid = reinterpret_cast<RtpBundleCxx *>(bundle)->getSessionMid(session);
		return bctbx_strdup(mid.c_str());
	} catch (std::string const &e) {
		ortp_warning("RtpBundle[%p]: cannot get mid for session (%p): %s", bundle, session, e.c_str());
		return nullptr;
	}
}

extern "C" bool_t rtp_bundle_dispatch(RtpBundle *bundle, bool_t is_rtp, mblk_t *m) {
	return reinterpret_cast<RtpBundleCxx *>(bundle)->dispatch(is_rtp, m);
}

extern "C" RtpSession *rtp_bundle_lookup_session_for_outgoing_packet(RtpBundle *bundle, mblk_t *m) {
	return reinterpret_cast<RtpBundleCxx *>(bundle)->checkForSession(m, true, true);
}

// C++ - Implementation

RtpBundleCxx::~RtpBundleCxx() {
	clear();
}
int RtpBundleCxx::getMidId() const {
	return mMidId;
}

void RtpBundleCxx::setMidId(int id) {
	mMidId = id;
}

void RtpBundleCxx::addSession(const std::string &mid, RtpSession *session) {
	// Search for the session in both maps to check if it hasn't already been inserted.
	if (findSession(session))
		ortp_error("RtpBundle[%p]: Cannot add session (%p) as it is already in the bundle", this, session);

	// Check for the mode. If SENDONLY, we already know it's SSRC, and we can assign it now.
	// Otherwise, add it in the waiting for assignment map.
	if (session->mode == RTP_SESSION_SENDONLY) {
		mSsrcToSession.emplace(session->snd.ssrc, BundleSession{{mid, 0}, session});
	} else {
		mWaitingForAssignment.emplace(mid, session);
	}

	if (!mPrimary) {
		mPrimary = session;
		session->is_primary = TRUE;
	}

	rtp_session_set_bundle(session, reinterpret_cast<RtpBundle *>(this));
}

bool RtpBundleCxx::findSession(RtpSession *session) const {
	const auto inMainMap = std::find_if(
	    mSsrcToSession.begin(), mSsrcToSession.end(),
	    [session](const std::pair<uint32_t, BundleSession> &t) -> bool { return t.second.rtpSession == session; });

	if (inMainMap != mSsrcToSession.end()) {
		return true;
	}

	const auto inWaitingMap =
	    std::find_if(mWaitingForAssignment.begin(), mWaitingForAssignment.end(),
	                 [session](const std::pair<std::string, RtpSession *> &t) -> bool { return t.second == session; });

	if (inWaitingMap != mWaitingForAssignment.end()) {
		return true;
	}

	return false;
}

bool RtpBundleCxx::findMid(const std::string &mid) const {
	const auto inMainMap =
	    std::find_if(mSsrcToSession.begin(), mSsrcToSession.end(),
	                 [mid](const std::pair<uint32_t, BundleSession> &t) -> bool { return t.second.mid.mid == mid; });

	if (inMainMap != mSsrcToSession.end()) {
		return true;
	}

	const auto inWaitingMap =
	    std::find_if(mWaitingForAssignment.begin(), mWaitingForAssignment.end(),
	                 [mid](const std::pair<std::string, RtpSession *> &t) -> bool { return t.first == mid; });

	if (inWaitingMap != mWaitingForAssignment.end()) {
		return true;
	}

	return false;
}

void RtpBundleCxx::removeSessions(const std::string &mid) {
	const std::lock_guard guard(mAssignmentMutex);

	// Remove the session from the main map.
	for (auto it = mSsrcToSession.begin(); it != mSsrcToSession.end();) {
		if (it->second.mid.mid == mid) {
			clearSession(it->second.rtpSession);
			it = mSsrcToSession.erase(it);
		} else {
			++it;
		}
	}

	// Then check for sessions waiting for assignment.
	// mWaitingForAssignment is a multimap, we need to remove all RtpSessions pointed by the mid.
	if (const auto session = mWaitingForAssignment.find(mid); session != mWaitingForAssignment.end()) {
		// We have to remove the bundle from each RtpSession
		const auto [first, last] = mWaitingForAssignment.equal_range(mid);
		for (auto i = first; i != last; ++i) {
			clearSession(i->second);
		}

		mWaitingForAssignment.erase(mid);
	}

	// Finally remove the ssrcs associated.
	for (auto it = mSsrcToMid.begin(); it != mSsrcToMid.end();) {
		if (it->second == mid) {
			it = mSsrcToMid.erase(it);
		} else {
			++it;
		}
	}
}

void RtpBundleCxx::removeSession(RtpSession *session) {
	const std::lock_guard guard(mAssignmentMutex);

	// Remove the session from the main map.
	for (auto it = mSsrcToSession.begin(); it != mSsrcToSession.end();) {
		if (it->second.rtpSession == session) {
			clearSession(it->second.rtpSession);
			it = mSsrcToSession.erase(it);
		} else {
			++it;
		}
	}

	// Remove the session from the assignment map.
	for (auto it = mWaitingForAssignment.begin(); it != mWaitingForAssignment.end();) {
		if (it->second == session) {
			clearSession(it->second);
			it = mWaitingForAssignment.erase(it);
		} else {
			++it;
		}
	}
}

void RtpBundleCxx::clearSession(RtpSession *session) {
	rtp_session_set_bundle(session, nullptr);

	if (mPrimary != nullptr) {
		if (session == mPrimary) {
			mPrimary->is_primary = FALSE;
			mPrimary = nullptr;
		} else {
			// Remove the session from all of mPrimary's signal tables.
			for (const bctbx_list_t *it = mPrimary->signal_tables; it != nullptr; it = it->next) {
				const auto t = static_cast<RtpSignalTable *>(it->data);
				rtp_signal_table_remove_by_source_session(t, session);
			}
		}
	}
}

void RtpBundleCxx::clear() {
	for (const auto &entry : mSsrcToSession) {
		entry.second.rtpSession->bundle = nullptr;
	}
	mSsrcToSession.clear();

	for (const auto &entry : mWaitingForAssignment) {
		entry.second->bundle = nullptr;
	}
	mWaitingForAssignment.clear();

	mSsrcToMid.clear();
	mPrimary = nullptr;
}

void RtpBundleCxx::sessionModeUpdated(RtpSession *session, RtpSessionMode previousMode) {
	const RtpSessionMode newMode = session->mode;
	if (previousMode == newMode) return;

	const std::lock_guard guard(mAssignmentMutex);

	// We only have to do something if the session goes from SENDONLY to another mode or the opposite
	if ((previousMode == RTP_SESSION_RECVONLY || previousMode == RTP_SESSION_SENDRECV) &&
	    newMode == RTP_SESSION_SENDONLY) {
		Mid mid{};

		if (session->ssrc_set && session->rcv.ssrc != 0) {
			// Remove it from main map
			for (auto it = mSsrcToSession.begin(); it != mSsrcToSession.end(); ++it) {
				if (it->second.rtpSession == session) {
					mid = it->second.mid;
					mSsrcToSession.erase(it);
					break;
				}
			}
		} else {
			// Remove it from waiting map
			for (auto it = mWaitingForAssignment.begin(); it != mWaitingForAssignment.end(); ++it) {
				if (it->second == session) {
					mid.mid = it->first;
					mWaitingForAssignment.erase(it);
					break;
				}
			}
		}

		// Add it to main map with send ssrc
		mSsrcToSession.emplace(session->snd.ssrc, BundleSession{mid, session});

		ortp_message("RtpBundle[%p]: Session (%p) mode has been updated from %d to %d", this, session, previousMode,
		             newMode);
	} else if (previousMode == RTP_SESSION_SENDONLY &&
	           (newMode == RTP_SESSION_RECVONLY || newMode == RTP_SESSION_SENDRECV)) {
		if (const auto it = mSsrcToSession.find(session->snd.ssrc); it != mSsrcToSession.end()) {
			// Remove it from main map
			const auto mid = it->second.mid.mid;
			mSsrcToSession.erase(it);

			// Add it to waiting for assignment map
			mWaitingForAssignment.emplace(mid, session);

			ortp_message("RtpBundle[%p]: Session (%p) mode has been updated from %d to %d", this, session, previousMode,
			             newMode);
		}
	}
}

RtpSession *RtpBundleCxx::getPrimarySession() const {
	return mPrimary;
}

void RtpBundleCxx::setPrimarySession(RtpSession *session) {
	if (findSession(session)) {
		if (mPrimary) {
			mPrimary->is_primary = FALSE;
		}

		mPrimary = session;
		mPrimary->is_primary = TRUE;
	}
}

const std::string &RtpBundleCxx::getSessionMid(RtpSession *session) const {
	const auto inMainMap = std::find_if(
	    mSsrcToSession.begin(), mSsrcToSession.end(),
	    [session](const std::pair<uint32_t, BundleSession> &t) -> bool { return t.second.rtpSession == session; });

	if (inMainMap != mSsrcToSession.end()) {
		return inMainMap->second.mid.mid;
	}

	const auto inWaitingMap =
	    std::find_if(mWaitingForAssignment.begin(), mWaitingForAssignment.end(),
	                 [session](const std::pair<std::string, RtpSession *> &t) -> bool { return t.second == session; });

	if (inWaitingMap != mWaitingForAssignment.end()) {
		return inWaitingMap->first;
	}

	throw std::string("the session must be in the bundle!");
}

static void getSsrcFromSdes(void *userData,
                            uint32_t ssrc,
                            rtcp_sdes_type_t t,
                            BCTBX_UNUSED(const char *content),
                            BCTBX_UNUSED(uint8_t contentLen)) {
	const auto value = static_cast<uint32_t *>(userData);

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
				return *ssrc != 0;
			}
			break;
		case RTCP_RR:
			if (rtcp_common_header_get_rc(ch) != 1) return false;
			rb = rtcp_RR_get_report_block(m, 0);
			if (rb) {
				*ssrc = report_block_get_ssrc(rb);
				return *ssrc != 0;
			}
			break;
		case RTCP_APP:
		case RTCP_SDES:
			// No referred SSRC in a SDES or APP
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

			return *ssrc != 0;
		case RTCP_PSFB:
			*ssrc = rtcp_PSFB_get_media_source_ssrc(m);
			return *ssrc != 0;
		default:
			break;
	}

	return false;
}

void RtpBundleCxx::checkForSessionSdesCallback(
    void *userData, BCTBX_UNUSED(uint32_t ssrc), rtcp_sdes_type_t t, const char *content, uint8_t contentLen) {
	auto *bundle = static_cast<RtpBundleCxx *>(userData);

	if (t == RTCP_SDES_MID) {
		bundle->mSdesParseMid = std::string(content, contentLen);
	}
}

std::string RtpBundleCxx::getMid(const mblk_t *m, bool isRtp) {
	if (isRtp && rtp_get_extbit(m)) {
		uint8_t *data;
		if (const size_t midSize = rtp_get_extension_header(m, mMidId != -1 ? mMidId : RTP_EXTENSION_MID, &data);
		    midSize != static_cast<size_t>(-1)) {
			return {reinterpret_cast<char *>(data), midSize};
		}
	} else {
		if (rtcp_is_SDES(m)) {
			// The checkForSessionSdesCallback() checks for presence of mid.
			mSdesParseMid.clear();
			rtcp_sdes_parse(m, checkForSessionSdesCallback, this);

			return mSdesParseMid;
		}
	}

	return "";
}

RtpBundleCxx::BundleSession *RtpBundleCxx::findReferredSession(const uint32_t referredSsrc) {
	// Check if we have an entry associated to this ssrc, this should be the case if the ssrc is from a SEND_ONLY
	// session.
	if (const auto it = mSsrcToSession.find(referredSsrc); it != mSsrcToSession.end()) {
		return &it->second;
	}

	// Else check for a corresponding SENDRCV session with the send ssrc in the session map for this mid.
	for (auto &[ssrc, session] : mSsrcToSession) {
		if (session.rtpSession->mode == RTP_SESSION_SENDRECV && session.rtpSession->snd.ssrc == referredSsrc) {
			return &session;
		}
	}

	return nullptr;
}

void RtpBundleCxx::updateBundleSession(BundleSession &session, const std::string &mid, uint32_t sequenceNumber) {
	if (!mid.empty() && mid != session.mid.mid && sequenceNumber > session.mid.sequenceNumber) {
		session.mid.mid = mid;
		session.mid.sequenceNumber = sequenceNumber;
	}
}

RtpSession *RtpBundleCxx::checkForSession(const mblk_t *m, bool isRtp, bool isOutgoing) {
	const std::lock_guard guard(mAssignmentMutex);

	// STUN packet, return the primary session.
	if (isRtp && rtp_get_version(m) != 2) {
		return mPrimary;
	}

	const uint32_t ssrc = getSsrcFromMessage(m, isRtp);
	std::string mid = getMid(m, isRtp);

	// If we are in RTCP and have a referred ssrc, try to route it to the correct session first.
	if (uint32_t referredSsrc; !isRtp && getRTCPReferedSSRC(m, &referredSsrc)) {
		if (auto *session = findReferredSession(referredSsrc); session != nullptr) {
			const rtcp_common_header_t *ch = rtcp_get_common_header(m);
			ortp_message("RtpBundle[%p]: RTCP msg (%d) referring to SSRC %u with sender-ssrc %u "
			             "routed to session %p",
			             this, rtcp_common_header_get_packet_type(ch), referredSsrc, ssrc, session->rtpSession);

			updateBundleSession(*session, mid, rtp_get_seqnumber(m));
			return session->rtpSession;
		}
	}

	// Try to route the packet to the correct session.
	if (const auto it = mSsrcToSession.find(ssrc); it != mSsrcToSession.end()) {
		updateBundleSession(it->second, mid, rtp_get_seqnumber(m));
		return it->second.rtpSession;
	}

	// Retrieve or update the MID from the association map.
	if (const auto it = mSsrcToMid.find(ssrc); mid.empty()) {
		// If there is no mid in the packet, check if we have it stored for this ssrc.
		if (it == mSsrcToMid.end()) {
			ortp_warning("RtpBundle[%p]: Packet with SSRC %u doesn't have any mid and no corresponding mid in bundle",
			             this, ssrc);
			return nullptr;
		}

		mid = it->second;
	} else if (it == mSsrcToMid.end()) {
		// We have a mid in the packet, but not in the map. Insert it.
		mSsrcToMid[ssrc] = mid;
	}

	// If we are in RTP and not outgoing, check if we have a corresponding mid in the assignment map.
	if (isRtp && !isOutgoing) {
		const auto [first, last] = mWaitingForAssignment.equal_range(mid);

		for (auto s = first; s != last; ++s) {
			RtpSession *session = s->second;

			// Check if this blank session knows the payload type of the incoming packet.
			const RtpProfile *profile = rtp_session_get_recv_profile(session);
			if (rtp_profile_get_payload(profile, rtp_get_payload_type(m)) != nullptr) {
				ortp_message("RtpBundle[%p]: Assigning incoming SSRC %u to session %p using RTP with pt %d", this, ssrc,
				             session, rtp_get_payload_type(m));

				session->ssrc_set = TRUE;
				session->rcv.ssrc = ssrc;

				// Assign the session to the incoming ssrc and remove this session from the assignment map.
				mSsrcToSession.emplace(ssrc, BundleSession{{mid, 0}, session});
				mWaitingForAssignment.erase(s);

				return session;
			}
		}
	}

	// We have no existing RtpSession for this SSRC.
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
				// The new session is associated to the incoming SSRC.
				newRtpSession->ssrc_set = TRUE;
				newRtpSession->rcv.ssrc = ssrc;
			}
		}

		if (newRtpSession) {
			if (newRtpSession->bundle == nullptr) {
				// We do not use addSession as we already know it's ssrc
				mSsrcToSession.emplace(isOutgoing ? newRtpSession->snd.ssrc : newRtpSession->rcv.ssrc,
				                       BundleSession{{mid, 0}, newRtpSession});
				rtp_session_set_bundle(newRtpSession, reinterpret_cast<RtpBundle *>(this));
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
	if (session == nullptr) {
		freemsg(m);
		return true;
	}

	if (session != mPrimary) {
		ortp_mutex_lock(&session->rtp.gs.bundleq_lock);
		putq(&session->rtp.gs.bundleq, m);
		ortp_mutex_unlock(&session->rtp.gs.bundleq_lock);
		return true;
	}

	return false;
}

bool RtpBundleCxx::dispatchRtcpMessage(mblk_t *m) {
	mblk_t *mPrimarymsg = nullptr;

	// Check if the packet contains a SDES first
	RtcpParserContext rtcp_parser_ctx;
	const mblk_t *m_rtcp = rtcp_parser_context_init(&rtcp_parser_ctx, m);
	do {
		if (rtcp_is_SDES(m_rtcp)) {
			// call checkForSession that will update the mid table
			checkForSession(m_rtcp, false);
		}
	} while ((m_rtcp = rtcp_parser_context_next_packet(&rtcp_parser_ctx)) != nullptr);

	// Now go through the compound RTCP packet and dispatch each of its elements in streams.
	// In order to avoid unnecessary split between SR and SDES of a same compound packet,
	// each RTCP element belonging to same stream are aggregated.
	m_rtcp = rtcp_parser_context_start(&rtcp_parser_ctx);
	std::map<RtpSession *, mblk_t *> dispatchMap;
	do {
		mblk_t *tmp = dupmsg(const_cast<mblk_t *>(m_rtcp)); // const qualifier discarded intentionally.
		tmp->b_wptr = tmp->b_rptr + rtcp_get_size(m_rtcp);

		// some RTCP packet can be for multiple streams (e.g. BYE)
		if (RtpSession *session = checkForSession(tmp, false)) {
			auto &pendingMsg = dispatchMap[session];
			if (pendingMsg == nullptr) pendingMsg = tmp;
			else concatb(pendingMsg, tmp);
		} else {
			const rtcp_common_header_t *ch = rtcp_get_common_header(tmp);
			ortp_warning("RtpBundle[%p]: Rctp msg (%d) ssrc=%u does not correspond to any sessions", this,
			             rtcp_common_header_get_packet_type(ch), getSsrcFromMessage(tmp, false));
			freemsg(tmp);
		}
	} while ((m_rtcp = rtcp_parser_context_next_packet(&rtcp_parser_ctx)) != nullptr);

	rtcp_parser_context_uninit(&rtcp_parser_ctx);

	for (auto &[fst, snd] : dispatchMap) {
		if (fst == mPrimary) {
			mPrimarymsg = snd;
		} else {
			RtpSession *session = fst;
			ortp_mutex_lock(&session->rtcp.gs.bundleq_lock);
			msgpullup(snd, static_cast<size_t>(-1));
			putq(&session->rtcp.gs.bundleq, snd);
			ortp_mutex_unlock(&session->rtcp.gs.bundleq_lock);
		}
	}

	if (mPrimarymsg) {
		msgpullup(mPrimarymsg, static_cast<size_t>(-1));
		msgpullup(m, static_cast<size_t>(-1));

		// FIXME: not so elegant to copy back to the original mblk_t.
		const size_t len = mPrimarymsg->b_wptr - mPrimarymsg->b_rptr;
		memcpy(m->b_rptr, mPrimarymsg->b_rptr, len);
		m->b_wptr = m->b_rptr + len;

		freemsg(mPrimarymsg);
		return false;
	}

	freemsg(m);
	return true;
}
