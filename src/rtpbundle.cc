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

#include "ortp/logging.h"
#include "ortp/rtpsession.h"
#include "rtpbundle.h"

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
extern "C" void rtp_bundle_add_fec_session(RtpBundle *bundle, const RtpSession *source_session, RtpSession *fec_session) {
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
		ortp_warning("Rtp Bundle [%p]: cannot get mid for session (%p): %s", bundle, session, e.c_str());
		return NULL;
	}
}

extern "C" bool_t rtp_bundle_dispatch(RtpBundle *bundle, bool_t is_rtp, mblk_t *m) {
	return ((RtpBundleCxx *)bundle)->dispatch(is_rtp, m);
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
		ortp_error("RtpBundle [%p]: Cannot add session (%p) has it is already in the bundle", this, session);
		return;
	}
	
	sessions.emplace(mid, session);

	session->bundle = (RtpBundle *)this;

	if (!primary) {
		primary = session;
		session->is_primary = TRUE;
	}
}
void  RtpBundleCxx::addFecSession(const RtpSession *sourceSession, RtpSession *fecSession){
	auto it =
		std::find_if(sessions.begin(), sessions.end(),
					 [sourceSession](const std::pair<std::string, RtpSession *> &t) -> bool { return t.second == sourceSession; });

	if (it == sessions.end()) {
		ortp_error("RtpBundle [%p]: Cannot add session (%p) because the associated source session isn't in the bundle", this, fecSession);
		return;
	}
	std::string mid = getSessionMid(it->second);
	fec_sessions.emplace(mid, fecSession);
	fecSession->bundle = (RtpBundle *)this;
	ortp_message("Fec session [%u] added to the bundle", rtp_session_get_send_ssrc(fecSession));
}

void RtpBundleCxx::removeSession(const std::string &mid) {
	auto session = sessions.find(mid);
	if (session != sessions.end()) {
		if (session->second == primary) {
			primary->is_primary = FALSE;
			primary = NULL;
		}

		ssrcToMidMutex.lock();
		for (auto it = ssrcToMid.begin(); it != ssrcToMid.end();) {
			if (it->second.mid == mid) {
				ssrcToMid.erase(it++);
			} else {
				it++;
			}
		}
		ssrcToMidMutex.unlock();

		if(session->second->fec_stream != NULL){
			auto fec_session = fec_sessions.find(mid);
			if(fec_session != fec_sessions.end()){
				fec_session->second->bundle = NULL;
				fec_sessions.erase(mid);
			}
		}
		session->second->bundle = NULL;
		sessions.erase(mid);
	}
}

void RtpBundleCxx::removeSession(RtpSession *session) {
	auto it =
		std::find_if(sessions.begin(), sessions.end(),
					 [session](const std::pair<std::string, RtpSession *> &t) -> bool { return t.second == session; });

	if (it != sessions.end()) {
		removeSession(it->first);
	}
}

void RtpBundleCxx::clear() {
	for (const auto &entry : sessions) {
		RtpSession *session = entry.second;
		session->bundle = NULL;
	}
	for(const auto &entry : fec_sessions){
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
	}
	else {//Could be a FEC session
		it = std::find_if(fec_sessions.begin(), fec_sessions.end(),
					 [session](const std::pair<std::string, RtpSession *> &t) -> bool { return t.second == session; });
		if (it != sessions.end()) {
			return it->first;
		}
	}

	throw std::string("the session must be in the bundle!");
}

bool RtpBundleCxx::updateMid(const std::string &mid, const uint32_t ssrc, const uint16_t sequenceNumber, bool isRtp) {
	auto session = sessions.find(mid);
	if (session != sessions.end()) {
		auto entry = ssrcToMid.find(ssrc);
		if (entry == ssrcToMid.end()) {
			Mid value = {mid, isRtp ? sequenceNumber : (uint16_t)0};
			ssrcToMid[ssrc] = value;
			ortp_message("Rtp Bundle [%p] SSRC [%u] paired with mid [%s]", this, ssrc, mid.c_str());
			return true;
		} else if ((*entry).second.mid != mid) {
			if (isRtp) {	
				ortp_message("Rtp Bundle [%p]: received a mid update via RTP.", this);
				if (entry->second.sequenceNumber < sequenceNumber) {
					Mid value = {mid, sequenceNumber};
					ssrcToMid[ssrc] = value;
				}
			} else {
				// We should normally update the mid but we chose not to for simplicity
				// since RTCP does not have a sequence number.
				// https://tools.ietf.org/html/draft-ietf-mmusic-sdp-bundle-negotiation-54#page-24
				ortp_warning("Rtp Bundle [%p]: received a mid update via RTCP, ignoring it.", this);
			}
		}
		return true;
	}
	/* The mid is totally unknown, this is an error. */
	return false;
}

static void getSsrcFromSdes(void *userData, uint32_t ssrc, rtcp_sdes_type_t t, const char *content,
							uint8_t contentLen) {
	uint32_t *value = (uint32_t *)userData;

	if (*value == 0 || t == RTCP_SDES_MID) {
		*value = ssrc;
	}
}

static uint32_t getSsrcFromMessage(mblk_t *m, bool isRtp) {
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

static void checkForSessionSdesCallback(void *userData, uint32_t ssrc, rtcp_sdes_type_t t, const char *content,
										uint8_t contentLen) {
	RtpBundleCxx *bundle = (RtpBundleCxx *)userData;
	std::string value(content, contentLen);

	if (t == RTCP_SDES_MID) {
		// Update the mid map with the corresponding session
		if (!bundle->updateMid(value, ssrc, UINT16_MAX, false)) {
			ortp_warning("Rtp Bundle [%p]: SSRC %u not found and SDES mid \"%s\" from msg does not "
						 "correspond to any sessions",
						 bundle, ssrc, value.c_str());
		}

		bundle->sdesParseMid = value;
	}
}

RtpSession *RtpBundleCxx::checkForSession(mblk_t *m, bool isRtp) {
	const std::lock_guard<std::mutex> guard(ssrcToMidMutex);
	uint32_t ssrc;

	if (isRtp && rtp_get_version(m)!= 2) {
		/* STUN packet*/
		return primary; 
	}

	ssrc = getSsrcFromMessage(m, isRtp);
	auto it = ssrcToMid.find(ssrc);

	if (isRtp) {
		if (rtp_get_extbit(m)) {
			size_t midSize;
			uint8_t *data;

			midSize = rtp_get_extension_header(m, midId != -1 ? midId : RTP_EXTENSION_MID, &data);
			if (midSize != (size_t)-1) {
				std::string mid = std::string((char *)data, midSize);

				// Update the mid map with the corresponding session
				if (!updateMid(mid, ssrc, rtp_get_seqnumber(m), true)) {
					if (it == ssrcToMid.end()) {
						ortp_warning("Rtp Bundle [%p]: SSRC %u not found and mid \"%s\" from msg (%d) does not "
									 "correspond to any sessions",
									 this, ssrc, mid.c_str(), (int)rtp_get_seqnumber(m));
						return NULL;
					}
				}
			} else {
				if (it == ssrcToMid.end()) {
					ortp_warning("Rtp Bundle [%p]: SSRC %u not found and msg (%d) does not have a mid extension header",
								 this, ssrc, (int)rtp_get_seqnumber(m));
					return NULL;
				}
			}
		} else {
			if (it == ssrcToMid.end()) {
				ortp_warning("Rtp Bundle [%p]: SSRC %u not found and msg (%d) does not have an extension header", this,
							 ssrc, (int)rtp_get_seqnumber(m));
				return NULL;
			}
		}
	} else {
		if (rtcp_is_SDES(m)) {
			rtcp_sdes_parse(m, checkForSessionSdesCallback, this);

			if (sdesParseMid.empty()) {
				if (it == ssrcToMid.end()) {
					return NULL;
				}
			} else {
				sdesParseMid = "";
			}
		} else {
			if (it == ssrcToMid.end()) {
				// Cannot look at mid in RTCP as it is not a SDES
				return NULL;
			}
		}
	}

	// Get the value again in case it has been updated
	it = ssrcToMid.find(ssrc);
	if (it == ssrcToMid.end()) {
		ortp_warning("Rtp Bundle [%p]: SSRC %u not found in map to convert it to mid", this, ssrc);
	} else {
		try {
			auto session = sessions.at(it->second.mid);
			if(session->fec_stream){
				RtpSession *fec_session = fec_stream_get_fec_session(session->fec_stream);
				if(rtp_session_get_recv_payload_type(fec_session) == rtp_get_payload_type(m)){
					return fec_session;
				}
			}
			return session;
		} catch (std::out_of_range&) {
			ortp_warning("Rtp Bundle [%p]: Unable to find session with mid %s (SSRC %u)", this, it->second.mid.c_str(), ssrc);
			return nullptr;
		}
	}
	return nullptr;
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

	// Check if the packet contains a SDES first
	do {
		if (rtcp_is_SDES(m)) {
			// call checkForSession that will update the mid table
			checkForSession(m, false);
		}
	} while (rtcp_next_packet(m));
	rtcp_rewind(m);

	do {
		mblk_t *tmp = dupmsg(m);
		tmp->b_rptr = m->b_rptr;
		tmp->b_wptr = tmp->b_rptr + rtcp_get_size(m);

		// TODO: some RTCP packet can be for multiple session (e.g. BYE)

		RtpSession *session = checkForSession(tmp, false);
		if (session == primary) {
			if (primarymsg) {
				concatb(primarymsg, tmp);
			} else {
				primarymsg = tmp;
			}
		} else if (session != NULL) {
			ortp_mutex_lock(&session->rtcp.gs.bundleq_lock);
			putq(&session->rtcp.gs.bundleq, tmp);
			ortp_mutex_unlock(&session->rtcp.gs.bundleq_lock);
		} else {
			const rtcp_common_header_t *ch = rtcp_get_common_header(tmp);
			ortp_warning("Rtp Bundle [%p]: Rctp msg (%d) ssrc=%u does not correspond to any sessions", this,
						 rtcp_common_header_get_packet_type(ch), getSsrcFromMessage(tmp, false));
			freemsg(tmp);
		}
	} while (rtcp_next_packet(m));
	rtcp_rewind(m);

	if (primarymsg) {
		msgpullup(primarymsg, (size_t)-1);

		// TODO: Fix when possible
		size_t len = primarymsg->b_wptr - primarymsg->b_rptr;
		memcpy(m->b_rptr, primarymsg->b_rptr, len);
		m->b_wptr = m->b_rptr + len;

		freemsg(primarymsg);

		return false;
	}

	freemsg(m);
	return true;
}
