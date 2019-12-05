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
 * You should have dispatchd a copy of the GNU General Public License
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
		auto & mid = ((RtpBundleCxx *)bundle)->getSessionMid(session);
		return mid.c_str();
	} catch (std::string const &e) {
		ortp_warning("Rtp Bundle [%p]: cannot get mid for session (%p), must be in the bundle!", bundle, session);
		return NULL;
	}
}

extern "C" int rtp_bundle_send_through_primary(RtpBundle *bundle, bool_t is_rtp, mblk_t *m, int flags,
											   const struct sockaddr *destaddr, socklen_t destlen) {
	return ((RtpBundleCxx *)bundle)->sendThroughPrimary(is_rtp, m, flags, destaddr, destlen);
}

extern "C" bool_t rtp_bundle_dispatch(RtpBundle *bundle, bool_t is_rtp, mblk_t *m, bool_t received_by_rtcp_mux) {
	return ((RtpBundleCxx *)bundle)->dispatch(is_rtp, m, received_by_rtcp_mux);
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
	sessions.emplace(mid, session);

	session->bundle = (RtpBundle *)this;
	qinit(&session->bundleq);
	ortp_mutex_init(&session->bundleq_lock, NULL);

	if (!primary) {
		primary = session;
		session->is_primary = TRUE;
	}
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
			if (it->second == mid) {
				ssrcToMid.erase(it++);
			} else {
				it++;
			}
		}
		ssrcToMidMutex.unlock();

		sessions.erase(mid);

		session->second->bundle = NULL;
		flushq(&session->second->bundleq, FLUSHALL);
		ortp_mutex_destroy(&session->second->bundleq_lock);
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
		flushq(&session->bundleq, FLUSHALL);
		ortp_mutex_destroy(&session->bundleq_lock);
	}

	primary = NULL;
	ssrcToMid.clear();
	sessions.clear();
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

	throw std::string("the session must be in the bundle!");
}

int RtpBundleCxx::sendThroughPrimary(bool isRtp, mblk_t *m, int flags, const struct sockaddr *destaddr,
									 socklen_t destlen) const {
	if (!primary)
		return -1;

	RtpTransport *primaryTransport;
	if (isRtp) {
		rtp_session_get_transports(primary, &primaryTransport, NULL);
	} else {
		rtp_session_get_transports(primary, NULL, &primaryTransport);
	}

	// This will bypass the modifiers of the primary transport
	return meta_rtp_transport_send_through_endpoint(primaryTransport, m, flags, destaddr, destlen);
}

bool RtpBundleCxx::updateMid(const std::string &mid, const uint32_t ssrc) {
	auto session = sessions.find(mid);
	if (session != sessions.end()) {
		ssrcToMid[ssrc] = mid;
		return true;
	}
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
		return ntohl(rtp_get_ssrc(m));
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
		return rtcp_RTPFB_get_media_source_ssrc(m);
	case RTCP_PSFB:
		return rtcp_PSFB_get_media_source_ssrc(m);
	case RTCP_XR:
		return rtcp_XR_get_ssrc(m);
	default:
		ortp_warning("Unknown RTCP packet type while retrieving it's SSRC");
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
		if (!bundle->updateMid(value, ssrc)) {
			ortp_warning("Rtp Bundle [%p]: SDES mid \"%s\" from msg does not "
						 "correspond to any sessions",
						 bundle, value.c_str());
		}

		bundle->sdesParseMid = value;
	}
}

RtpSession *RtpBundleCxx::checkForSession(mblk_t *m, bool isRtp) {
	const std::lock_guard<std::mutex> guard(ssrcToMidMutex);

	rtp_header_t *rtp = (rtp_header_t *)m->b_rptr;
	if (isRtp && rtp->version != 2) {
		/* STUN packet*/
		return primary;
	}

	std::string mid;
	uint32_t ssrc = getSsrcFromMessage(m, isRtp);

	auto it = ssrcToMid.find(ssrc);
	if (it == ssrcToMid.end()) {
		if (isRtp) {
			if (rtp_get_extbit(m)) {
				size_t midSize;
				uint8_t *data;

				midSize = rtp_get_extension_header(m, midId != -1 ? midId : RTP_EXTENSION_MID, &data);
				if (midSize != (size_t)-1) {
					mid = std::string((char *)data, midSize);

					// Update the mid map with the corresponding session
					if (!updateMid(mid, ssrc)) {
						ortp_warning("Rtp Bundle [%p]: mid \"%s\" from msg (%d) does not correspond to any sessions",
									 this, mid.c_str(), (int)rtp_get_seqnumber(m));
						return NULL;
					}
				} else {
					ortp_warning("Rtp Bundle [%p]: msg (%d) does not have a mid extension header", this,
								 (int)rtp_get_seqnumber(m));
					return NULL;
				}
			} else {
				ortp_warning("Rtp Bundle [%p]: msg (%d) does not have an extension header", this,
							 (int)rtp_get_seqnumber(m));
				return NULL;
			}
		} else {
			if (rtcp_is_SDES(m)) {
				rtcp_sdes_parse(m, checkForSessionSdesCallback, this);

				if (sdesParseMid.empty()) {
					return NULL;
				} else {
					mid = sdesParseMid;
					sdesParseMid = "";
				}
			}
			return NULL;
		}
	} else {
		mid = it->second;
	}

	auto session = sessions.at(mid);
	return session;
}

bool RtpBundleCxx::dispatch(bool isRtp, mblk_t *m, bool receivedByRtcpMux) {
	if (isRtp && !receivedByRtcpMux) {
		return dispatchRtpMessage(m);
	} else {
		return dispatchRtcpMessage(m);
	}
}

bool RtpBundleCxx::dispatchRtpMessage(mblk_t *m) {
	RtpSession *session = checkForSession(m, true);
	if (session == NULL)
		return true;

	if (session != primary) {
		ortp_mutex_lock(&session->bundleq_lock);
		putq(&session->bundleq, dupmsg(m));
		ortp_mutex_unlock(&session->bundleq_lock);

		return true;
	}

	return false;
}

bool RtpBundleCxx::dispatchRtcpMessage(mblk_t *m) {
	mblk_t *primarymsg = NULL;

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
			ortp_mutex_lock(&session->bundleq_lock);
			putq(&session->bundleq, tmp);
			ortp_mutex_unlock(&session->bundleq_lock);
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
		int len = primarymsg->b_wptr - primarymsg->b_rptr;
		memcpy(m->b_rptr, primarymsg->b_rptr, len);
		m->b_wptr = m->b_rptr + len;

		freemsg(primarymsg);

		return false;
	}

	return true;
}
