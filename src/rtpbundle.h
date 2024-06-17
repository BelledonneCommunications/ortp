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

#ifndef RTPBUNDLE_H
#define RTPBUNDLE_H

#include <map>
#include <mutex>
#include <string>

#include "ortp/rtpsession.h"

class RtpBundleCxx {

public:
	RtpBundleCxx() = default;
	~RtpBundleCxx();

	RtpBundleCxx(const RtpBundleCxx &) = delete;
	RtpBundleCxx(RtpBundleCxx &&) = delete;

	int getMidId() const;
	void setMidId(int id);
	void addSession(const std::string &mid, RtpSession *session);
	bool findSession(RtpSession *session) const;
	bool findMid(const std::string &mid) const;
	void removeSessions(const std::string &mid);
	void removeSession(RtpSession *session);
	void clear();

	void sessionModeUpdated(RtpSession *session, RtpSessionMode previousMode);

	RtpSession *getPrimarySession() const;
	void setPrimarySession(RtpSession *session);

	const std::string &getSessionMid(RtpSession *session) const;

	// Dispatch an incoming packet to one of the bundled secondary session.
	// Returns true if dispatched, false is the packet belongs to the primary session where it was received.
	bool dispatch(bool isRtp, mblk_t *m);

	RtpSession *checkForSession(const mblk_t *m, bool isRtp, bool isOutgoing = false);

private:
	struct Mid {
		std::string mid;
		uint32_t sequenceNumber;
	};

	struct BundleSession {
		Mid mid;
		RtpSession *rtpSession = nullptr;
	};

	static void checkForSessionSdesCallback(void *, uint32_t, rtcp_sdes_type_t, const char *, uint8_t);
	std::string getMid(const mblk_t *m, bool isRtp);

	BundleSession *findReferredSession(const uint32_t referredSsrc);

	static void updateBundleSession(BundleSession &session, const std::string &mid, uint32_t sequenceNumber);

	bool dispatchRtpMessage(mblk_t *m);
	bool dispatchRtcpMessage(mblk_t *m);

	void clearSession(RtpSession *session);

	RtpSession *mPrimary = nullptr;

	// Used to remember MID from incoming packets, as not all packets contains a MID.
	// This only serves in cases where we are receiving packets for a session that has not been yet added to the bundle
	// or being assigned.
	std::map<uint32_t, std::string> mSsrcToMid;

	// Main map of the bundle, we can directly assign a session to a ssrc (incoming or outgoing) which will speed up the
	// transfer to the correct destination.
	std::map<uint32_t, BundleSession> mSsrcToSession;

	// RCVONLY and SENDRCV sessions do not know their reception's SSRC before receiving any packet. So they are inserted
	// into this map. When we receive a packet, we will retrieve all sessions that have the corresponding MID and the
	// correct session will be removed from this map and added to the mSsrcToSession for direct access.
	std::multimap<std::string, RtpSession *> mWaitingForAssignment;

	std::mutex mAssignmentMutex;

	std::string mSdesParseMid;
	int mMidId = -1;
};

#endif /* RTPBUNDLE_H */
