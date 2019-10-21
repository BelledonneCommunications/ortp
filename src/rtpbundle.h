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

#ifndef RTPBUNDLE_H
#define RTPBUNDLE_H

#include <map>
#include <mutex>
#include <string>

#include "ortp/rtpsession.h"

/* Need to declare this function so the class can be friend with it */
static void checkForSessionSdesCallback(void *, uint32_t, rtcp_sdes_type_t, const char *, uint8_t);

class RtpBundleCxx {
	friend void checkForSessionSdesCallback(void *, uint32_t, rtcp_sdes_type_t, const char *, uint8_t);

  public:
	RtpBundleCxx() = default;
	~RtpBundleCxx();

	RtpBundleCxx(const RtpBundleCxx &) = delete;
	RtpBundleCxx(RtpBundleCxx &&) = delete;

	int getMidId() const;
	void setMidId(int id);

	void addSession(const std::string &mid, RtpSession *session);
	void removeSession(const std::string &mid);
	void removeSession(RtpSession *session);
	void clear();

	RtpSession *getPrimarySession() const;
	void setPrimarySession(const std::string &mid);

	const std::string &getSessionMid(RtpSession *session) const;

	int sendThroughPrimary(bool isRtp, mblk_t *m, int flags, const struct sockaddr *destaddr, socklen_t destlen) const;
	bool dispatch(bool isRtp, mblk_t *m, bool receivedByRtcpMux);

	bool updateMid(const std::string &mid, const uint32_t ssrc, const uint16_t sequenceNumber, bool isRtp);

  private:
	struct Mid {
		std::string mid;
		uint16_t sequenceNumber;
	};

	RtpSession *checkForSession(mblk_t *m, bool isRtp);

	bool dispatchRtpMessage(mblk_t *m);
	bool dispatchRtcpMessage(mblk_t *m);

	RtpSession *primary = NULL;
	std::map<uint32_t, Mid> ssrcToMid;
	std::map<std::string, RtpSession *> sessions;
	std::mutex ssrcToMidMutex;

	std::string sdesParseMid = "";
	int midId = -1;
};

#endif /* RTPBUNDLE_H */
