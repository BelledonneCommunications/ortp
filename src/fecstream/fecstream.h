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
#ifndef FECSTREAM_H
#define FECSTREAM_H

#include <iostream>
#include <map>
#include <memory>
#include <ortp/rtpsession.h>
#include <vector>

#include "fec-encoder.h"
#include "receive-cluster.h"

namespace ortp {

#ifdef _WIN32
// Disable C4251 triggered by need to export all stl template classes
#pragma warning(disable : 4251)
#endif // ifdef _WIN32

class ORTP_PUBLIC FecStreamCxx : public FecParamsSubscriber {

private:
	RtpSession *mSourceSession;
	RtpSession *mFecSession;
	FecEncoder mEncoder;
	ReceiveCluster mCluster;
	fec_stats mStats;
	RtpTransportModifier *mModifier;
	bool mIsEnabled;

public:
	FecStreamCxx(struct _RtpSession *source, struct _RtpSession *fec, FecParamsController *fecParams);
	void init();

	static int processOnSend(struct _RtpTransportModifier *m, mblk_t *packet);
	static int processOnReceive(struct _RtpTransportModifier *m, mblk_t *packet);
	void onNewSourcePacketSent(mblk_t *packet);
	void onNewSourcePacketReceived(mblk_t *packet);
	void receiveRepairPacket(uint32_t timestamp);
	mblk_t *findMissingPacket(uint16_t seqnum);
	RtpSession *getFecSession() const;
	RtpSession *getSourceSession() const;
	fec_stats *getStats();
	void printStats();
	void update(FecParamsController *) override;
	bool isEnabled();
	void disable();
	void enable(FecParamsController *params);
	~FecStreamCxx(){};
};

void modifierFree(struct _RtpTransportModifier *m);
} // namespace ortp
#endif
