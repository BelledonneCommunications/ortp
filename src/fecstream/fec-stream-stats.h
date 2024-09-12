/*
 * Copyright (c) 2010-2024 Belledonne Communications SARL.
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

#ifndef FECSTREAMSTATS_H
#define FECSTREAMSTATS_H

#include "ortp/rtpsession.h"
#include <string>
#include <unordered_map>
#include <vector>

namespace ortp {

#ifdef _WIN32
// Disable C4251 triggered by need to export all stl template classes
#pragma warning(disable : 4251)
#endif // ifdef _WIN32

class FecStreamStats {
private:
	std::vector<uint16_t> mLostPackets;                   // sequence numbers of the lost packets
	                                                      // that are not found when the jitter buffer is read
	std::vector<uint16_t> mRepairedPackets;               // sequence numbers of the packets repaired by FEC
	std::unordered_map<uint16_t, size_t> mMissingPackets; // number of repair attempts of each packet
	                                                      // given its sequence number
	fec_stats mFecStats;
	const size_t mMaxSize = 100;
	const size_t mBins = 31;

	// histograms, bins from 0 to mBins - 1
	std::vector<uint8_t> mLocalHistoRecovering; // number of attemps before a successful repair
	std::vector<uint8_t> mLocalHistoLost;       // number of repair attemps of definitely lost packets
	std::vector<uint8_t> mLocalHistoMissingGap; // number of packets between two lost packets
	std::vector<uint8_t> mLocalHistoGapSize;    // number of consecutive lost packets
	std::vector<uint8_t> mGlobalHistoRecovering;
	std::vector<uint8_t> mGlobalHistoLost;
	std::vector<uint8_t> mGlobalHistoMissingGap;
	std::vector<uint8_t> mGlobalHistoGapSize;

	void printHistoAndClear();
	void printGlobalHistoAndClear();
	void printLostPacketsHisto();
	std::string histoToString(const std::vector<uint8_t> &histo) const;

public:
	FecStreamStats();
	~FecStreamStats(){};
	void rowRepairSent() {
		mFecStats.row_repair_sent++;
	};
	void colRepairSent() {
		mFecStats.col_repair_sent++;
	};
	void rowRepairReceived(uint64_t cpt) {
		mFecStats.row_repair_received = cpt;
	};
	void colRepairReceived(uint64_t cpt) {
		mFecStats.col_repair_received = cpt;
	};
	uint64_t getPacketsLost() const {
		return mFecStats.packets_lost;
	};
	uint64_t getPacketsRecovered() const {
		return mFecStats.packets_recovered;
	};
	uint64_t getPacketsNotRecovered() const {
		return mFecStats.packets_not_recovered;
	};
	fec_stats *getFecStats() {
		return &mFecStats;
	};
	void askedPacket(uint16_t seqNum);
	void repairedPacket(uint16_t seqNum);
	void definitelyLostPacket(uint16_t newSeqNumReceived, int16_t diff);
	void printStats(RtpSession *sourceSession, RtpSession *fecSession);
	void clearAll();
};

} // namespace ortp
#endif