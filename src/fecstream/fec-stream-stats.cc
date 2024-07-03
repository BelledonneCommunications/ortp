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

#include <algorithm>
#include <inttypes.h>

#include "fec-stream-stats.h"
#include "ortp/logging.h"

#define HEADER_1 '\x80'
#define HEADER_2 '\0'

using namespace ortp;

FecStreamStats::FecStreamStats() {
	memset(&mFecStats, 0, sizeof(fec_stats));
	mLocalHistoRecovering.resize(mBins);
	mLocalHistoLost.resize(mBins);
	mLocalHistoMissingGap.resize(mBins);
	mLocalHistoGapSize.resize(mBins);
	mGlobalHistoRecovering.resize(mBins);
	mGlobalHistoLost.resize(mBins);
	mGlobalHistoMissingGap.resize(mBins);
	mGlobalHistoGapSize.resize(mBins);
	std::fill(mLocalHistoRecovering.begin(), mLocalHistoRecovering.begin(), 0);
	std::fill(mLocalHistoLost.begin(), mLocalHistoLost.end(), 0);
	std::fill(mLocalHistoMissingGap.begin(), mLocalHistoMissingGap.end(), 0);
	std::fill(mLocalHistoGapSize.begin(), mLocalHistoGapSize.end(), 0);
	std::fill(mGlobalHistoRecovering.begin(), mGlobalHistoRecovering.end(), 0);
	std::fill(mGlobalHistoLost.begin(), mGlobalHistoLost.end(), 0);
	std::fill(mGlobalHistoMissingGap.begin(), mGlobalHistoMissingGap.end(), 0);
	std::fill(mGlobalHistoGapSize.begin(), mGlobalHistoGapSize.end(), 0);
}

void FecStreamStats::askedPacket(uint16_t seqNum) {
	if (mMissingPackets.find(seqNum) == mMissingPackets.end()) {
		mMissingPackets[seqNum] = 1;
	} else {
		mMissingPackets[seqNum]++;
	}

	if (mMissingPackets.size() > mMaxSize) {
		printHistoAndClear();
	}
}

void FecStreamStats::definitelyLostPacket(uint16_t seqNum, int16_t diff) {
	if (diff > 0) {
		mFecStats.packets_not_recovered += static_cast<uint64_t>(diff);
		mFecStats.packets_lost = mFecStats.packets_not_recovered + mFecStats.packets_recovered;
		for (uint16_t seqNumPrec = seqNum - (uint16_t)diff; seqNumPrec < seqNum; seqNumPrec++) {
			mLostPackets.emplace_back(seqNumPrec);
		}
	}
}

void FecStreamStats::repairedPacket(uint16_t seqNum) {
	mRepairedPackets.emplace_back(seqNum);
	mFecStats.packets_recovered++;
	mFecStats.packets_lost = mFecStats.packets_not_recovered + mFecStats.packets_recovered;
}

void FecStreamStats::printStats(RtpSession *sourceSession, RtpSession *fecSession) {
	double initialLossRate =
	    (sourceSession->stats.packet_recv == 0)
	        ? 0.
	        : static_cast<double>(mFecStats.packets_lost) / static_cast<double>(sourceSession->stats.packet_recv);
	double residualLossRate = (sourceSession->stats.packet_recv == 0)
	                              ? 0.
	                              : static_cast<double>(mFecStats.packets_lost - mFecStats.packets_recovered) /
	                                    static_cast<double>(sourceSession->stats.packet_recv);
	double recoveringRate = (mFecStats.packets_lost == 0) ? 0.
	                                                      : static_cast<double>(mFecStats.packets_recovered) /
	                                                            static_cast<double>(mFecStats.packets_lost);
	auto stats = rtp_session_get_stats(fecSession);
	double ratio_sent = (sourceSession->stats.sent == 0)
	                        ? 0.
	                        : static_cast<double>(stats->sent) / static_cast<double>(sourceSession->stats.sent);
	double ratio_recv = (sourceSession->stats.recv == 0)
	                        ? 0.
	                        : static_cast<double>(stats->recv) / static_cast<double>(sourceSession->stats.recv);

	ortp_log(ORTP_MESSAGE, "===========================================================");
	ortp_log(ORTP_MESSAGE, "               Forward Error Correction Stats              ");
	ortp_log(ORTP_MESSAGE, "-----------------------------------------------------------");
	ortp_log(ORTP_MESSAGE, "	row repair sent             	%10" PRId64 " packets", mFecStats.row_repair_sent);
	ortp_log(ORTP_MESSAGE, "	row repair received         	%10" PRId64 " packets", mFecStats.row_repair_received);
	ortp_log(ORTP_MESSAGE, "	col repair sent             	%10" PRId64 " packets", mFecStats.col_repair_sent);
	ortp_log(ORTP_MESSAGE, "	col repair received         	%10" PRId64 " packets", mFecStats.col_repair_received);
	ortp_log(ORTP_MESSAGE, "	packets lost                	%10" PRId64 " packets", mFecStats.packets_lost);
	ortp_log(ORTP_MESSAGE, "	packets recovered           	%10" PRId64 " packets", mFecStats.packets_recovered);
	ortp_log(ORTP_MESSAGE, "	initial loss rate           	%10.3f", initialLossRate);
	ortp_log(ORTP_MESSAGE, "	recovering rate             	%10.3f", recoveringRate);
	ortp_log(ORTP_MESSAGE, "	residual loss rate          	%10.3f", residualLossRate);
	ortp_log(ORTP_MESSAGE, "	ratio repair/source sizes sent  %10.3f", ratio_sent);
	ortp_log(ORTP_MESSAGE, "	ratio repair/source sizes recv  %10.3f", ratio_recv);
	ortp_log(ORTP_MESSAGE, "===========================================================");

	printGlobalHistoAndClear();
}

void FecStreamStats::clearAll() {
	printLostPacketsHisto();
	mLostPackets.clear();
	mRepairedPackets.clear();
	mMissingPackets.clear();
}

void FecStreamStats::printHistoAndClear() {
	printLostPacketsHisto();
	mLostPackets.clear();
	mRepairedPackets.clear();
}

std::string FecStreamStats::histoToString(std::vector<uint8_t> *histo) {
	std::string histoStr;
	for (auto it = histo->begin(); it != histo->end(); ++it) {
		histoStr += std::to_string(*it);
		histoStr += ",";
	}
	histoStr.pop_back();
	return histoStr;
}

void FecStreamStats::printGlobalHistoAndClear() {
	printLostPacketsHisto();
	ortp_message("[flexfec] global histogram of successful repair attempts: %s",
	             histoToString(&mGlobalHistoRecovering).c_str());
	ortp_message("[flexfec] global histogram of failed repair attempts: %s", histoToString(&mGlobalHistoLost).c_str());
	ortp_message("[flexfec] global histogram of gaps between missing packets: %s",
	             histoToString(&mGlobalHistoMissingGap).c_str());
	ortp_message("[flexfec] global histogram of number of consecutive packets loss: %s",
	             histoToString(&mGlobalHistoGapSize).c_str());
	mLostPackets.clear();
	mRepairedPackets.clear();
}

void FecStreamStats::printLostPacketsHisto() {

	std::vector<uint16_t> repairedPackets(mRepairedPackets.begin(), mRepairedPackets.end());
	std::vector<uint16_t> lostPackets(mLostPackets.begin(), mLostPackets.end());
	std::sort(repairedPackets.begin(), repairedPackets.end());
	std::sort(lostPackets.begin(), lostPackets.end());
	std::vector<uint16_t> mergedMissingPackets(repairedPackets.size() + lostPackets.size());
	std::merge(repairedPackets.begin(), repairedPackets.end(), lostPackets.begin(), lostPackets.end(),
	           mergedMissingPackets.begin());

	int count_missing = (int)mergedMissingPackets.size();
	int count_repaired = (int)repairedPackets.size();
	int count_lost = (int)lostPackets.size();
	float recovery_rate = (float)count_repaired / (float)count_missing;
	ortp_message("[flexfec] local stats: %d packets missing, %d repaired, %d lost (recovery rate: %f)", count_missing,
	             count_repaired, count_lost, recovery_rate);

	for (uint16_t seqNum : repairedPackets) {
		mLocalHistoRecovering.at(std::min(mBins - 1, mMissingPackets[seqNum]))++;
		mGlobalHistoRecovering.at(std::min(mBins - 1, mMissingPackets[seqNum]))++;
		mMissingPackets.erase(seqNum);
	}
	for (uint16_t seqNum : lostPackets) {
		if (mMissingPackets.find(seqNum) == mMissingPackets.end()) {
			mLocalHistoLost.at(0)++;
			mGlobalHistoLost.at(0)++;
		} else {
			mLocalHistoLost.at(std::min(mBins - 1, mMissingPackets[seqNum]))++;
			mGlobalHistoLost.at(std::min(mBins - 1, mMissingPackets[seqNum]))++;
			mMissingPackets.erase(seqNum);
		}
	}
	uint8_t lost_sequence_size = 1;
	for (size_t i = 0; i < mergedMissingPackets.size() - 1; i++) {
		uint16_t gap = mergedMissingPackets.at(i + 1) - mergedMissingPackets.at(i);
		mLocalHistoMissingGap[std::min(mBins - 1, (size_t)gap)]++;
		mGlobalHistoMissingGap[std::min(mBins - 1, (size_t)gap)]++;
		if (gap == 1) {
			lost_sequence_size++;
		} else {
			mLocalHistoGapSize.at(lost_sequence_size)++;
			mGlobalHistoGapSize.at(lost_sequence_size)++;
			lost_sequence_size = 1;
		}
	}

	ortp_message("[flexfec] local histogram of successful repair attempts: %s",
	             histoToString(&mLocalHistoRecovering).c_str());
	ortp_message("[flexfec] local histogram of failed repair attempts: %s", histoToString(&mLocalHistoLost).c_str());
	ortp_message("[flexfec] local histogram of gaps between missing packets: %s",
	             histoToString(&mLocalHistoMissingGap).c_str());
	ortp_message("[flexfec] local histogram of number of consecutive packets loss: %s",
	             histoToString(&mLocalHistoGapSize).c_str());

	std::fill(mLocalHistoRecovering.begin(), mLocalHistoRecovering.end(), 0);
	std::fill(mLocalHistoLost.begin(), mLocalHistoLost.end(), 0);
	std::fill(mLocalHistoMissingGap.begin(), mLocalHistoMissingGap.end(), 0);
	std::fill(mLocalHistoGapSize.begin(), mLocalHistoGapSize.end(), 0);
}