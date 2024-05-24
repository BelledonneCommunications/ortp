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

#include "receive-cluster.h"

using namespace ortp;

ReceiveCluster::ReceiveCluster(struct _RtpSession *session, uint32_t repairWindow) : mRepairWindow(repairWindow) {
	this->mSession = session;
	mRowRepairCpt = 0;
	mColRepairCpt = 0;
}

void ReceiveCluster::cleanSource() {
	uint32_t lastTimestamp = mSourceTimeStamp.rbegin()->first;
	uint32_t firstTimestamp = mSourceTimeStamp.begin()->first;
	if (!mSource.empty() && lastTimestamp - firstTimestamp >= mRepairWindow) {
		auto itLimit = mSourceTimeStamp.upper_bound(lastTimestamp - mRepairWindow);
		for (auto it = mSourceTimeStamp.begin(); it != itLimit; it++) {
			mSource.erase(it->second);
		}
		mSourceTimeStamp.erase(mSourceTimeStamp.begin(), itLimit);
	}
}

void ReceiveCluster::cleanRepair() {
	uint32_t lastTimestamp = mRepairTimeStamp.rbegin()->first;
	uint32_t firstTimestamp = mRepairTimeStamp.begin()->first;
	if (!mColRepairAll.empty() && lastTimestamp - firstTimestamp >= mRepairWindow) {
		auto itLimit = mRepairTimeStamp.upper_bound(lastTimestamp - mRepairWindow);
		for (auto it = mRepairTimeStamp.begin(); it != itLimit; it++) {
			if (mRowRepairAll.count(it->second) != 0) {
				mRowRepairAll.erase(it->second);
				mFecGraph.cleanRowRepair(it->second);
			}
			if (mColRepairAll.count(it->second) != 0) {
				mColRepairAll.erase(it->second);
				mFecGraph.cleanColRepair(it->second);
			}
		}
		mRepairTimeStamp.erase(mRepairTimeStamp.begin(), itLimit);
	}
}

void ReceiveCluster::add(mblk_t *mp) {
	uint16_t seqnum = rtp_get_seqnumber(mp);
	auto packet = std::make_shared<FecSourcePacket>(mp);
	mSourceTimeStamp.emplace(packet->getBitstring().getTimestamp(), seqnum);
	cleanSource();
	if (mSourceTimeStamp.count(packet->getBitstring().getTimestamp()) > 0) {
		mSource.emplace(seqnum, packet);
	}
}

void ReceiveCluster::add(const std::shared_ptr<FecRepairPacket> &packet) {
	const uint16_t seqnum = packet->getSeqnum();
	const auto seqnumList = packet->createSequenceNumberList();
	const uint32_t timestamp = rtp_get_timestamp(packet->getRepairPacket());
	mRepairTimeStamp.emplace(timestamp, seqnum);
	cleanRepair();
	if (packet->getD() > 1) {
		mColRepairCpt++;
		if (mRepairTimeStamp.count(timestamp) > 0) {
			mFecGraph.addColRepair(seqnum, seqnumList);
			mColRepairAll.emplace(seqnum, packet);
		}
	} else {
		mRowRepairCpt++;
		if (mRepairTimeStamp.count(timestamp) > 0) {
			mFecGraph.addRowRepair(seqnum, seqnumList);
			mRowRepairAll.emplace(seqnum, packet);
		}
	}
}

std::shared_ptr<FecSourcePacket> ReceiveCluster::getSourcePacket(uint16_t seqnum) const {
	auto it = mSource.find(seqnum);
	if (it != mSource.end()) return it->second;
	else return nullptr;
}

void ReceiveCluster::repair(uint16_t seqNum) {

	if (getSourcePacket(seqNum)) {
		ortp_debug("receive-cluster[%p] packet %d already repaired", this, seqNum);
		return;
	}

	std::set<uint16_t> seqNumBaseToRepairRow;
	std::set<uint16_t> seqNumBaseToRepairCol;
	mFecGraph.getRepairPacketsToRecoverSource(seqNum, seqNumBaseToRepairRow, seqNumBaseToRepairCol);
	mRowRepairForDecoding.clear();
	mColRepairForDecoding.clear();
	for (uint16_t seqNum : seqNumBaseToRepairRow) {
		if (mRowRepairAll.count(seqNum) != 0) {
			mRowRepairForDecoding.emplace_back(mRowRepairAll.at(seqNum));
		}
	}
	for (uint16_t seqNum : seqNumBaseToRepairCol) {
		if (mColRepairAll.count(seqNum) != 0) {
			mColRepairForDecoding.emplace_back(mColRepairAll.at(seqNum));
		}
	}

	repair2D();
	return;
}

void ReceiveCluster::repair2D() {
	int num_recovered_until_this_iteration = 0;
	int num_recovered_so_far = 0;

	do {
		num_recovered_so_far += repair1D(false);
		num_recovered_so_far += repair1D(true);

		if (num_recovered_so_far > num_recovered_until_this_iteration) {
			num_recovered_until_this_iteration = num_recovered_so_far;
		} else break;

	} while (1);
	return;
}

int ReceiveCluster::repair1D(bool interleaved) {
	auto repairPackets = (interleaved) ? mColRepairForDecoding : mRowRepairForDecoding;
	int repaired = 0;
	for (size_t i = 0; i < repairPackets.size(); i++) {
		repaired += repairOne(*repairPackets[i]);
	}
	return repaired;
}

int ReceiveCluster::repairOne(FecRepairPacket const &repairPacket) {
	std::vector<uint16_t> seqnumList;
	uint16_t seqnumToRepair = 0;

	int loss = 0;
	int i = 0;
	Bitstring recoveryBs;
	seqnumList = repairPacket.createSequenceNumberList();

	while (loss <= 1 && (unsigned long)i < seqnumList.size()) {

		std::shared_ptr<FecSourcePacket> source = getSourcePacket(seqnumList[i]);
		if (source == nullptr) {
			seqnumToRepair = seqnumList[i];
			loss++;
		} else {
			recoveryBs.add(source->getBitstring());
		}
		i++;
	}
	if (loss != 1) return 0;

	recoveryBs.add(repairPacket.extractBitstring());
	auto recovery = std::make_shared<FecSourcePacket>(mSession, recoveryBs);
	recovery->initPayload(recoveryBs.getLength());
	recovery->writeBitstring();
	recovery->setSequenceNumber(seqnumToRepair);
	recovery->setSsrc(repairPacket.getProtectedSsrc());

	for (int i = 0; (unsigned long)i < seqnumList.size(); i++) {
		if (seqnumList[i] == seqnumToRepair) continue;
		std::shared_ptr<FecSourcePacket> sourceP = getSourcePacket(seqnumList[i]);
		recovery->addPayload(*sourceP);
	}
	repairAddPacket(*recovery, repairPacket);
	mSource.emplace(seqnumToRepair, recovery);
	mSourceTimeStamp.emplace(recovery->getBitstring().getTimestamp(), seqnumToRepair);
	ortp_debug("receive-cluster[%p] source packet %u repaired", this, seqnumToRepair);

	return 1;
}

void ReceiveCluster::repairAddPacket(FecSourcePacket &source, FecRepairPacket const &repair) {
	uint8_t *rptr = NULL;
	size_t repairSize = repair.repairPayloadStart(&rptr);
	source.addPayload(rptr, repairSize);
}

void ReceiveCluster::reset() {
	ortp_message("receive-cluster[%p] reset packets", this);
	mSourceTimeStamp.clear();
	mRepairTimeStamp.clear();
	mSource.clear();
	mRowRepairAll.clear();
	mColRepairAll.clear();
	mRowRepairForDecoding.clear();
	mColRepairForDecoding.clear();
	mFecGraph.reset();
}