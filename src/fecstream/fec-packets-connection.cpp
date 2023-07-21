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

#include "fec-packets-connection.h"

using namespace ortp;

FecSourceNode::FecSourceNode(const uint16_t seqNum) : mSeqNum(seqNum) {
}

void FecSourceNode::addRowRepair(const uint16_t seqNum) {
	mRowRepairSeqNum.insert(seqNum);
}

void FecSourceNode::addColRepair(const uint16_t seqNum) {
	mColRepairSeqNum.insert(seqNum);
}

bool FecSourceNode::removeRowRepair(const uint16_t repairSeqNum) {
	mRowRepairSeqNum.erase(repairSeqNum);
	return mRowRepairSeqNum.size() == 0 && mColRepairSeqNum.size() == 0;
}

bool FecSourceNode::removeColRepair(const uint16_t repairSeqNum) {
	mColRepairSeqNum.erase(repairSeqNum);
	return mRowRepairSeqNum.size() == 0 && mColRepairSeqNum.size() == 0;
}

FecRepairNode::FecRepairNode(const std::vector<uint16_t> sequenceNumberProtected)
    : mSourceSeqNum(sequenceNumberProtected.begin(), sequenceNumberProtected.end()) {
}

FecPacketsConnection::FecPacketsConnection() {
}

void FecPacketsConnection::addRowRepair(const uint16_t repairSeqNum,
                                        const std::vector<uint16_t> sequenceNumberProtected) {
	mRowRepairNodes.emplace(repairSeqNum, FecRepairNode(sequenceNumberProtected));
	for (uint16_t seqNum : sequenceNumberProtected) {
		if (mSourceNodes.count(seqNum) == 0) {
			mSourceNodes.emplace(seqNum, FecSourceNode(seqNum));
		}
		mSourceNodes.at(seqNum).addRowRepair(repairSeqNum);
	}
}

void FecPacketsConnection::addColRepair(const uint16_t repairSeqNum,
                                        const std::vector<uint16_t> sequenceNumberProtected) {
	mColRepairNodes.emplace(repairSeqNum, FecRepairNode(sequenceNumberProtected));
	for (uint16_t seqNum : sequenceNumberProtected) {
		if (mSourceNodes.count(seqNum) == 0) {
			mSourceNodes.emplace(seqNum, FecSourceNode(seqNum));
		}
		mSourceNodes.at(seqNum).addColRepair(repairSeqNum);
	}
}

void FecPacketsConnection::getRepairPacketsToRecoverSource(const uint16_t seqNum,
                                                           std::set<uint16_t> &rowRepairPackets,
                                                           std::set<uint16_t> &colRepairPackets) const {

	rowRepairPackets.clear();
	colRepairPackets.clear();
	if (mSourceNodes.count(seqNum) == 0) {
		return;
	}

	std::set<uint16_t> exploredSources = {};
	std::set<uint16_t> addedSources = {seqNum};
	std::set<uint16_t> addedRowRepair = {};
	std::set<uint16_t> addedColRepair = {};
	for (int it = 0; it < 10; it++) {

		addedRowRepair.clear();
		addedColRepair.clear();
		for (const uint16_t protectedSource : addedSources) {
			if (mSourceNodes.count(protectedSource) == 1) {
				for (const uint16_t newRepair : mSourceNodes.at(protectedSource).getRowRepair()) {
					if (rowRepairPackets.count(newRepair) == 0) {
						addedRowRepair.insert(newRepair);
					}
				}
				for (const uint16_t newRepair : mSourceNodes.at(protectedSource).getColRepair()) {
					if (colRepairPackets.count(newRepair) == 0) {
						addedColRepair.insert(newRepair);
					}
				}
			}
		}
		for (const uint16_t newSource : addedSources) {
			exploredSources.insert(newSource);
		}
		addedSources.clear();
		for (const uint16_t newRepair : addedRowRepair) {
			for (const uint16_t newSource : mRowRepairNodes.at(newRepair).getProtectedSources()) {
				if (exploredSources.count(newSource) == 0 && mSourceNodes.count(newSource) == 1) {
					addedSources.insert(newSource);
				}
			}
			rowRepairPackets.insert(newRepair);
		}
		for (const uint16_t newRepair : addedColRepair) {
			for (const uint16_t newSource : mColRepairNodes.at(newRepair).getProtectedSources()) {
				if (exploredSources.count(newSource) == 0 && mSourceNodes.count(newSource) == 1) {
					addedSources.insert(newSource);
				}
			}
			colRepairPackets.insert(newRepair);
		}

		if (addedSources.size() == 0) {
			break;
		}
	}
}

void FecPacketsConnection::cleanRowRepair(const uint16_t seqNum) {
	if (mRowRepairNodes.count(seqNum) == 0) {
		return;
	}

	for (auto source : mRowRepairNodes.at(seqNum).getProtectedSources()) {
		if (mSourceNodes.at(source).removeRowRepair(seqNum)) {
			mSourceNodes.erase(source);
		}
	}
	mRowRepairNodes.erase(seqNum);
}

void FecPacketsConnection::cleanColRepair(const uint16_t seqNum) {
	if (mColRepairNodes.count(seqNum) == 0) {
		return;
	}

	for (auto source : mColRepairNodes.at(seqNum).getProtectedSources()) {
		if (mSourceNodes.at(source).removeColRepair(seqNum)) {
			mSourceNodes.erase(source);
		}
	}
	mColRepairNodes.erase(seqNum);
}

void FecPacketsConnection::reset() {
	mSourceNodes.clear();
	mRowRepairNodes.clear();
	mColRepairNodes.clear();
}