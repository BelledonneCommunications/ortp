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

#include "fec-encoder.h"

using namespace ortp;

FecEncoder::FecEncoder(FecParamsController *params) {
	updateProtectionParam(params->getL(), params->getD(), params->is2D());
	mLoading = 0;
}

void FecEncoder::updateProtectionParam(uint8_t L, uint8_t D, bool is2D) {
	if (L == 0) {
		mIs2D = false;
		mL = 0;
		mD = 0;
		mRows = 0;
		mColumns = 0;
		mRowRepairNb = 0;
		mColRepairNb = 0;
		ortp_message("[flexfec] wrong parameters: L = 0, should be > 0. No repair packets sent.");
		return;
	}
	mIs2D = is2D;
	mL = L;
	mD = D;
	if (D == 0) {
		mIs2D = false;
	}

	if (mIs2D) {
		mRows = D;
		mColumns = L;
		mRowRepairNb = D;
		mColRepairNb = L;
	} else {
		if (D > 1) {
			mRows = D;
			mColumns = L;
			mRowRepairNb = 0;
			mColRepairNb = L;
		} else {
			mRows = 1;
			mColumns = L;
			mRowRepairNb = 1;
			mColRepairNb = 0;
		}
	}
}

void FecEncoder::init(struct _RtpSession *fecSession, struct _RtpSession *sourceSession) {
	this->mFecSession = fecSession;
	this->mSourceSession = sourceSession;
	initRowRepairPackets();
	initColRepairPackets();
	mLoading = 0;
}

void FecEncoder::update(uint8_t L, uint8_t D, bool is2D) {
	updateProtectionParam(L, D, is2D);
	clear();
	initRowRepairPackets();
	initColRepairPackets();
}

void FecEncoder::clear() {
	mRowRepair.clear();
	mColRepair.clear();
	mLoading = 0;
}

void FecEncoder::initRowRepairPackets() {
	uint16_t seqnum = 0U;
	int D = (mIs2D) ? 1 : 0;
	for (int i = 0; i < mRowRepairNb; i++) {
		auto repair = std::make_shared<FecRepairPacket>(mFecSession, mSourceSession, seqnum, mL, D);
		mRowRepair.emplace_back(repair);
		seqnum += mColumns;
	}
}

void FecEncoder::initColRepairPackets() {
	uint16_t seqnum = 0U;
	for (int i = 0; i < mColRepairNb; i++) {
		auto repair = std::make_shared<FecRepairPacket>(mFecSession, mSourceSession, seqnum, mL, mD);
		mColRepair.emplace_back(repair);
		seqnum++;
	}
}

void FecEncoder::reset(uint16_t nextSequenceNumber) {
	mLoading = 0;
	if (mRowRepairNb > 0) {
		resetRowRepairPackets(nextSequenceNumber);
	}
	if (mColRepairNb > 0) {
		resetColRepairPackets(nextSequenceNumber);
	}
}

void FecEncoder::resetRowRepairPackets(uint16_t seqnumBase) {
	uint16_t seqnum = seqnumBase;
	for (size_t i = 0; i < mRowRepair.size(); i++) {
		mRowRepair[i]->reset(seqnum);
		seqnum += mColumns;
	}
}

void FecEncoder::resetColRepairPackets(uint16_t seqnumBase) {
	uint16_t seqnum = seqnumBase;
	for (size_t i = 0; i < mColRepair.size(); i++) {
		mColRepair[i]->reset(seqnum);
		seqnum++;
	}
}

void FecEncoder::add(FecSourcePacket const &packet) {
	mLoading++;
	int i = getCurrentRow();
	int j = getCurrentColumn();
	if (mRowRepairNb > 0) {
		mRowRepair[i]->add(packet);
	}
	if (mColRepairNb > 0) {
		mColRepair[j]->add(packet);
	}
}

bool FecEncoder::isFull() const {
	return mLoading == mRows * mColumns && mLoading != 0;
}

bool FecEncoder::isEmpty() const {
	return mLoading == 0;
}

int FecEncoder::getCurrentRow() const {
	if (mD > 1) {
		return ((mLoading - 1) / mColumns);
	} else {
		return 0;
	}
}

int FecEncoder::getCurrentColumn() const {
	return ((mLoading - 1) % mColumns);
}

bool FecEncoder::isRowFull() const {
	if (mRowRepairNb == 0) return false;
	else return (getCurrentColumn() == (mColumns - 1));
}

bool FecEncoder::isColFull() const {
	if (mColRepairNb == 0) return false;
	return (getCurrentRow() == (mRows - 1));
}

std::shared_ptr<FecRepairPacket> FecEncoder::getRowRepair(int i) const {
	if (i < static_cast<int>(mRowRepair.size())) return mRowRepair[i];
	else return nullptr;
}

std::shared_ptr<FecRepairPacket> FecEncoder::getColRepair(int i) const {
	if (i < static_cast<int>(mColRepair.size())) return mColRepair[i];
	else return nullptr;
}

mblk_t *FecEncoder::getRowRepairMblk(int i) const {
	if (i < static_cast<int>(mRowRepair.size())) return mRowRepair[i]->getCopy();
	else return nullptr;
}

mblk_t *FecEncoder::getColRepairMblk(int i) const {
	if (i < static_cast<int>(mColRepair.size())) return mColRepair[i]->getCopy();
	else return nullptr;
}