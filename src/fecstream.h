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

namespace ortp {

#ifdef _WIN32
	// Disable C4251 triggered by need to export all stl template classes
	#pragma warning(disable: 4251)
#endif // ifdef _WIN32

class ORTP_PUBLIC Bitstring {

  private:
	uint8_t mBuffer[8];

  public:
	Bitstring();
	Bitstring(const mblk_t *packet);
	void add(Bitstring const &other);
	void reset();
	void write(mblk_t *packet);
	uint16_t getHeader() const {
		return *(uint16_t *) &mBuffer[0];
	};
	uint32_t getTimestamp() const {
		return *(uint32_t *) &mBuffer[2];
	};
	uint16_t getLength() const {
		return	*(uint16_t *)&mBuffer[6];
	};	
	void setHeader(uint16_t *h) {
		*(uint16_t *)&mBuffer[0] = *(uint16_t *)h;
	};
	void setLength(uint16_t l) {
		*(uint16_t *) &mBuffer[6] = (uint16_t) l;
	};
	void setTimestamp(uint32_t t) {
		*(uint32_t *) &mBuffer[2] = t;
	};
	bool equals(Bitstring const &other) {
		return (memcmp(&mBuffer[0], &other.mBuffer[0], 8) == 0);
	}
	~Bitstring(){};
};

class ORTP_PUBLIC FecSourcePacket {

  private:
	mblk_t *mPacket;
	Bitstring mBitstring;

  public:
	FecSourcePacket(struct _RtpSession *session, const Bitstring &bs);
	FecSourcePacket(struct _RtpSession *session);
	FecSourcePacket(const mblk_t *incoming);
	FecSourcePacket(const FecSourcePacket &other) = delete;
	FecSourcePacket &operator=(const FecSourcePacket &other) = delete;
	void addBitstring(Bitstring const &other);

	void add(FecSourcePacket const &other);

	void writeBitstring();
	size_t getPayloadBuffer(uint8_t **start) const;
	void addPayload(FecSourcePacket const &other);
	void addPayload(const uint8_t *toAdd, size_t size);
	void initPayload(uint16_t length);
	mblk_t *getPacket() const {
		return mPacket;
	}
	mblk_t *getPacketCopy() const {
		return copymsg(mPacket);
	}
	const Bitstring &getBitstring() const {
		return mBitstring;
	}
	mblk_t *transfer();
	void setSsrc(uint32_t ssrc){
		rtp_set_ssrc(mPacket,ssrc);
	};
	void setSequenceNumber(uint16_t seqnum){
		rtp_set_seqnumber(mPacket, seqnum);
	};
	~FecSourcePacket() {
		if (mPacket) {
			freemsg(mPacket);
		}
	}
};

class ORTP_PUBLIC FecRepairPacket {
  private:
	mblk_t *mPacket;
	uint8_t mL;
	uint8_t mD;
	uint16_t mSeqnumBase;

  public:
	FecRepairPacket();
	FecRepairPacket(const mblk_t *repairPacket);
	FecRepairPacket(const FecRepairPacket &other) = delete;
	FecRepairPacket &operator=(const FecRepairPacket &other) = delete;

	FecRepairPacket(struct _RtpSession *fecSession, struct _RtpSession *sourceSession, uint16_t seqnumBase, uint8_t L, uint8_t D);
	void addBitstring(Bitstring const &bitstring);
	size_t bitstringStart(uint8_t **start) const;
	Bitstring extractBitstring() const;
	size_t parametersStart(uint8_t **start) const;

	size_t repairPayloadStart(uint8_t **start) const;
	uint32_t getProtectedSsrc() const {
		return rtp_get_csrc(mPacket, 0);
	}
	void addPayload(FecSourcePacket const &sourcePacket);
	void add(FecSourcePacket const &sourcePacket);

	void reset(uint16_t seqnumBase);
	std::vector<uint16_t> createSequenceNumberList() const;

	uint8_t getL() const {
		return mL;
	};
	uint8_t getD() const {
		return mD;
	};
	uint16_t getSeqnumBase() const {
		return mSeqnumBase;
	};
	mblk_t *transfer() {
		if (mPacket) {
			mblk_t *ret = mPacket;
			mPacket = nullptr;
			return ret;
		}
		return nullptr;
	}
	mblk_t *getRepairPacket() const {
		return mPacket;
	};
	mblk_t *getCopy() {
		if (mPacket)
			return copymsg(mPacket);
		return nullptr;
	}
	~FecRepairPacket() {
		if (mPacket) {
			freemsg(mPacket);
		}
	};
};

class ORTP_PUBLIC FecEncoder {

  private:
	std::vector<std::shared_ptr<FecRepairPacket>> mRowRepair;
	std::vector<std::shared_ptr<FecRepairPacket>> mColRepair;
	RtpSession *mFecSession;
	RtpSession *mSourceSession;
	int mLoading;
	int mColumns;
	int mRows;
	int mSize;
	bool mIs2D;
	void initRowRepairPackets(uint16_t seqnumBase);
	void resetRowRepairPackets(uint16_t seqnumBase);
	void initColRepairPackets(uint16_t seqnumBase);
	void resetColRepairPackets(uint16_t seqnumBase);

  public:


	FecEncoder(){};
	FecEncoder(FecParameters *parameters);
	void init(struct _RtpSession *fecSession, struct _RtpSession *sourceSession);
	void add(FecSourcePacket const &packet);
	bool isFull() const {
		return mLoading == mSize;
	};
	void reset(uint16_t nextSequenceNumber);
	int getCurrentColumn() const {
		return ((mLoading - 1) % mColumns);
	};
	bool isColFull() const {
		return (getCurrentRow() == (mRows - 1));
	};
	int getCurrentRow() const {
		return (mIs2D) ? ((mLoading - 1) / mColumns) : 0;
	};
	bool isRowFull() const {
		return (getCurrentColumn() == (mColumns - 1));
	};
	int getRows() const {
		return mRows;
	};
	int getColumns() const {
		return mColumns;
	};
	int getSize() const {
		return mSize;
	};

	const std::vector<std::shared_ptr<FecRepairPacket>> &getRowRepair() {
		return mRowRepair;
	};
	mblk_t *getRowRepairMblk(int i);
	std::shared_ptr<FecRepairPacket> getRowRepair(int i) {
		return mRowRepair[i];
	};
	std::shared_ptr<FecRepairPacket> getColRepair(int i) {
		return mColRepair[i];
	};
	const std::vector<std::shared_ptr<FecRepairPacket>> &getColRepair() {
		return mColRepair;
	};
	mblk_t *getColRepairMblk(int i);
};

class ORTP_PUBLIC RecieveCluster {

  private:

	uint32_t mRepairWindow = 200000;
	RtpSession *mSession;
	RtpTransportModifier * mModifier;
	std::map<uint16_t, std::shared_ptr<FecSourcePacket>> mSource;
	std::vector<std::shared_ptr<FecRepairPacket>> mRowRepair;
	std::vector<std::shared_ptr<FecRepairPacket>> mColRepair;
	void addRepair(FecSourcePacket &source, FecRepairPacket const &repair);
	
  public:


	RecieveCluster(struct _RtpSession *session) {
		this->mSession = session;
	};
	RecieveCluster(struct _RtpSession *session, int repair) {
		mRepairWindow = repair;
		this->mSession = session;
	};
	std::shared_ptr<FecSourcePacket> getSourcePacket(uint16_t seqnum);
	void add(uint16_t seqnum, const std::shared_ptr<FecSourcePacket> &packet);
	void add(const std::shared_ptr<FecRepairPacket> &packet);
	bool isFull() const;
	bool repairPacketsTooOld(FecParameters const &parameters);
	void clearRepairPackets();
	std::map<uint16_t, std::shared_ptr<FecSourcePacket>> const &getSource();
	int repairOne(FecRepairPacket const &repairPacket);
	int repair1D(bool interleaved);
	int repair2D();
	void setModifier(struct _RtpTransportModifier * modifier){
		this->mModifier = modifier;
	};
	uint32_t getRepairWindow() {
		return mRepairWindow;
	};
	void print();
	~RecieveCluster(){};
};

class ORTP_PUBLIC FecStreamCxx {

  private:
	FecParameters *parameters;
	RtpSession *mSourceSession;
	RtpSession *mFecSession;
	FecEncoder mEncoder;
	RecieveCluster mCluster;
	fec_stats mStats;
	RtpTransportModifier *mModifier;

  public:
	FecStreamCxx(struct _RtpSession *source, struct _RtpSession *fec, FecParameters *fecParams);
	void init();
	static int processOnSend(struct _RtpTransportModifier *m,mblk_t *packet);
	static int processOnRecieve(struct _RtpTransportModifier *m,mblk_t *packet);
	void onNewSourcePacketSent(mblk_t *packet);
	void onNewSourcePacketRecieved(mblk_t *packet);
	void recieveRepairPacket(uint32_t timestamp);
	mblk_t *findMissingPacket(uint16_t seqnum);
	RtpSession *getFecSession() const{
		return mFecSession;
	};
	RtpSession *getSourceSession() const{
		return mSourceSession;
	};
	fec_stats *getStats() {
		return &mStats;
	};
	void printStats();
	~FecStreamCxx(){};
};


void modifierFree(struct _RtpTransportModifier *m);
} // namespace ortp
#endif
