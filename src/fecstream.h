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
	mblk_t *packet;
	Bitstring bitstring;

  public:
	FecSourcePacket(struct _RtpSession *session, const Bitstring &bs);
	FecSourcePacket(struct _RtpSession *session);
	FecSourcePacket(const mblk_t *incoming);
	FecSourcePacket(const FecSourcePacket &other) = delete;
	FecSourcePacket &operator=(const FecSourcePacket &other) = delete;
	void addBitstring(Bitstring const &other);

	void add(FecSourcePacket const &other);

	void writeBitstring();
	void writeBitstring(uint16_t seqnum);
	size_t getPayloadBuffer(uint8_t **start) const;
	void addPayload(FecSourcePacket const &other);
	void addPayload(const uint8_t *toAdd, size_t size);
	void initPayload(uint16_t length);
	mblk_t *getPacket() const {
		return packet;
	}
	mblk_t *getPacketCopy() const {
		return copymsg(packet);
	}
	const Bitstring &getBitstring() const {
		return bitstring;
	}
	mblk_t *transfer();

	~FecSourcePacket() {
		if (packet) {
			freemsg(packet);
		}
	}
};

class ORTP_PUBLIC FecRepairPacket {
  private:
	mblk_t *packet;
	uint8_t L;
	uint8_t D;
	uint16_t seqnumBase;

  public:
	FecRepairPacket();
	FecRepairPacket(const mblk_t *repairPacket);
	FecRepairPacket(const FecRepairPacket &other) = delete;
	FecRepairPacket &operator=(const FecRepairPacket &other) = delete;

	FecRepairPacket(struct _RtpSession *session, uint16_t seqnumBase, uint8_t L, uint8_t D);
	void addBitstring(Bitstring const &bitstring);
	size_t bitstringStart(uint8_t **start) const;
	Bitstring extractBitstring() const;
	size_t parametersStart(uint8_t **start) const;

	size_t repairPayloadStart(uint8_t **start) const;

	void addPayload(FecSourcePacket const &sourcePacket);
	void add(FecSourcePacket const &sourcePacket);

	void reset(uint16_t seqnumBase);
	std::vector<uint16_t> createSequenceNumberList() const;

	uint8_t getL() const {
		return L;
	};
	uint8_t getD() const {
		return D;
	};
	uint16_t getSeqnumBase() const {
		return seqnumBase;
	};
	mblk_t *transfer() {
		if (packet) {
			mblk_t *ret = packet;
			packet = nullptr;
			return ret;
		}
		return nullptr;
	}
	mblk_t *getRepairPacket() const {
		return packet;
	};
	mblk_t *getCopy() {
		if (packet)
			return copymsg(packet);
		return nullptr;
	}
	~FecRepairPacket() {
		if (packet) {
			freemsg(packet);
		}
	};
};

class ORTP_PUBLIC FecEncoder {

  private:
	std::vector<std::shared_ptr<FecRepairPacket>> rowRepair;
	std::vector<std::shared_ptr<FecRepairPacket>> colRepair;
	RtpSession *session;
	int loading;
	int columns;
	int rows;
	int size;
	bool is2D;
	void initRowRepairPackets(uint16_t seqnumBase);
	void resetRowRepairPackets(uint16_t seqnumBase);
	void initColRepairPackets(uint16_t seqnumBase);
	void resetColRepairPackets(uint16_t seqnumBase);

  public:


	FecEncoder(){};
	FecEncoder(FecParameters *parameters);
	void init(struct _RtpSession *session);
	void add(FecSourcePacket const &packet);
	bool isFull() const {
		return loading == size;
	};
	void reset(uint16_t nextSequenceNumber);
	int getCurrentColumn() const {
		return ((loading - 1) % columns);
	};
	bool isColFull() const {
		return (getCurrentRow() == (rows - 1));
	};
	int getCurrentRow() const {
		return (is2D) ? ((loading - 1) / columns) : 0;
	};
	bool isRowFull() const {
		return (getCurrentColumn() == (columns - 1));
	};
	int getRows() const {
		return rows;
	};
	int getColumns() const {
		return columns;
	};
	int getSize() const {
		return size;
	};

	const std::vector<std::shared_ptr<FecRepairPacket>> &getRowRepair() {
		return rowRepair;
	};
	mblk_t *getRowRepairMblk(int i);
	std::shared_ptr<FecRepairPacket> getRowRepair(int i) {
		return rowRepair[i];
	};
	std::shared_ptr<FecRepairPacket> getColRepair(int i) {
		return colRepair[i];
	};
	const std::vector<std::shared_ptr<FecRepairPacket>> &getColRepair() {
		return colRepair;
	};
	mblk_t *getColRepairMblk(int i);
};

class ORTP_PUBLIC RecieveCluster {

  private:

	uint32_t repairWindow = 200000;
	RtpSession *session;
	std::map<uint16_t, std::shared_ptr<FecSourcePacket>> source;
	std::vector<std::shared_ptr<FecRepairPacket>> rowRepair;
	std::vector<std::shared_ptr<FecRepairPacket>> colRepair;
	void addRepair(FecSourcePacket &source, FecRepairPacket const &repair);

  public:


	RecieveCluster(struct _RtpSession *session) {
		this->session = session;
	};
	RecieveCluster(struct _RtpSession *session, int repair) {
		repairWindow = repair;
		this->session = session;
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
	uint32_t getRepairWindow() {
		return repairWindow;
	};
	void print();
	~RecieveCluster(){};
};

class ORTP_PUBLIC FecStreamCxx {

  private:
	FecParameters *parameters;
	RtpSession *sourceSession;
	RtpSession *fecSession;
	FecEncoder encoder;
	RecieveCluster cluster;
	fec_stats stats;

  public:
	FecStreamCxx(struct _RtpSession *source, struct _RtpSession *fec, FecParameters *fecParams);
	void init();
	void onNewSourcePacketSent(mblk_t *packet);
	void onNewSourcePacketRecieved(mblk_t *packet);
	mblk_t *findMissingPacket(uint16_t seqnum);
	RtpSession *getFecSession() {
		return fecSession;
	};
	fec_stats *getStats() {
		return &stats;
	};
	void printStats();
	~FecStreamCxx(){};
};
} // namespace ortp
#endif
