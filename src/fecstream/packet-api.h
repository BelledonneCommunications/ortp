

#ifndef PACKET_API_H
#define PACKET_API_H

#include <ortp/logging.h>
#include <ortp/rtpsession.h>
#include <vector>

namespace ortp {
class ORTP_PUBLIC Bitstring {

private:
	uint8_t mBuffer[8];

public:
	Bitstring();
	Bitstring(const mblk_t *packet);
	void add(Bitstring const &other);
	void reset();
	void write(mblk_t *packet);
	inline uint16_t getHeader() const {
		return *(uint16_t *)&mBuffer[0];
	}
	inline uint32_t getTimestamp() const {
		return *(uint32_t *)&mBuffer[2];
	}
	inline uint16_t getLength() const {
		return *(uint16_t *)&mBuffer[6];
	}
	void setHeader(uint16_t *h);
	void setLength(uint16_t l);
	void setTimestamp(uint32_t t);
	bool equals(Bitstring const &other);
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
	mblk_t *getPacket() const;
	mblk_t *getPacketCopy() const;
	const Bitstring &getBitstring() const;
	mblk_t *transfer();
	void setSsrc(uint32_t ssrc);
	void setSequenceNumber(uint16_t seqnum);
	~FecSourcePacket();
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

	FecRepairPacket(
	    struct _RtpSession *fecSession, struct _RtpSession *sourceSession, uint16_t seqnumBase, uint8_t L, uint8_t D);
	void addBitstring(Bitstring const &bitstring);
	size_t bitstringStart(uint8_t **start) const;
	Bitstring extractBitstring() const;
	size_t parametersStart(uint8_t **start) const;

	size_t repairPayloadStart(uint8_t **start) const;
	uint32_t getProtectedSsrc() const;
	void addPayload(FecSourcePacket const &sourcePacket);
	void add(FecSourcePacket const &sourcePacket);
	void reset(uint16_t seqnumBase);
	std::vector<uint16_t> createSequenceNumberList() const;
	uint8_t getL() const;
	uint8_t getD() const;
	uint16_t getSeqnumBase() const;
	mblk_t *transfer();
	mblk_t *getRepairPacket() const;
	mblk_t *getCopy();
	~FecRepairPacket();
};
} // namespace ortp
#endif // PACKET_API_H