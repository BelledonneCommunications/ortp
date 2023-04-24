#include "packet-api.h"
using namespace ortp;

Bitstring::Bitstring() {
	memset(&mBuffer[0], 0, 8);
}
Bitstring::Bitstring(const mblk_t *packet) {

	size_t payload_size = msgdsize(packet) - RTP_FIXED_HEADER_SIZE;
	mBuffer[0] =
	    rtp_get_version(packet) << 6 | rtp_get_padbit(packet) << 5 | rtp_get_extbit(packet) << 4 | rtp_get_cc(packet);
	mBuffer[1] = rtp_get_markbit(packet) << 7 | rtp_get_payload_type(packet);
	setTimestamp((uint32_t)rtp_get_timestamp(packet));
	setLength((uint16_t)payload_size);
}

void Bitstring::add(Bitstring const &other) {

	*(uint64_t *)&mBuffer[0] ^= *(uint64_t *)&other.mBuffer[0];
}
void Bitstring::reset() {
	memset(&mBuffer[0], 0, 8);
}

void Bitstring::setHeader(uint16_t *h) {
	*(uint16_t *)&mBuffer[0] = *(uint16_t *)h;
}
void Bitstring::setLength(uint16_t l) {
	*(uint16_t *)&mBuffer[6] = (uint16_t)l;
}
void Bitstring::setTimestamp(uint32_t t) {
	*(uint32_t *)&mBuffer[2] = t;
}
bool Bitstring::equals(Bitstring const &other) {
	return (memcmp(&mBuffer[0], &other.mBuffer[0], 8) == 0);
}
void Bitstring::write(mblk_t *packet) {
	rtp_set_version(packet, 2);
	rtp_set_padbit(packet, (mBuffer[0] >> 5) & 0x1);
	rtp_set_extbit(packet, (mBuffer[0] >> 4) & 0x1);
	rtp_set_cc(packet, (mBuffer[0]) & 0xF);
	rtp_set_markbit(packet, (mBuffer[1] >> 7) & 0x1);
	rtp_set_payload_type(packet, mBuffer[1] & 0x7F);
	rtp_set_timestamp(packet, getTimestamp());
}
FecSourcePacket::FecSourcePacket(struct _RtpSession *session) {

	mPacket = rtp_session_create_packet_header(session, 0);
	Bitstring bitstring(mPacket);
}
FecSourcePacket::FecSourcePacket(struct _RtpSession *session, const Bitstring &bs) {

	mPacket = allocb(RTP_FIXED_HEADER_SIZE, BPRI_MED);
	mPacket->b_wptr += RTP_FIXED_HEADER_SIZE;
	rtp_set_ssrc(mPacket, rtp_session_get_send_ssrc(session));
	mBitstring.add(bs);
}
FecSourcePacket::FecSourcePacket(const mblk_t *incoming) : mBitstring(incoming) {

	mPacket = copymsg(incoming);
}
void FecSourcePacket::initPayload(uint16_t length) {

	msgpullup(mPacket, msgdsize(mPacket) + length);
	memset(mPacket->b_wptr, 0, length);
	mPacket->b_wptr += length;
}
void FecSourcePacket::addBitstring(Bitstring const &other) {
	mBitstring.add(other);
}
void FecSourcePacket::addPayload(const uint8_t *toAdd, size_t size) {

	uint8_t *wptr = NULL;
	uint8_t *rptr = (uint8_t *)toAdd;
	size_t currentSize = getPayloadBuffer(&wptr);
	size_t minSize = (size < currentSize) ? size : currentSize;
	for (size_t i = 0; i < minSize; i++) {
		*wptr ^= *rptr;
		wptr++;
		rptr++;
	}
}
void FecSourcePacket::addPayload(FecSourcePacket const &other) {

	uint8_t *other_rptr = NULL;
	size_t otherPayloadSize = other.getPayloadBuffer(&other_rptr);
	addPayload(other_rptr, otherPayloadSize);
}

void FecSourcePacket::add(FecSourcePacket const &other) {

	addBitstring(other.mBitstring);
	addPayload(other);
}
void FecSourcePacket::writeBitstring() {
	mBitstring.write(mPacket);
}
size_t FecSourcePacket::getPayloadBuffer(uint8_t **start) const {
	*start = mPacket->b_rptr + RTP_FIXED_HEADER_SIZE;
	return msgdsize(mPacket) - RTP_FIXED_HEADER_SIZE;
}
mblk_t *FecSourcePacket::transfer() {
	if (mPacket) {
		mblk_t *ret = mPacket;
		mPacket = nullptr;
		return ret;
	}
	return nullptr;
}
mblk_t *FecSourcePacket::getPacket() const {
	return mPacket;
}
mblk_t *FecSourcePacket::getPacketCopy() const {
	return copymsg(mPacket);
}
const Bitstring &FecSourcePacket::getBitstring() const {
	return mBitstring;
}
void FecSourcePacket::setSsrc(uint32_t ssrc) {
	rtp_set_ssrc(mPacket, ssrc);
}
void FecSourcePacket::setSequenceNumber(uint16_t seqnum) {
	rtp_set_seqnumber(mPacket, seqnum);
}
FecSourcePacket::~FecSourcePacket() {
	if (mPacket) {
		freemsg(mPacket);
	}
}
FecRepairPacket::FecRepairPacket(
    struct _RtpSession *fecSession, struct _RtpSession *sourceSession, uint16_t seqnumBase, uint8_t L, uint8_t D) {
	mPacket = NULL;
	this->mSeqnumBase = seqnumBase;
	this->mL = L;
	this->mD = D;
	mPacket = rtp_session_create_repair_packet_header(
	    fecSession, sourceSession,
	    8 * sizeof(uint8_t) + sizeof(uint32_t)); // allocate extra size for initBitString, SeqNumBase, L and D

	// initBitstring
	memset(mPacket->b_wptr, 0, 8 * sizeof(uint8_t));
	mPacket->b_wptr += 8 * sizeof(uint8_t);
	// writeSeqnumBase
	*(uint16_t *)mPacket->b_wptr = mSeqnumBase;
	mPacket->b_wptr += sizeof(uint16_t);
	// writeL
	*(uint8_t *)mPacket->b_wptr = mL;
	mPacket->b_wptr += sizeof(uint8_t);
	// writeD
	*(uint8_t *)mPacket->b_wptr = mD;
	mPacket->b_wptr += sizeof(uint8_t);
}
FecRepairPacket::FecRepairPacket(const mblk_t *repairPacket) {

	mPacket = copymsg(repairPacket);
	uint8_t *rptr = NULL;
	parametersStart(&rptr);

	mSeqnumBase = *(uint16_t *)rptr;
	rptr += sizeof(uint16_t);
	mL = *(uint8_t *)rptr;
	rptr += sizeof(uint8_t);
	mD = *(uint8_t *)rptr;
}

size_t FecRepairPacket::bitstringStart(uint8_t **start) const {
	rtp_get_payload(mPacket, start);
	return (8 * sizeof(uint8_t));
}
size_t FecRepairPacket::parametersStart(uint8_t **start) const {

	size_t bitstringSize = bitstringStart(start);
	*start += bitstringSize;
	return rtp_get_cc(mPacket) * sizeof(uint32_t);
}
size_t FecRepairPacket::repairPayloadStart(uint8_t **start) const {
	size_t parametersSize = parametersStart(start);
	*start += parametersSize;
	return (mPacket->b_wptr - *start);
}
Bitstring FecRepairPacket::extractBitstring() const {

	uint8_t *rptr = NULL;
	Bitstring bs;

	bitstringStart(&rptr);
	bs.setHeader((uint16_t *)rptr);
	rptr += sizeof(uint16_t);
	bs.setTimestamp(*(uint32_t *)rptr);
	rptr += sizeof(uint32_t);
	bs.setLength(ntohs(*(uint16_t *)rptr));

	return bs;
}
void FecRepairPacket::addBitstring(Bitstring const &bitstring) {
	uint8_t *ptr = NULL;
	bitstringStart(&ptr);
	*(uint16_t *)ptr ^= bitstring.getHeader();
	ptr += sizeof(uint16_t);
	*(uint32_t *)ptr ^= bitstring.getTimestamp();
	ptr += sizeof(uint32_t);
	*(uint16_t *)ptr ^= htons(bitstring.getLength());
}
void FecRepairPacket::addPayload(FecSourcePacket const &sourcePacket) {

	uint8_t *packet_rptr = NULL;
	uint8_t *repair_wptr = NULL;

	size_t sourcePayloadSize = sourcePacket.getPayloadBuffer(&packet_rptr);
	size_t repairPayloadSize = repairPayloadStart(&repair_wptr);

	if (sourcePayloadSize > repairPayloadSize) {
		size_t diff = sourcePayloadSize - repairPayloadSize;
		msgpullup(mPacket, msgdsize(mPacket) + diff);
		memset(mPacket->b_wptr, 0, diff);
		mPacket->b_wptr += diff;
	}
	repairPayloadSize = repairPayloadStart(&repair_wptr);
	size_t minSize = (repairPayloadSize > sourcePayloadSize) ? sourcePayloadSize : repairPayloadSize;
	for (size_t i = 0; i < minSize; i++) {
		*repair_wptr ^= *packet_rptr;
		repair_wptr++;
		packet_rptr++;
	}
}
void FecRepairPacket::add(FecSourcePacket const &sourcePacket) {
	addBitstring(sourcePacket.getBitstring());
	addPayload(sourcePacket);
}
std::vector<uint16_t> FecRepairPacket::createSequenceNumberList() const {
	std::vector<uint16_t> list;
	uint8_t step = ((mD <= 1) ? 1 : mL);
	uint16_t size = ((mD <= 1) ? mL : mD);
	list.emplace_back(mSeqnumBase);
	for (int i = 1; i < size; i++) {
		list.emplace_back(list[i - 1] + step);
	}
	return list;
}
void FecRepairPacket::reset(uint16_t seqnumBase) {

	this->mSeqnumBase = seqnumBase;
	bitstringStart(&mPacket->b_wptr);

	// initBitstring
	memset(mPacket->b_wptr, 0, 8 * sizeof(uint8_t));
	mPacket->b_wptr += 8 * sizeof(uint8_t);
	// writeSeqnumBase
	*(uint16_t *)mPacket->b_wptr = seqnumBase;
	mPacket->b_wptr += sizeof(uint16_t);
	// writeL
	*(uint8_t *)mPacket->b_wptr = mL;
	mPacket->b_wptr += sizeof(uint8_t);
	// writeD
	*(uint8_t *)mPacket->b_wptr = mD;
	mPacket->b_wptr += sizeof(uint8_t);
}
uint32_t FecRepairPacket::getProtectedSsrc() const {
	return rtp_get_csrc(mPacket, 0);
}
uint8_t FecRepairPacket::getL() const {
	return mL;
}
uint8_t FecRepairPacket::getD() const {
	return mD;
}
uint16_t FecRepairPacket::getSeqnumBase() const {
	return mSeqnumBase;
};
mblk_t *FecRepairPacket::transfer() {
	if (mPacket) {
		mblk_t *ret = mPacket;
		mPacket = nullptr;
		return ret;
	}
	return nullptr;
}
mblk_t *FecRepairPacket::getRepairPacket() const {
	return mPacket;
};
mblk_t *FecRepairPacket::getCopy() {
	if (mPacket) return copymsg(mPacket);
	return nullptr;
}
FecRepairPacket::~FecRepairPacket() {
	if (mPacket) {
		freemsg(mPacket);
	}
}