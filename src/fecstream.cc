#include "ortp/rtp.h"
#include "ortp/rtpsession.h"
#include "ortp/str_utils.h"

#include "ortp/logging.h"
#include "ortp/port.h"

#include "fecstream.h"

#define HEADER_1 '\x80'
#define HEADER_2 '\0'

using namespace ortp;

extern "C" FecStream *fec_stream_new(struct _RtpSession *source, struct _RtpSession *fec, FecParameters *fecParams) {
	return (FecStream *)new FecStreamCxx(source, fec, fecParams);
}
extern "C" void fec_stream_destroy(FecStream *fec_stream) {
	delete (FecStreamCxx *)fec_stream;
}
extern "C" void fec_stream_on_new_packet_sent(FecStream *fec_stream, mblk_t *packet) {
	((FecStreamCxx *)fec_stream)->onNewSourcePacketSent(packet);
}
extern "C" void fec_stream_on_new_packet_recieved(FecStream *fec_stream, mblk_t *packet) {
	((FecStreamCxx *)fec_stream)->onNewSourcePacketRecieved(packet);
}
extern "C" void fec_stream_recieve_repair_packet(FecStream *fec_stream, uint32_t timestamp) {
	((FecStreamCxx *)fec_stream)->recieveRepairPacket(timestamp);
}

extern "C" mblk_t *fec_stream_find_missing_packet(FecStream *fec_stream, uint16_t seqnum) {
	return ((FecStreamCxx *)fec_stream)->findMissingPacket(seqnum);
}
extern "C" RtpSession *fec_stream_get_fec_session(FecStream *fec_stream) {
	return ((FecStreamCxx *)fec_stream)->getFecSession();
}
extern "C" void fec_stream_print_stats(FecStream *fec_stream) {
	((FecStreamCxx *)fec_stream)->printStats();
}
extern "C" void fec_stream_init(FecStream *fec_stream) {
	((FecStreamCxx *)fec_stream)->init();
}
extern "C" fec_stats *fec_stream_get_stats(FecStream *fec_stream) {
	return ((FecStreamCxx *)fec_stream)->getStats();
}
FecStreamCxx::FecStreamCxx(struct _RtpSession *source, struct _RtpSession *fec, FecParameters *fecParams)
    : mEncoder(fecParams), mCluster(source) {

	parameters = fecParams;
	mSourceSession = source;
	mFecSession = fec;
	rtp_session_enable_jitter_buffer(mFecSession, FALSE);
	mSourceSession->fec_stream = (FecStream *)this;
	mFecSession->fec_stream = NULL;
	memset(&mStats, 0, sizeof(fec_stats));
}

FecStreamCxx::~FecStreamCxx() {
	if (parameters != nullptr) {
		bctbx_free(parameters);
		parameters = nullptr;
	}
}

void FecStreamCxx::init() {
	RtpTransport *transport = NULL;
	RtpBundle *bundle = (RtpBundle *)mSourceSession->bundle;
	RtpSession *session = rtp_bundle_get_primary_session(bundle);
	rtp_session_get_transports(session, &transport, NULL);

	mModifier = ortp_new0(RtpTransportModifier, 1);
	mModifier->level = RtpTransportModifierLevelForwardErrorCorrection;
	mModifier->data = this;
	mModifier->t_process_on_send = FecStreamCxx::processOnSend;
	mModifier->t_process_on_receive = FecStreamCxx::processOnRecieve;
	mModifier->t_process_on_schedule = NULL;
	mModifier->t_destroy = modifierFree;
	meta_rtp_transport_append_modifier(transport, mModifier);
	mCluster.setModifier(mModifier);
	mEncoder.init(mFecSession, mSourceSession);
}
int FecStreamCxx::processOnSend(struct _RtpTransportModifier *m, mblk_t *packet) {

	FecStreamCxx *fecStream = (FecStreamCxx *)m->data;
	RtpSession *sourceSession = fecStream->getSourceSession();
	uint32_t ssrc = rtp_get_ssrc(packet);
	if (ssrc == rtp_session_get_send_ssrc(sourceSession)) {
		fecStream->onNewSourcePacketSent(packet);
	}
	return (int)msgdsize(packet);
}
int FecStreamCxx::processOnRecieve(struct _RtpTransportModifier *m, mblk_t *packet) {

	FecStreamCxx *fecStream = (FecStreamCxx *)m->data;
	RtpSession *sourceSession = fecStream->getSourceSession();
	uint32_t ssrc = rtp_get_ssrc(packet);
	if (ssrc == rtp_session_get_recv_ssrc(sourceSession)) {
		fecStream->onNewSourcePacketRecieved(packet);
	}
	return (int)msgdsize(packet);
}
void ortp::modifierFree(struct _RtpTransportModifier *m) {
	ortp_free(m);
}
void FecStreamCxx::onNewSourcePacketSent(mblk_t *packet) {

	uint16_t seqnum = rtp_get_seqnumber(packet);
	uint32_t timestamp = rtp_get_timestamp(packet);

	msgpullup(packet, -1);
	// To fix : mediastream tool sends two packets with seqnum = 0. The first one is degenerated so we dont take it.
	if (rtp_get_version(packet) != 2) return;

	std::shared_ptr<FecSourcePacket> source(new FecSourcePacket(packet));

	if (mEncoder.isFull()) {
		mEncoder.reset(seqnum);
	}

	mEncoder.add(*source);
	if (mEncoder.isRowFull()) {
		int i = mEncoder.getCurrentRow();
		mblk_t *rowRepair = mEncoder.getRowRepairMblk(i);
		rtp_set_timestamp(rowRepair, timestamp);
		rtp_set_seqnumber(rowRepair, rtp_session_get_seq_number(mFecSession));
		// ortp_message("row repair sended [%u] | %u", timestamp, rtp_get_seqnumber(rowRepair));
		rtp_session_sendm_with_ts(mFecSession, rowRepair, timestamp);

		mStats.row_repair_sended++;
	}
	if (parameters->D > 1 && mEncoder.isColFull()) {
		int i = mEncoder.getCurrentColumn();
		mblk_t *colRepair = mEncoder.getColRepairMblk(i);
		rtp_set_timestamp(colRepair, timestamp);
		rtp_set_seqnumber(colRepair, rtp_session_get_seq_number(mFecSession));
		// ortp_message("col repair sended  [%u] | %u", timestamp, rtp_get_seqnumber(colRepair));
		rtp_session_sendm_with_ts(mFecSession, colRepair, timestamp);
		mStats.col_repair_sended++;
	}
}

void FecStreamCxx::onNewSourcePacketRecieved(mblk_t *packet) {

	uint16_t seqnum;

	msgpullup(packet, -1);
	if (rtp_get_version(packet) != 2) return;

	seqnum = rtp_get_seqnumber(packet);
	std::shared_ptr<FecSourcePacket> source(new FecSourcePacket(packet));
	mCluster.add(seqnum, source);
}

void FecStreamCxx::recieveRepairPacket(uint32_t timestamp) {
	mblk_t *repair_packet = rtp_session_recvm_with_ts(mFecSession, timestamp);

	if (repair_packet == NULL) return;
	if (mCluster.repairPacketsTooOld(*parameters)) mCluster.clearRepairPackets();

	std::shared_ptr<FecRepairPacket> repair(new FecRepairPacket(repair_packet));
	mCluster.add(repair);

	freemsg(repair_packet);
}
void FecStreamCxx::printStats() {

	double initialLossRate = (double)mStats.packets_lost / (double)mSourceSession->stats.packet_recv;
	double residualLossRate =
	    ((double)(mStats.packets_lost - mStats.packets_recovered) / (double)mSourceSession->stats.packet_recv);
	double recoveringRate = (double)mStats.packets_recovered / (double)mStats.packets_lost;

	ortp_log(ORTP_MESSAGE, "===========================================================");
	ortp_log(ORTP_MESSAGE, "               Forward Error Correction Stats              ");
	ortp_log(ORTP_MESSAGE, "-----------------------------------------------------------");
	ortp_log(ORTP_MESSAGE, "	row repair sended           %d packets", mStats.row_repair_sended);
	ortp_log(ORTP_MESSAGE, "	row repair recieved         %d packets", mStats.row_repair_recieved);
	ortp_log(ORTP_MESSAGE, "	col repair sended           %d packets", mStats.col_repair_sended);
	ortp_log(ORTP_MESSAGE, "	col repair recieved         %d packets", mStats.col_repair_recieved);
	ortp_log(ORTP_MESSAGE, "	packets lost                %d packets", mStats.packets_lost);
	ortp_log(ORTP_MESSAGE, "	packets recovered           %d packets", mStats.packets_recovered);
	ortp_log(ORTP_MESSAGE, "	initial loss rate           %f", initialLossRate);
	ortp_log(ORTP_MESSAGE, "	recovering rate             %f", recoveringRate);
	ortp_log(ORTP_MESSAGE, "	residual loss rate          %f", residualLossRate);
	ortp_log(ORTP_MESSAGE, "===========================================================");
}

mblk_t *FecStreamCxx::findMissingPacket(uint16_t seqnum) {

	mCluster.repair2D();
	auto packet = mCluster.getSourcePacket(seqnum);
	mStats.packets_lost++;
	if (packet != nullptr) {
		mblk_t *mp = packet->getPacketCopy();
		RtpTransport *transport = NULL;
		RtpBundle *bundle = (RtpBundle *)mSourceSession->bundle;
		RtpSession *session = rtp_bundle_get_primary_session(bundle);
		rtp_session_get_transports(session, &transport, NULL);
		if (meta_rtp_transport_apply_all_except_one_on_recieve(transport, mModifier, mp) >= 0) {
			ortp_message("Source packet reconstructed : SeqNum = %d;", (int)rtp_get_seqnumber(mp));
			mStats.packets_recovered++;
		}
		return mp;

	} else {
		return nullptr;
	}
}
FecParameters *fec_params_new(uint8_t L, uint8_t D, uint32_t repairWindow) {
	FecParameters *fecParams = (FecParameters *)ortp_malloc0(sizeof(FecParameters));
	fecParams->L = L;
	fecParams->D = D;
	fecParams->repairWindow = repairWindow;
	return fecParams;
}

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
FecEncoder::FecEncoder(FecParameters *parameters) {
	mColumns = parameters->L;
	mIs2D = (parameters->D > 1);
	mRows = (mIs2D) ? parameters->D : 1;
	mSize = mRows * mColumns;
	mLoading = 0;
}
void FecEncoder::init(struct _RtpSession *fecSession, struct _RtpSession *sourceSession) {
	this->mFecSession = fecSession;
	this->mSourceSession = sourceSession;
	initRowRepairPackets(0);
	initColRepairPackets(0);
}
void FecEncoder::initRowRepairPackets(uint16_t seqnumBase) {
	uint16_t seqnum = seqnumBase;
	int L = mColumns;
	int D = (mIs2D) ? 1 : mRows;

	for (int i = 0; i < mRows; i++) {
		std::shared_ptr<FecRepairPacket> repair(new FecRepairPacket(mFecSession, mSourceSession, seqnum, L, D));
		mRowRepair.emplace_back(repair);
		seqnum += mColumns;
	}
}
void FecEncoder::initColRepairPackets(uint16_t seqnumBase) {
	if (mRows <= 1) return;
	uint16_t seqnum = seqnumBase;
	int L = mColumns;
	int D = mRows;
	for (int i = 0; i < mColumns; i++) {
		std::shared_ptr<FecRepairPacket> repair(new FecRepairPacket(mFecSession, mSourceSession, seqnum, L, D));
		mColRepair.emplace_back(repair);
		seqnum++;
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
	if (mRows <= 1) return;
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
	mRowRepair[i]->add(packet);
	if (mIs2D) {
		mColRepair[j]->add(packet);
	}
}

void FecEncoder::reset(uint16_t nextSequenceNumber) {
	mLoading = 0;
	resetRowRepairPackets(nextSequenceNumber);
	if (mIs2D) {
		resetColRepairPackets(nextSequenceNumber);
	}
}
mblk_t *FecEncoder::getRowRepairMblk(int i) {
	return mRowRepair[i]->getCopy();
}
mblk_t *FecEncoder::getColRepairMblk(int i) {
	return mColRepair[i]->getCopy();
}

void RecieveCluster::add(uint16_t seqnum, const std::shared_ptr<FecSourcePacket> &packet) {

	if (mSource.empty()) {
		mSource.emplace(seqnum, packet);
		return;
	}
	auto start = mSource.begin();
	auto firstTs = (start->second)->getBitstring().getTimestamp();
	auto currentTs = packet->getBitstring().getTimestamp();

	if (currentTs - firstTs > mRepairWindow) {
		mSource.erase(start);
	}
	mSource.emplace(seqnum, packet);
}

bool RecieveCluster::isFull() const {
	auto start = (mSource.begin()->second)->getBitstring().getTimestamp();
	auto end = (mSource.rbegin()->second)->getBitstring().getTimestamp();
	return (end - start >= mRepairWindow);
}
std::map<uint16_t, std::shared_ptr<FecSourcePacket>> const &RecieveCluster::getSource() {
	return mSource;
};

std::shared_ptr<FecSourcePacket> RecieveCluster::getSourcePacket(uint16_t seqnum) {

	auto it = mSource.find(seqnum);
	if (it != mSource.end()) return it->second;
	else return nullptr;
}

bool RecieveCluster::repairPacketsTooOld(FecParameters const &parameters) {

	auto sizeRow = mRowRepair.size();
	auto sizeCol = mColRepair.size();
	auto tooOldCondition = 3U * (parameters.L + parameters.D);
	return (sizeRow + sizeCol > tooOldCondition);
}
void RecieveCluster::clearRepairPackets() {
	mRowRepair.clear();
	mColRepair.clear();
}

void RecieveCluster::add(const std::shared_ptr<FecRepairPacket> &packet) {

	if (packet->getD() <= 1) {
		mRowRepair.emplace_back(packet);
	} else {
		mColRepair.emplace_back(packet);
	}
}

void RecieveCluster::addRepair(FecSourcePacket &source, FecRepairPacket const &repair) {

	uint8_t *rptr = NULL;
	size_t repairSize = repair.repairPayloadStart(&rptr);
	source.addPayload(rptr, repairSize);
}

int RecieveCluster::repairOne(FecRepairPacket const &repairPacket) {
	std::vector<uint16_t> seqnumList;
	uint16_t seqnumToRepair = 0;

	int loss = 0;
	int i = 0;
	Bitstring recoveryBs;
	seqnumList = repairPacket.createSequenceNumberList();
	while (loss <= 1 && (unsigned long)i < seqnumList.size()) {

		std::shared_ptr<FecSourcePacket> source = getSourcePacket(seqnumList[i]);

		if (source == NULL) {
			seqnumToRepair = seqnumList[i];
			loss++;
		} else {
			recoveryBs.add(source->getBitstring());
		}
		i++;
	}

	if (loss == 1) {

		recoveryBs.add(repairPacket.extractBitstring());
		std::shared_ptr<FecSourcePacket> recovery(new FecSourcePacket(mSession, recoveryBs));
		recovery->initPayload(recoveryBs.getLength());
		recovery->writeBitstring();
		recovery->setSequenceNumber(seqnumToRepair);

		recovery->setSsrc(repairPacket.getProtectedSsrc());
		for (int i = 0; (unsigned long)i < seqnumList.size(); i++) {
			if (seqnumList[i] == seqnumToRepair) continue;
			std::shared_ptr<FecSourcePacket> sourceP = getSourcePacket(seqnumList[i]);
			recovery->addPayload(*sourceP);
		}
		addRepair(*recovery, repairPacket);
		mSource.emplace(seqnumToRepair, recovery);

		return 1;
	}
	return 0;
}

int RecieveCluster::repair1D(bool interleaved) {
	auto repairPackets = (interleaved) ? mColRepair : mRowRepair;
	int repaired = 0;
	for (size_t i = 0; i < repairPackets.size(); i++) {
		repaired += repairOne(*repairPackets[i]);
	}
	return repaired;
}

int RecieveCluster::repair2D() {
	int num_recovered_until_this_iteration = 0;
	int num_recovered_so_far = 0;

	do {
		num_recovered_so_far += repair1D(false);
		num_recovered_so_far += repair1D(true);

		if (num_recovered_so_far > num_recovered_until_this_iteration) {
			num_recovered_until_this_iteration = num_recovered_so_far;
		} else break;

	} while (1);
	return num_recovered_until_this_iteration;
}

void RecieveCluster::print() {
	int i = 0;
	for (auto it = mSource.begin(); it != mSource.end(); it++) {

		printf("%u ", it->first);
		i++;
		if (i % 5 == 0) {
			printf("\n");
		}
	}
}
