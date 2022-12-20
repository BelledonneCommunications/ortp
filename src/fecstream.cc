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
extern "C" fec_stats * fec_stream_get_stats(FecStream *fec_stream) {
	return ((FecStreamCxx *)fec_stream)->getStats();
}
FecStreamCxx::FecStreamCxx(struct _RtpSession *source, struct _RtpSession *fec, FecParameters *fecParams) : encoder(fecParams), cluster(source)  {

	parameters = fecParams;
	sourceSession = source;
	fecSession = fec;
	rtp_session_enable_jitter_buffer(fecSession, FALSE);
	sourceSession->fec_stream = (FecStream *)this;
	fecSession->fec_stream = NULL;
	memset(&stats, 0, sizeof(fec_stats));
}
void FecStreamCxx::init(){
	encoder.init(fecSession);
}

void FecStreamCxx::onNewSourcePacketSent(mblk_t *packet) {

	uint16_t seqnum = rtp_get_seqnumber(packet);
	uint32_t timestamp = rtp_get_timestamp(packet);

	msgpullup(packet, -1);
	// To fix : mediastream tool sends two packets with seqnum = 0. The first one is degenerated so we dont take it.
	if (rtp_get_version(packet) != 2)
		return;

	std::shared_ptr<FecSourcePacket> source(new FecSourcePacket(packet));

	if (encoder.isFull()) {
		encoder.reset(seqnum);
		//ortp_message("Reset of the FecEncoder");
	}
	//ortp_message("Add of an rtp packet to the encoder");
	encoder.add(*source);
	if (encoder.isRowFull()) {
		int i = encoder.getCurrentRow();
		mblk_t * rowRepair = encoder.getRowRepairMblk(i);
		rtp_set_timestamp(rowRepair, timestamp);
		rtp_set_seqnumber(rowRepair, rtp_session_get_seq_number(fecSession));
		//ortp_message("row repair sended [%u] | %u", timestamp, rtp_get_seqnumber(rowRepair));
		rtp_session_sendm_with_ts(fecSession, rowRepair, timestamp);
		stats.row_repair_sended++;
	}
	if (parameters->D > 1 && encoder.isColFull()) {
		int i = encoder.getCurrentColumn();
		mblk_t * colRepair = encoder.getColRepairMblk(i);
		rtp_set_timestamp(colRepair, timestamp);
		rtp_set_seqnumber(colRepair, rtp_session_get_seq_number(fecSession));
		//ortp_message("col repair sended  [%u] | %u", timestamp, rtp_get_seqnumber(colRepair));
		rtp_session_sendm_with_ts(fecSession, colRepair, timestamp);
		stats.col_repair_sended++;
	}
}

void FecStreamCxx::onNewSourcePacketRecieved(mblk_t *packet) {

	mblk_t *repair_packet = NULL;
	uint16_t seqnum;
	uint32_t timestamp;

	msgpullup(packet, -1);
	if (rtp_get_version(packet) != 2)
		return;
	timestamp = rtp_get_timestamp(packet);
	seqnum = rtp_get_seqnumber(packet);

	std::shared_ptr<FecSourcePacket> source(new FecSourcePacket(packet));

	cluster.add(seqnum, source);
	//ortp_message("Source packet added to the recieve cluster");
	repair_packet = rtp_session_recvm_with_ts(fecSession, timestamp);

	if (repair_packet == NULL)
		return;

	if (cluster.repairPacketsTooOld(*parameters))
		cluster.clearRepairPackets();

	std::shared_ptr<FecRepairPacket> repair(new FecRepairPacket(repair_packet));
	cluster.add(repair);

	if (repair->getD() <= 1) {
		stats.row_repair_recieved++;
		cluster.repair1D(false);
	} else {
		stats.col_repair_recieved++;
		cluster.repair1D(true);
	}
}

void FecStreamCxx::printStats() {

	double initialLossRate = (double)stats.packets_lost / (double)sourceSession->stats.packet_recv;
	double residualLossRate =
		((double)(stats.packets_lost - stats.packets_recovered) / (double)sourceSession->stats.packet_recv);
	double recoveringRate = (double)stats.packets_recovered / (double)stats.packets_lost;

	ortp_log(ORTP_MESSAGE, "===========================================================");
	ortp_log(ORTP_MESSAGE, "               Forward Error Correction stats              ");
	ortp_log(ORTP_MESSAGE, "-----------------------------------------------------------");
	ortp_log(ORTP_MESSAGE, "	row repair sended           %d packets", stats.row_repair_sended);
	ortp_log(ORTP_MESSAGE, "	row repair recieved         %d packets", stats.row_repair_recieved);
	ortp_log(ORTP_MESSAGE, "	col repair sended           %d packets", stats.col_repair_sended);
	ortp_log(ORTP_MESSAGE, "	col repair recieved         %d packets", stats.col_repair_recieved);
	ortp_log(ORTP_MESSAGE, "	packets lost                %d packets", stats.packets_lost);
	ortp_log(ORTP_MESSAGE, "	packets recovered           %d packets", stats.packets_recovered);
	ortp_log(ORTP_MESSAGE, "	initial loss rate           %f", initialLossRate);
	ortp_log(ORTP_MESSAGE, "	recovering rate             %f", recoveringRate);
	ortp_log(ORTP_MESSAGE, "	residual loss rate          %f", residualLossRate);
	ortp_log(ORTP_MESSAGE, "===========================================================");
}

mblk_t *FecStreamCxx::findMissingPacket(uint16_t seqnum) {

	auto packet = cluster.getSourcePacket(seqnum);
	stats.packets_lost++;
	if (packet != nullptr) {
		stats.packets_recovered++;
		return packet->getPacketCopy();
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

	*(uint64_t *) &mBuffer[0] ^= *(uint64_t *) &other.mBuffer[0];
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

	packet = rtp_session_create_packet(session, RTP_FIXED_HEADER_SIZE, NULL, 0);
	Bitstring bitstring(packet);
}
FecSourcePacket::FecSourcePacket(struct _RtpSession *session, const Bitstring &bs) {

	packet  = allocb(RTP_FIXED_HEADER_SIZE, BPRI_MED);
	packet->b_wptr+=RTP_FIXED_HEADER_SIZE;
	rtp_set_ssrc(packet, rtp_session_get_send_ssrc(session));
	bitstring.add(bs);
}
FecSourcePacket::FecSourcePacket(const mblk_t *incoming) : bitstring(incoming){

	packet = copymsg(incoming);
}
void FecSourcePacket::initPayload(uint16_t length) {

	msgpullup(packet, msgdsize(packet) + length);
	memset(packet->b_wptr, 0, length);
	packet->b_wptr += length;
}
void FecSourcePacket::addBitstring(Bitstring const &other) {
	bitstring.add(other);
}
void FecSourcePacket::addPayload(const uint8_t *toAdd, size_t size) {

	uint8_t *wptr = NULL;
	uint8_t *rptr = (uint8_t *) toAdd;
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

	addBitstring(other.bitstring);
	addPayload(other);
}
void FecSourcePacket::writeBitstring() {

	bitstring.write(packet);
}
void FecSourcePacket::writeBitstring(uint16_t seqnum) {

	rtp_set_seqnumber(packet, seqnum);
	bitstring.write(packet);
}
size_t FecSourcePacket::getPayloadBuffer(uint8_t **start) const {
	*start = packet->b_rptr + RTP_FIXED_HEADER_SIZE;
	return msgdsize(packet) - RTP_FIXED_HEADER_SIZE;
}
mblk_t *FecSourcePacket::transfer() {
	if (packet) {
		mblk_t *ret = packet;
		packet = nullptr;
		return ret;
	}
	return nullptr;
}
FecRepairPacket::FecRepairPacket(struct _RtpSession *session, uint16_t seqnumBase, uint8_t L, uint8_t D) {
	packet = NULL;
	this->seqnumBase = seqnumBase;
	this->L = L;
	this->D = D;
	packet = rtp_session_create_packet(session, RTP_FIXED_HEADER_SIZE, NULL, 0);
	rtp_set_ssrc(packet, rtp_session_get_send_ssrc(session));
	rtp_set_payload_type(packet, rtp_session_get_send_payload_type(session));
	// compute size
	size_t newSize = msgdsize(packet) + 8 + 4;
	msgpullup(packet, newSize);

	// initBitstring
	memset(packet->b_wptr, 0, 8 * sizeof(uint8_t));
	packet->b_wptr += 8 * sizeof(uint8_t);
	// writeSeqnumBase
	*(uint16_t *)packet->b_wptr = seqnumBase;
	packet->b_wptr += sizeof(uint16_t);
	// writeL
	*(uint8_t *)packet->b_wptr = L;
	packet->b_wptr += sizeof(uint8_t);
	// writeD
	*(uint8_t *)packet->b_wptr = D;
	packet->b_wptr += sizeof(uint8_t);
}
FecRepairPacket::FecRepairPacket(const mblk_t *repairPacket) {

	packet = copymsg(repairPacket);
	uint8_t *rptr = NULL;
	parametersStart(&rptr);

	seqnumBase = *(uint16_t *)rptr;
	rptr += sizeof(uint16_t);
	L = *(uint8_t *)rptr;
	rptr += sizeof(uint8_t);
	D = *(uint8_t *)rptr;
}

size_t FecRepairPacket::bitstringStart(uint8_t **start) const {
	rtp_get_payload(packet, start);
	return (8 * sizeof(uint8_t));
}
size_t FecRepairPacket::parametersStart(uint8_t **start) const {

	size_t bitstringSize = bitstringStart(start);
	*start += bitstringSize;
	//TODO : return 4 * rtp_get_cc(packet) * sizeof(uint8_t);
	return (4 * sizeof(uint8_t));
}
size_t FecRepairPacket::repairPayloadStart(uint8_t **start) const {
	size_t parametersSize = parametersStart(start);
	*start += parametersSize;
	return (packet->b_wptr - *start);
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
	*(uint16_t *) ptr ^= bitstring.getHeader();
	ptr+=sizeof(uint16_t);
	*(uint32_t *) ptr ^= bitstring.getTimestamp();
	ptr+=sizeof(uint32_t);
	*(uint16_t *) ptr ^= htons(bitstring.getLength());
}
void FecRepairPacket::addPayload(FecSourcePacket const &sourcePacket) {

	uint8_t *packet_rptr = NULL;
	uint8_t *repair_wptr = NULL;
	
	size_t sourcePayloadSize = sourcePacket.getPayloadBuffer(&packet_rptr);
	size_t repairPayloadSize = repairPayloadStart(&repair_wptr);

	if (sourcePayloadSize > repairPayloadSize) {
		size_t diff = sourcePayloadSize - repairPayloadSize;
		msgpullup(packet, msgdsize(packet)+diff);
		memset(packet->b_wptr, 0, diff);
		packet->b_wptr += diff;
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
	uint8_t step = ((D <= 1) ? 1 : L);
	uint16_t size = ((D <= 1) ? L : D);
	list.emplace_back(seqnumBase);
	for (int i = 1; i < size; i++) {
		list.emplace_back(list[i - 1] + step);
	}
	return list;
}
void FecRepairPacket::reset(uint16_t seqnumBase) {

	this->seqnumBase = seqnumBase;
	bitstringStart(&packet->b_wptr);

	// initBitstring
	memset(packet->b_wptr, 0, 8 * sizeof(uint8_t));
	packet->b_wptr += 8 * sizeof(uint8_t);
	// writeSeqnumBase
	*(uint16_t *)packet->b_wptr = seqnumBase;
	packet->b_wptr += sizeof(uint16_t);
	// writeL
	*(uint8_t *)packet->b_wptr = L;
	packet->b_wptr += sizeof(uint8_t);
	// writeD
	*(uint8_t *)packet->b_wptr = D;
	packet->b_wptr += sizeof(uint8_t);
}
FecEncoder::FecEncoder(FecParameters *parameters) {
	columns = parameters->L;
	is2D = (parameters->D > 1);
	rows = (is2D) ? parameters->D : 1;
	size = rows * columns;
	loading = 0;
}
void FecEncoder::init(struct _RtpSession *session){
	this->session = session;
	initRowRepairPackets(0);
	initColRepairPackets(0);
}
void FecEncoder::initRowRepairPackets(uint16_t seqnumBase) {
	uint16_t seqnum = seqnumBase;
	int L = columns;
	int D = (is2D) ? 1 : rows;

	for (int i = 0; i < rows; i++) {
		std::shared_ptr<FecRepairPacket> repair(new FecRepairPacket(session, seqnum, L, D));
		rowRepair.emplace_back(repair);
		seqnum += columns;
	}
}
void FecEncoder::initColRepairPackets(uint16_t seqnumBase) {
	if(rows <= 1) return;
	uint16_t seqnum = seqnumBase;
	int L = columns;
	int D = rows;
	for (int i = 0; i < columns; i++) {
		std::shared_ptr<FecRepairPacket> repair(new FecRepairPacket(session, seqnum, L, D));
		colRepair.emplace_back(repair);
		seqnum++;
	}
}
void FecEncoder::resetRowRepairPackets(uint16_t seqnumBase) {

	uint16_t seqnum = seqnumBase;
	for (size_t i = 0; i < rowRepair.size(); i++) {
		rowRepair[i]->reset(seqnum);
		seqnum+=columns;
	}
}
void FecEncoder::resetColRepairPackets(uint16_t seqnumBase) {
	if(rows <= 1) return;
	uint16_t seqnum = seqnumBase;
	for (size_t i = 0; i < colRepair.size(); i++) {
		colRepair[i]->reset(seqnum);
		seqnum++;
	}
}

void FecEncoder::add(FecSourcePacket const &packet) {
	loading++;
	int i = getCurrentRow();
	int j = getCurrentColumn();
	rowRepair[i]->add(packet);
	if (is2D) {
		colRepair[j]->add(packet);
	}
}

void FecEncoder::reset(uint16_t nextSequenceNumber) {
	loading = 0;
	resetRowRepairPackets(nextSequenceNumber);
	if (is2D) {
		resetColRepairPackets(nextSequenceNumber);
	}
}
mblk_t *FecEncoder::getRowRepairMblk(int i) {
	return rowRepair[i]->getCopy();
}
mblk_t *FecEncoder::getColRepairMblk(int i) {
	return colRepair[i]->getCopy();
}

void RecieveCluster::add(uint16_t seqnum, const std::shared_ptr<FecSourcePacket> & packet) {

	if (source.empty()) {
		source.emplace(seqnum, packet);
		return;
	}
	auto start = source.begin();
	auto firstTs = (start->second)->getBitstring().getTimestamp();
	auto currentTs = packet->getBitstring().getTimestamp();

	if (currentTs - firstTs > repairWindow) {
		source.erase(start);
	}
	source.emplace(seqnum, packet);
}

bool RecieveCluster::isFull() const {
	auto start = (source.begin()->second)->getBitstring().getTimestamp();
	auto end = (source.rbegin()->second)->getBitstring().getTimestamp();
	return (end - start >= repairWindow);
}
std::map<uint16_t, std::shared_ptr<FecSourcePacket>> const &RecieveCluster::getSource() {
	return source;
};

std::shared_ptr<FecSourcePacket> RecieveCluster::getSourcePacket(uint16_t seqnum) {

	auto it = source.find(seqnum);
	if (it != source.end())
		return it->second;
	else
		return nullptr;
}

bool RecieveCluster::repairPacketsTooOld(FecParameters const &parameters) {

	auto sizeRow = rowRepair.size();
	auto sizeCol = colRepair.size();
	return (sizeRow + sizeCol > 3*(parameters.L + parameters.D));
}
void RecieveCluster::clearRepairPackets() {
	rowRepair.clear();
	colRepair.clear();
}

void RecieveCluster::add(const std::shared_ptr<FecRepairPacket> & packet) {

	if (packet->getD() <= 1) {
		rowRepair.emplace_back(packet);
	} else {
		colRepair.emplace_back(packet);
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
		std::shared_ptr<FecSourcePacket> recovery(new FecSourcePacket(session, recoveryBs));
		recovery->initPayload(recoveryBs.getLength());
		recovery->writeBitstring(seqnumToRepair);

		for (int i = 0; (unsigned long)i < seqnumList.size(); i++) {
			if (seqnumList[i] == seqnumToRepair)
				continue;
			std::shared_ptr<FecSourcePacket> sourceP = getSourcePacket(seqnumList[i]);
			recovery->addPayload(*sourceP);
		}
		addRepair(*recovery, repairPacket);
		source.emplace(seqnumToRepair, recovery);
		return 1;
	}
	return 0;
}

int RecieveCluster::repair1D(bool interleaved) {
	auto repairPackets = (interleaved) ? colRepair : rowRepair;
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
		} else
			break;

	} while (1);
	return num_recovered_until_this_iteration;
}


void RecieveCluster::print(){
	int i=0;
	for(auto it = source.begin(); it != source.end(); it++){

		printf("%u ",it->first);
		i++;
		if(i % 5 == 0){
			printf("\n");
		}
		
	}
}