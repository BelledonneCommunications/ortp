
#include "fec-encoder.h"

using namespace ortp;

FecEncoder::FecEncoder(FecParamsController *params) {
	params->addSubscriber(this);
	mColumns = params->getL();
	mIs2D = (params->getD() > 1);
	mRows = (mIs2D) ? params->getD() : 1;
	mSize = mRows * mColumns;
	mLoading = 0;
}
void FecEncoder::init(struct _RtpSession *fecSession, struct _RtpSession *sourceSession, uint16_t seqnum) {
	this->mFecSession = fecSession;
	this->mSourceSession = sourceSession;
	initRowRepairPackets(seqnum);
	initColRepairPackets(seqnum);
}
void FecEncoder::update(FecParamsController *params) {

	mColumns = params->getL();
	mIs2D = (params->getD() > 1);
	mRows = (mIs2D) ? params->getD() : 1;
	mSize = mRows * mColumns;
	uint16_t seqnum = mSourceSession->rtp.rcv_last_seq + 1;
	clear();
	initRowRepairPackets(seqnum);
	initColRepairPackets(seqnum);
}
void FecEncoder::clear() {
	mRowRepair.clear();
	mColRepair.clear();
	mLoading = 0;
}
void FecEncoder::initRowRepairPackets(uint16_t seqnumBase) {
	uint16_t seqnum = seqnumBase;
	int L = mColumns;
	int D = (mIs2D) ? 1 : mRows;

	for (int i = 0; i < mRows; i++) {
		auto repair = std::make_shared<FecRepairPacket>(mFecSession, mSourceSession, seqnum, L, D);
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
		auto repair = std::make_shared<FecRepairPacket>(mFecSession, mSourceSession, seqnum, L, D);
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
bool FecEncoder::isFull() const {
	return mLoading == mSize;
}
int FecEncoder::getCurrentColumn() const {
	return ((mLoading - 1) % mColumns);
}
bool FecEncoder::isColFull() const {
	return (getCurrentRow() == (mRows - 1));
}
int FecEncoder::getCurrentRow() const {
	return (mIs2D) ? ((mLoading - 1) / mColumns) : 0;
}
bool FecEncoder::isRowFull() const {
	return (getCurrentColumn() == (mColumns - 1));
}
int FecEncoder::getRows() const {
	return mRows;
}
int FecEncoder::getColumns() const {
	return mColumns;
}
int FecEncoder::getSize() const {
	return mSize;
}
int FecEncoder::is2D() const {
	return mIs2D;
}
const std::vector<std::shared_ptr<FecRepairPacket>> &FecEncoder::getRowRepair() {
	return mRowRepair;
}
std::shared_ptr<FecRepairPacket> FecEncoder::getRowRepair(int i) {
	return mRowRepair[i];
}
std::shared_ptr<FecRepairPacket> FecEncoder::getColRepair(int i) {
	return mColRepair[i];
}
const std::vector<std::shared_ptr<FecRepairPacket>> &FecEncoder::getColRepair() {
	return mColRepair;
}