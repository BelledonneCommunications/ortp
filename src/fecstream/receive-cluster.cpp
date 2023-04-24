#include "receive-cluster.h"

using namespace ortp;

ReceiveCluster::ReceiveCluster(struct _RtpSession *session) {
	this->mSession = session;
}

ReceiveCluster::ReceiveCluster(struct _RtpSession *session, int repair) {
	mRepairWindow = repair;
	this->mSession = session;
}
void ReceiveCluster::setModifier(struct _RtpTransportModifier *modifier) {
	this->mModifier = modifier;
}
uint32_t ReceiveCluster::getRepairWindow() {
	return mRepairWindow;
}
void ReceiveCluster::add(uint16_t seqnum, const std::shared_ptr<FecSourcePacket> &packet) {

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

bool ReceiveCluster::isFull() const {
	auto start = (mSource.begin()->second)->getBitstring().getTimestamp();
	auto end = (mSource.rbegin()->second)->getBitstring().getTimestamp();
	return (end - start >= mRepairWindow);
}
std::map<uint16_t, std::shared_ptr<FecSourcePacket>> const &ReceiveCluster::getSource() {
	return mSource;
};

std::shared_ptr<FecSourcePacket> ReceiveCluster::getSourcePacket(uint16_t seqnum) {

	auto it = mSource.find(seqnum);
	if (it != mSource.end()) return it->second;
	else return nullptr;
}

bool ReceiveCluster::repairPacketsTooOld() {

	auto sizeRow = mRowRepair.size();
	auto sizeCol = mColRepair.size();
	auto tooOldCondition = 60U;
	return (sizeRow + sizeCol > tooOldCondition);
}
void ReceiveCluster::clearRepairPackets() {
	mRowRepair.clear();
	mColRepair.clear();
}
void ReceiveCluster::clear() {
	clearRepairPackets();
	mSource.clear();
}
void ReceiveCluster::add(const std::shared_ptr<FecRepairPacket> &packet) {

	if (repairPacketsTooOld()) {
		clearRepairPackets();
	}
	if (packet->getD() <= 1) {
		mRowRepair.emplace_back(packet);
	} else {
		mColRepair.emplace_back(packet);
	}
}

void ReceiveCluster::addRepair(FecSourcePacket &source, FecRepairPacket const &repair) {

	uint8_t *rptr = NULL;
	size_t repairSize = repair.repairPayloadStart(&rptr);
	source.addPayload(rptr, repairSize);
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

		if (source == NULL) {
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
	addRepair(*recovery, repairPacket);
	mSource.emplace(seqnumToRepair, recovery);

	return 1;
}

int ReceiveCluster::repair1D(bool interleaved) {
	auto repairPackets = (interleaved) ? mColRepair : mRowRepair;
	int repaired = 0;
	for (size_t i = 0; i < repairPackets.size(); i++) {
		repaired += repairOne(*repairPackets[i]);
	}
	return repaired;
}

int ReceiveCluster::repair2D() {
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

void ReceiveCluster::print() {
	int i = 0;
	for (auto it = mSource.begin(); it != mSource.end(); it++) {

		printf("%u ", it->first);
		i++;
		if (i % 5 == 0) {
			printf("\n");
		}
	}
}
