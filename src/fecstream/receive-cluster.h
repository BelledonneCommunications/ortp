#ifndef RECIEVE_CLUSTER_H
#define RECIEVE_CLUSTER_H

#include <map>
#include <memory>
#include <vector>

#include "fec-params.h"
#include "packet-api.h"

namespace ortp {

class FecParamsController;

class ORTP_PUBLIC ReceiveCluster {

private:
	uint32_t mRepairWindow = 200000;
	RtpSession *mSession;
	RtpTransportModifier *mModifier;
	std::map<uint16_t, std::shared_ptr<FecSourcePacket>> mSource;
	std::vector<std::shared_ptr<FecRepairPacket>> mRowRepair;
	std::vector<std::shared_ptr<FecRepairPacket>> mColRepair;
	void addRepair(FecSourcePacket &source, FecRepairPacket const &repair);

public:
	ReceiveCluster(struct _RtpSession *session);
	ReceiveCluster(struct _RtpSession *session, int repair);
	std::shared_ptr<FecSourcePacket> getSourcePacket(uint16_t seqnum);
	void add(uint16_t seqnum, const std::shared_ptr<FecSourcePacket> &packet);
	void add(const std::shared_ptr<FecRepairPacket> &packet);
	bool isFull() const;
	bool repairPacketsTooOld();
	void clearRepairPackets();
	std::map<uint16_t, std::shared_ptr<FecSourcePacket>> const &getSource();
	int repairOne(FecRepairPacket const &repairPacket);
	int repair1D(bool interleaved);
	int repair2D();
	void setModifier(struct _RtpTransportModifier *modifier);
	uint32_t getRepairWindow();
	void clear();
	void print();
	~ReceiveCluster(){};
};
} // namespace ortp
#endif // RECIEVE_CLUSTER_H