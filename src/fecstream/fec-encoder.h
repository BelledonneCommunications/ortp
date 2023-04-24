#ifndef FEC_ENCODER_H
#define FEC_ENCODER_H

#include <memory>
#include <vector>

#include "fec-params.h"
#include "packet-api.h"

namespace ortp {

class FecParamsSubscriber;
class FecParamsController;

class ORTP_PUBLIC FecEncoder : public FecParamsSubscriber {

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

	FecEncoder(FecParamsController *parameters);

	void init(struct _RtpSession *fecSession, struct _RtpSession *sourceSession, uint16_t seqnum);
	void add(FecSourcePacket const &packet);
	void update(FecParamsController *params) override;
	bool isFull() const;
	void reset(uint16_t nextSequenceNumber);
	void clear();
	int getCurrentColumn() const;
	bool isColFull() const;
	int getCurrentRow() const;
	bool isRowFull() const;
	int getRows() const;
	int getColumns() const;
	int getSize() const;
	int is2D() const;
	const std::vector<std::shared_ptr<FecRepairPacket>> &getRowRepair();
	mblk_t *getRowRepairMblk(int i);
	std::shared_ptr<FecRepairPacket> getRowRepair(int i);
	std::shared_ptr<FecRepairPacket> getColRepair(int i);
	const std::vector<std::shared_ptr<FecRepairPacket>> &getColRepair();
	mblk_t *getColRepairMblk(int i);
};
} // namespace ortp
#endif // FEC_ENCODER_H