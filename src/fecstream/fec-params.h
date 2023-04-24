#ifndef FEC_PARAMS_H
#define FEC_PARAMS_H

#include <memory>
#include <ortp/rtpsession.h>
#include <vector>

namespace ortp {

class FecParamsController;

class ORTP_PUBLIC FecParamsSubscriber {

public:
	virtual void update(FecParamsController *) = 0;
	virtual ~FecParamsSubscriber();
};

class ORTP_PUBLIC FecParamsController {

public:
	FecParamsController(){};
	FecParamsController(uint8_t L, uint8_t D, uint32_t repairWindow);
	float updateParamsFromBandwidthRatio(float);

	void addSubscriber(FecParamsSubscriber *subscriber);
	void removeSubscriber(FecParamsSubscriber *subscriber);
	void set(uint8_t L, uint8_t D);
	void enable();
	void disable();
	uint8_t getL();
	uint8_t getD();
	uint32_t getRepairWindow();
	bool getEnabled();
	~FecParamsController(){};

private:
	void notifySubscribers();

	std::vector<FecParamsSubscriber *> mSubscribers;
	uint32_t mRepairWindow;
	bool mEnabled;
	uint8_t mL;
	uint8_t mD;
};
} // namespace ortp
#endif // FEC_PARAMS_H