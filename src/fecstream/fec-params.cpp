#include "fec-params.h"
#include "ortp/logging.h"

using namespace ortp;

extern "C" FecParams *fec_params_new(uint8_t L, uint8_t D, uint32_t repairWindow) {
	return (FecParams *)(new FecParamsController(L, D, repairWindow));
}

extern "C" float fec_params_update_from_ratio(FecParams *params, float ratio) {
	return ((FecParamsController *)params)->updateParamsFromBandwidthRatio(ratio);
}
FecParamsController::FecParamsController(uint8_t L, uint8_t D, uint32_t repairWindow)
    : mRepairWindow(repairWindow), mEnabled(true), mL(L), mD(D) {
}
void FecParamsController::notifySubscribers() {
	for (auto &subscriber : mSubscribers) {
		subscriber->update(this);
	}
}
void FecParamsController::addSubscriber(FecParamsSubscriber *subscriber) {

	mSubscribers.push_back(subscriber);
}
void FecParamsController::removeSubscriber(FecParamsSubscriber *subscriber) {

	for (auto it = mSubscribers.begin(); it != mSubscribers.end(); it++) {
		if (*it == subscriber) {
			mSubscribers.erase(it);
			return;
		}
	}
}
float FecParamsController::updateParamsFromBandwidthRatio(float bandwidth_ratio) {
	uint8_t newL = 0;
	uint8_t newD = 0;

	if (bandwidth_ratio <= -0.2f) {
		disable();
		return 0.0;
	}
	enable();
	if (bandwidth_ratio > -0.2 && bandwidth_ratio < -0.1) {
		newL = 10U;
	} else if (bandwidth_ratio > 0.1f && bandwidth_ratio <= 0.3) {
		newL = 5U;
	} else if (bandwidth_ratio > 0.3f && bandwidth_ratio <= 0.6) {
		newD = 5U;
		newL = 5U;
	} else if (bandwidth_ratio > 0.6) {
		newL = 3U;
		newD = 3U;
	}
	set(newL, newD);
	return (1.0 / (float)newL) + ((newD > 0) ? (1.0 / (float)newD) : 0.0);
}
void FecParamsController::set(uint8_t L, uint8_t D) {
	bool change = false;

	if (D != mD) {
		mD = D;
		change = true;
	}
	if (L != mL) {
		mL = L;
		change = true;
	}
	if (change) {
		notifySubscribers();
		ortp_message("[flexfec] Parameters changed : L = %u and D = %u", mL, mD);
	}
}
void FecParamsController::enable() {
	if (mEnabled) return;
	mEnabled = true;
	notifySubscribers();
	ortp_message("[flexfec] Enabling flexfec ...");
}
void FecParamsController::disable() {
	if (!mEnabled) return;
	mEnabled = false;
	notifySubscribers();
	ortp_message("[flexfec] Disabling flexfec because of too low bandwidth");
}
uint8_t FecParamsController::getL() {
	return mL;
}
uint8_t FecParamsController::getD() {
	return mD;
}
uint32_t FecParamsController::getRepairWindow() {
	return mRepairWindow;
}
bool FecParamsController::getEnabled() {
	return mEnabled;
}

FecParamsSubscriber::~FecParamsSubscriber() {
}