#include "fec-params.h"
#include "ortp/logging.h"

/*
 * Copyright (c) 2010-2024 Belledonne Communications SARL.
 *
 * This file is part of oRTP
 * (see https://gitlab.linphone.org/BC/public/ortp).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

using namespace ortp;

extern "C" FecParams *fec_params_new(uint32_t repairWindow) {
	return (FecParams *)(new FecParamsController(repairWindow));
}
extern "C" void fec_params_destroy(FecParams *params) {
	delete (FecParamsController *)params;
}
extern "C" void fec_params_update(FecParams *params, uint8_t level) {
	return ((FecParamsController *)params)->updateParams(level);
}
extern "C" uint8_t fec_params_estimate_best_level(
    FecParams *params, float lossRate, int bitrate, float currentOverhead, float *estimatedOverhead) {
	return ((FecParamsController *)params)->estimateBestLevel(lossRate, bitrate, currentOverhead, estimatedOverhead);
}

FecParamsController::FecParamsController(uint32_t repairWindow) : mRepairWindow(repairWindow), mEnabled(false) {
	mL = 0;
	mD = 0;
	mIs2D = false;
	mLevel = 0;
	mOverhead = 0.;
	computeLossRateTables();
}

void FecParamsController::addSubscriber(FecParamsSubscriber *subscriber) {
	mSubscribers.push_back(subscriber);
}

void FecParamsController::notifySubscribers() {
	for (auto &subscriber : mSubscribers) {
		subscriber->update(this);
	}
}

void FecParamsController::removeSubscriber(FecParamsSubscriber *subscriber) {

	for (auto it = mSubscribers.begin(); it != mSubscribers.end(); it++) {
		if (*it == subscriber) {
			mSubscribers.erase(it);
			return;
		}
	}
}

void FecParamsController::computeLossRateTableGivenOverhead(
    std::array<float, 5> *limits, float p0x, float p0y, float p1x, float p1y) {
	float a = (p1y - p0y) / (p1x - p0x);
	float b = p0y - a * p0x;
	for (size_t i = 0; i < mOverheadLimits.size() - 1; i++) {
		limits->at(i) = (mOverheadLimits.at(i + 1) - b) / a;
	}
}

void FecParamsController::computeLossRateTables() {
	computeLossRateTableGivenOverhead(&mLossRateLimitsLowBandwidth, 3.f, mOverheadLimits.at(1), 8.f,
	                                  mOverheadLimits.at(3));
	computeLossRateTableGivenOverhead(&mLossRateLimitsMediumBandwidth, 0.5f, mOverheadLimits.at(1), 5.f,
	                                  mOverheadLimits.at(5));
	computeLossRateTableGivenOverhead(&mLossRateLimitsHighBandwidth, 0.0f, mOverheadLimits.at(1), 1.f,
	                                  mOverheadLimits.at(5));
}

float FecParamsController::computeOverhead(uint8_t L, uint8_t D, bool is2D) {
	if (L == 0) return 0.f;
	if (is2D) {
		return (1.0f / (float)L) + ((D > 0) ? (1.0f / (float)D) : 0.0f);
	} else if (D == 0) {
		return 1.0f / (float)L;
	} else {
		return 1.0f / (float)D;
	}
}

std::array<float, 5> FecParamsController::findBandwidthRange(int availableBandwidth) {
	if (availableBandwidth < mLowBandwidth) {
		ortp_message("[flexfec] [%p] available bandwidth: %d (low)", this, availableBandwidth);
		mMaximalOverhead = mMaxOverheadList.at(0);
		return mLossRateLimitsLowBandwidth;
	} else if (availableBandwidth > mHighBandwidth) {
		ortp_message("[flexfec] [%p] available bandwidth: %d (high)", this, availableBandwidth);
		mMaximalOverhead = mMaxOverheadList.at(2);
		return mLossRateLimitsHighBandwidth;
	} else {
		ortp_message("[flexfec] [%p] available bandwidth: %d (medium)", this, availableBandwidth);
		mMaximalOverhead = mMaxOverheadList.at(1);
		return mLossRateLimitsMediumBandwidth;
	}
}

uint8_t FecParamsController::findLevelGivenLossRate(float lossRate, std::array<float, 5> *lossRateLimits) {
	uint8_t i = static_cast<uint8_t>(lossRateLimits->size());
	bool paramFound = false;
	while (!paramFound && i > 0) {
		if (lossRate >= lossRateLimits->at(i - 1)) {
			return i;
		}
		i--;
	}
	return 0;
}

uint8_t FecParamsController::estimateBestLevel(float lossRate,
                                               int availableBandwidth,
                                               float currentOverhead,
                                               float *estimatedOverhead) {

	if (lossRate > mMaxLossRate) {
		ortp_message("[flexfec] [%p] high value of loss rate estimation (%f), probable congestion, "
		             "disable FEC. Current fec overhead %f.",
		             this, lossRate, currentOverhead);
		*estimatedOverhead = 0.;
		return 0;
	}

	// best fec level for given loss rate and current bandwidth
	auto lossRateLimits = findBandwidthRange(availableBandwidth);
	uint8_t bestLevel = findLevelGivenLossRate(lossRate, &lossRateLimits);
	float theoreticalOverhead =
	    computeOverhead(mLvalues.at(bestLevel), mDvalues.at(bestLevel), mIs2Dvalues.at(bestLevel));
	float newOverhead = 0.f;

	if (mOverhead > 0.) {
		// estimation of overhead for this level
		newOverhead = theoreticalOverhead / mOverhead * currentOverhead;

		// reduction of the fec level if needed
		while (newOverhead > mMaximalOverhead) {
			ortp_message("[flexfec] [%p] reduce expected FEC level %d, because overhead is %f", this, bestLevel,
			             newOverhead);
			bestLevel--;
			theoreticalOverhead =
			    computeOverhead(mLvalues.at(bestLevel), mDvalues.at(bestLevel), mIs2Dvalues.at(bestLevel));
			newOverhead = theoreticalOverhead / mOverhead * currentOverhead;
		}
	}
	// FEC is currently disabled
	if (newOverhead == 0.) {
		newOverhead = theoreticalOverhead * 2.f;

		// reduction of the fec level if needed
		while (newOverhead > mMaximalOverhead) {
			bestLevel--;
			theoreticalOverhead =
			    computeOverhead(mLvalues.at(bestLevel), mDvalues.at(bestLevel), mIs2Dvalues.at(bestLevel));
			newOverhead = theoreticalOverhead * 2.f;
		}
	}
	*estimatedOverhead = newOverhead;
	ortp_message("[flexfec] [%p] proposed FEC level %d for L = %d, D = %d, estimated overhead %f (< %f)"
	             " for loss rate %f, current fec overhead %f",
	             this, bestLevel, mLvalues.at(bestLevel), mDvalues.at(bestLevel), *estimatedOverhead, mMaximalOverhead,
	             lossRate, currentOverhead);
	return bestLevel;
}

void FecParamsController::updateParams(uint8_t level) {
	if (level >= mLvalues.size()) {
		ortp_message("[flexfec] [%p] Can't change parameters, FEC level %u doesn't exist.", this, level);
		return;
	}
	if (mLevel != level) {
		mLevel = level;
		if (mLevel == 0) {
			disable();
		} else {
			enable();
			mD = mDvalues.at(mLevel);
			mL = mLvalues.at(mLevel);
			mIs2D = mIs2Dvalues.at(mLevel);
		}
		ortp_message("[flexfec] [%p] Parameters changed : L = %u and D = %u, %s, level %d", this, mL, mD,
		             mIs2D ? "2D" : "1D", mLevel);
		mOverhead = computeOverhead(mL, mD, mIs2D);
		notifySubscribers();
	}
}

void FecParamsController::enable() {
	if (mEnabled) return;
	mEnabled = true;
	ortp_message("[flexfec] [%p] Enabling flexfec ...", this);
}

void FecParamsController::disable() {
	if (!mEnabled) return;
	mEnabled = false;
	mL = 0;
	mD = 0;
	mIs2D = false;
	mOverhead = 0.f;
	mLevel = 0;
	ortp_message("[flexfec] [%p] Disabling flexfec", this);
}

FecParamsSubscriber::~FecParamsSubscriber() {
}