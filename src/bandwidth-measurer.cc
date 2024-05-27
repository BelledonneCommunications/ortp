/*
 * Copyright (c) 2010-2022 Belledonne Communications SARL.
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

#include "ortp/utils.h"

namespace ortp {

class BandwidthMeasurerBase {
public:
	virtual ~BandwidthMeasurerBase() = default;
	virtual void addBytes(size_t bytes, const struct timeval &tv) = 0;
	virtual float computeBandwidth() = 0;
};

/**
 * Measure bandwidth over a considered period of time windowMs. The measure is updated continuously (sliding average).
 * This measurer sums bytes count into slots, where slots represents small time division of the considered
 * average interval.
 * This slots are used in a circular manner thanks to modulo operation.
 * Compared to an alternative solution where pairs of < byte counts, time > are stacked into a container
 * and then used to compute the average bandwidth, the choice of fixed divsion of time (slots) has the strong advantage
 * of not requiring any reallocation of memory during the processing.
 * The use of modulo avoids shifting arrays permanently.
 * Each addBytes() has almost constant-time complexity, and each computeBandwidth() call is O(n) where n is the number
 * of slots.
 */
template <int windowsMs, int numSlots>
class BandwidthMeasurer : public BandwidthMeasurerBase {
public:
	static_assert(windowsMs % numSlots == 0);
	static constexpr size_t slotMs = windowsMs / numSlots;
	static constexpr float timeNormalization = 1000.0f / (float)(windowsMs - slotMs);
	void addBytes(size_t bytes, const struct timeval &tv) override {
		size_t absoluteIndex = moveToTimeval(tv);
		unsigned int relativeIndex = (unsigned int)(absoluteIndex % numSlots);
		mSlots[relativeIndex] += (int)bytes;
	}
	float computeBandwidth() override {
		size_t ret = 0;
		struct timeval current;
		bctbx_gettimeofday(&current, NULL);
		moveToTimeval(current);
		for (int i = 0; i < numSlots; ++i) {
			ret += mSlots[i];
		}
		// The current slot may not be filled yet: we then choose to exclude it
		// to avoid a permanent bias. timeNormalization takes into account its exclusion.
		ret -= mSlots[mCurrentAbsoluteIndex % numSlots];
		return ((float)ret) * 8.0f * timeNormalization;
	}

private:
	size_t moveToTimeval(const struct timeval &tv) {
		size_t newIndex = timevalToAbsIndex(tv);
		if (newIndex - mCurrentAbsoluteIndex >= numSlots) {
			memset(&mSlots, 0, sizeof(mSlots));
		} else {
			for (size_t i = mCurrentAbsoluteIndex + 1; i <= newIndex; ++i) {
				mSlots[i % numSlots] = 0;
			}
		}
		mCurrentAbsoluteIndex = newIndex;
		return newIndex;
	}
	size_t timevalToAbsIndex(const struct timeval &tv) {
		return (size_t)((tv.tv_sec * 1000 + tv.tv_usec / 1000) / (windowsMs / numSlots));
	}

	int mSlots[numSlots];
	size_t mCurrentAbsoluteIndex = 0;
};

} // namespace ortp

typedef struct _OrtpBandwidthMeasurer OrtpBandwidthMeasurer;

OrtpBandwidthMeasurer *ortp_bandwidth_measurer_long_term_new(void) {
	return (OrtpBandwidthMeasurer *)static_cast<ortp::BandwidthMeasurerBase *>(new ortp::BandwidthMeasurer<3000, 50>());
}

OrtpBandwidthMeasurer *ortp_bandwidth_measurer_short_term_new(void) {
	return (OrtpBandwidthMeasurer *)static_cast<ortp::BandwidthMeasurerBase *>(new ortp::BandwidthMeasurer<1000, 50>());
}

void ortp_bandwidth_measurer_add_bytes(OrtpBandwidthMeasurer *obj, size_t bytes, const struct timeval *t) {
	((ortp::BandwidthMeasurerBase *)obj)->addBytes(bytes, *t);
}

float ortp_bandwidth_measurer_get_bandwdith(OrtpBandwidthMeasurer *obj) {
	return ((ortp::BandwidthMeasurerBase *)obj)->computeBandwidth();
}

void ortp_bandwidth_measurer_destroy(OrtpBandwidthMeasurer *obj) {
	delete (ortp::BandwidthMeasurerBase *)obj;
}
