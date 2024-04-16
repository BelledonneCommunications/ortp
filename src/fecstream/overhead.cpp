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

#include <algorithm>

#include "overhead.h"

#define HEADER_1 '\x80'
#define HEADER_2 '\0'

using namespace ortp;

Overhead::Overhead() {
	mL = 1;
	mRepairSizesInEncoder.assign(mL, 0);
	mSourceSizesInEncoder.assign(mL, 0);
}

void Overhead::sendSourcePacket(size_t msgSize, int i) {
	if (mL == 1) {
		mSourceSizesInEncoder.at(0) += msgSize;
	} else {
		mSourceSizesInEncoder.at(i) += msgSize;
	}
}

void Overhead::sendRepairPacket(size_t msgSize, int i) {
	if (mL == 1) {
		mRepairSizesInEncoder.at(0) += msgSize;
	} else {
		mRepairSizesInEncoder.at(i) += msgSize;
	}
}

void Overhead::encoderFull() {
	for (size_t i = 0; i < mRepairSizesInEncoder.size(); i++) {
		float current_overhead =
		    (mSourceSizesInEncoder.at(i) == 0)
		        ? 0.f
		        : static_cast<float>(mRepairSizesInEncoder.at(i)) / static_cast<float>(mSourceSizesInEncoder.at(i));
		mOverheads.push(current_overhead);
	}
	while (mOverheads.size() > mBlocksNumber) {
		mOverheads.pop();
	}
	resetEncoder(mRepairSizesInEncoder.size());
}

void Overhead::resetEncoder() {
	mRepairSizesInEncoder.assign(mL, 0);
	mSourceSizesInEncoder.assign(mL, 0);
}

void Overhead::resetEncoder(size_t L) {
	mL = L;
	mRepairSizesInEncoder.assign(L, 0);
	mSourceSizesInEncoder.assign(L, 0);
}

void Overhead::reset(size_t L) {
	mL = L;
	while (!mOverheads.empty()) {
		mOverheads.pop();
	}
	resetEncoder(L);
}

float Overhead::computeOverheadEstimator() {
	float overhead_size = static_cast<float>(mOverheads.size());
	if (overhead_size < 5.f) return 0.f;

	std::queue<float> copy_overhead = mOverheads;
	float mean_overhead = 0.f;
	while (!copy_overhead.empty()) {
		mean_overhead += copy_overhead.front();
		copy_overhead.pop();
	}
	mean_overhead = mean_overhead / overhead_size;
	return mean_overhead;
}