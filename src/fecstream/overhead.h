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

#include <queue>

#ifndef OVERHEAD_H
#define OVERHEAD_H

namespace ortp {

#ifdef _WIN32
// Disable C4251 triggered by need to export all stl template classes
#pragma warning(disable : 4251)
#endif // ifdef _WIN32

/** @class Overhead
 * @brief Class to estimate the overhead between repair and source packets sent.
 *
 *  This class compute the mean overhead over the last FEC blocks sent from the ratio between the sizes of the repair
 * packets and source packets sent for each block. A local overhead is computed each time the encoderFull method is
 * called, for each independent column of a FEC block.
 *
 * The overhead of a FEC block is defined as the ratio (total size of the repair packets)/(total size of the source
 * packets).
 *
 * The overhead estimator is the average value of the last mBlocksNumber overhead measurements. The estimator can be
 * reset to 0 to collect new values, for example if the parameters ofthe FEC encoder have changed, or the settings of
 * the video encoder that can modidify the size of the packets. A FEC block is a set of successive source packets and
 * the repair packets that protect them. One overhead is computed per FEC block. In case of 1D interleaved parity
 * protection, the FEC blocks are interleaved and the source packets are sent for L independent columns. In that case, L
 * overheads can be measured in parallel, by setting mL = L.
 */
class Overhead {

private:
	size_t const mBlocksNumber = 50; /**< Number of last FEC blocks used to compute the overhead estimator. */
	std::queue<float> mOverheads;    /**< Last measures of overheads. Its maximal size is mBlocksNumber. */
	size_t mL;                       /**< Number of independant overheads to measure in parallel. By default is 1. */
	std::vector<size_t> mSourceSizesInEncoder; /**< Sum of sizes of the source packets of the current FEC blocks. There
	                                              is one element per independent measure. By default has 1 element. */
	std::vector<size_t> mRepairSizesInEncoder; /**< Sum of sizes of the repair packets of the current FEC block. There
	                                              is one element per independent measure. By default has 1 element. */

public:
	Overhead();

	/**
	 * Add the size of a source packet to the i-est overhead measure. If mL = 1, the size is added to the unique element
	 * in mSourceSizesInEncoder.
	 *
	 * @param msgSize size of the source packet.
	 * @param i Index of the current measure in mSourceSizesInEncoder if mL > 1, ignored otherwise.
	 */
	void sendSourcePacket(size_t msgSize, int i);

	/**
	 * Add the size of a repair packet to the i-est overhead measure. If mL = 1, the size is added to the unique element
	 * in mRepairSizesInEncoder.
	 *
	 * @param msgSize size of the repair packet.
	 * @param i Index of the current measure in mRepairSizesInEncoder if mL > 1, ignored otherwise.
	 */
	void sendRepairPacket(size_t msgSize, int i);

	/**
	 * Compute the current overhead from the current measurements of the packets sizes. If severeal overhead are
	 * measured in parallel, they are all computed. The resulting values are added in mOverheads. If the size of
	 * mOverheads exceed the maximal valu, the oldest measures are erased.
	 */
	void encoderFull();

	/**
	 * Reset the current source and packet sizes to 0.
	 */
	void resetEncoder();

	/**
	 * Reset the current source and packet sizes to 0 and set the number of overhead to measure in parallel to L.
	 *
	 * @param L Number of independant overheads to measure in parallel. L must be > 1 for 1D interleaved parity
	 * protection only.
	 */
	void resetEncoder(size_t L);

	/**
	 * Reset all measurements and estimator and set the number of overhead to measure in parallel to L.
	 *
	 * @param L Number of independant overheads to measure in parallel. L must be > 1 for 1D interleaved parity
	 * protection only.
	 */
	void reset(size_t L);

	/**
	 * Compute and return the estimation of the overhead as the average value of the last mBlocksNumber overheads
	 * measured in mOverheads.
	 */
	float computeOverheadEstimator();

	~Overhead(){};
};

} // namespace ortp
#endif
