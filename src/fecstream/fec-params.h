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

#ifndef FEC_PARAMS_H
#define FEC_PARAMS_H

#include <array>
#include <ortp/rtpsession.h>
#include <vector>

namespace ortp {

#ifdef _WIN32
// Disable C4251 triggered by need to export all stl template classes
#pragma warning(disable : 4251)
#endif // ifdef _WIN32

class FecParamsController;

/** @class FecParamsSubscriber
 * @brief Class to update the FecParamsController.
 */
class ORTP_PUBLIC FecParamsSubscriber {
public:
	virtual void update(FecParamsController *) = 0;
	virtual ~FecParamsSubscriber();
};

/** @class FecParamsController
 * @brief Class to control the parameters of the FEC.
 *
 * This class set the value of the repair window, and the parameters of the parity protection. A given FEC protection
 * configuration is represented by a FEC block with D rows and L colmuns, as described in RFC 8627. The configuration
 * can be:
 * - 1D non interleaved parity protection or row protection: L successive source packets are combined together on the
 * same row, and 1 row repair packet is generated.
 * - 1D interleaved parity protection, or column protection: D source packets are combined together every L packets, on
 * the same column, and 1 column repair packet is generated per column. It leads to L column repair packets for L
 * independent columns, for a set of L*D source packets in the FEC block.
 * - 2D parity protection : both row and column protection are applied, and D row repair packets and L column repair
 * packets are generated.
 *
 * Several levels of FEC protection have been defined, that give an increasing recovery rate but at the cost of an
 * increasing redundancy. The controller can identify the optimal level depending on the values of the loss rate, the
 * available bandwidth and the part of the bandwidth that is dedicated to the FEC repair packets, that is given by the
 * overhead. In order to limit the use of bandwidth by the FEC when the total available bandwidth is limited, several
 * rules have been defined between the loss rate and the FEC level, given the bandwidth. The protection increases
 * slowly with the loss rate in case of low bandwidth, and rapidly in case of high bandwidth.
 *
 * Each time that the FEC level is updated, the subscribers are notified and they receive the new FEC parameters.
 *
 * The bandwidths values are given in bit/s.
 */
class ORTP_PUBLIC FecParamsController {
public:
	/**
	 * @brief Initialize the FEC parameters controller.
	 *
	 * Set the value of the repair window, the FEC to disabled and compute the table of loss rate values given
	 * bandwidth.
	 *
	 * @param repairWindow Duration of the repair window, in micro seconds.
	 */
	FecParamsController(uint32_t repairWindow);

	/**
	 * @brief Update the FEC parameters for a given FEC protection level and notify subscribers.
	 *
	 * The subscribers are notified only if the new level is not equal to the current one. If not, the new values of mL,
	 * mD and mIs2D are set, and the state mEnabled is updated. The new value of mOverhead is computed.
	 *
	 * @param level FEC protection level.
	 */
	void updateParams(uint8_t level);

	/**
	 * @brief Estimate the optimal FEC protection level for given values of loss rate, total available bandwidth and
	 * current overhead.
	 *
	 * At first the available bandwidth is analyzed to select the right table of loss rates between the low, medium and
	 * high bandwidth cases. It gives the relationship between the loss rate and the FEC level, related to the current
	 * state of the network. Then the FEC level is determined by finding the loss rate interval that contains the
	 * current loss rate. The related overhead is estimated from the current overhead, measured by the real ratio
	 * between the repair and source sizes, and the theoretical overhead with the new FEC level. It allows to take into
	 * account the average size of the packets. This overhead is an estimate and may be different from the reality,
	 * because the size of the packets is not constant during the call and depends on the video (or audio) encoder
	 * parameters. If the estimated overhead is over a limit value, the FEC will consume too much bandwidth. In that
	 * case, the proposed FEC level is reduced. This check is repeated until the estimated overhead falls below the
	 * limit.
	 *
	 * If the FEC is not currently enabled, there is no measurement of the sizes of the source and the repair packets
	 * trough the overhead. Then the value of the theoretical overhead is taken by default, with the hypothesis that the
	 * source and the repair packets have the same size. As it has been observed that it underestimates the real
	 * overhead, a correction factor is applied.
	 *
	 * If the loss rate is greater than mMaxLossRate, there might be a congestion. In that case, the FEC level returned
	 * is 0.
	 *
	 * @param lossRate Current loss rate: ratio between the number of packets received and packets send.
	 * @param availableBandwidth Total available bandwidth, for the source stream and the FEC stream, in bit/s.
	 * @param currentOverhead Measurement of the current overhead: ratio between the size of the repair packets sent
	 * over the size of the source packets sent.
	 * @param estimatedOverhead To return the estimation of the new overhead for the estimated best FEC level.
	 * @return Optimal FEC protection level estimated.
	 */
	uint8_t estimateBestLevel(float lossRate, int availableBandwidth, float currentOverhead, float *estimatedOverhead);

	/**
	 * @brief Add a subscriber.
	 */
	void addSubscriber(FecParamsSubscriber *subscriber);

	/**
	 * @brief Remove a subscriber.
	 */
	void removeSubscriber(FecParamsSubscriber *subscriber);

	/**
	 * @brief Return the current FEC parameter mL that gives the number of columns of a FEC block.
	 */
	uint8_t getL() {
		return mL;
	}

	/**
	 * @brief Return the current FEC parameter mD that gives the number of rows of a FEC block.
	 */
	uint8_t getD() {
		return mD;
	}

	/**
	 * @brief Return true if the current FEC configuration is a 2D parity protection, false otherwise.
	 */
	bool is2D() {
		return mIs2D;
	}

	/**
	 * @brief Return true if the FEC is currently enabled, false otherwise.
	 */
	bool getEnabled() {
		return mEnabled;
	}

	/**
	 * @brief Return the duration of the repair window, in micro seconds.
	 */
	uint32_t getRepairWindow() {
		return mRepairWindow;
	}

	~FecParamsController(){};

private:
	/**
	 * @brief Notify the subscribers for the current set of FEC parameters.
	 */
	void notifySubscribers();

	/**
	 * @brief Set the parameter mEnabled to true.
	 */
	void enable();

	/**
	 * @brief Set the parameter mEnabled to false, and the FEC level and other parameters to 0.
	 */
	void disable();

	/**
	 * @brief Compute the table of the loss rates related to the values of overhead in mOverheadLimits.
	 *
	 * The loss rate values are computed from the overhead values such that the overhead = f(loss rate) where f is the
	 * line that passes through points P0(p0x, p0y) and P1(p1x, p1y).
	 *
	 * @param limits Table of loss rate limits computed.
	 * @param p0x Loss rate value of P0.
	 * @param p0y Overhead value of P0.
	 * @param p1x Loss rate value of P1.
	 * @param p1y Overhead value of P1.
	 */
	void computeLossRateTableGivenOverhead(std::array<float, 5> *limits, float p0x, float p0y, float p1x, float p1y);

	/**
	 * @brief Compute the tables of loss rates to identify the FEC level to apply given a loss rate for the three cases:
	 * low, medium and high available bandwidth.
	 *
	 * The tables mLossRateLimitsLowBandwidth, mLossRateLimitsMediumBandwidth and mLossRateLimitsHighBandwidth are
	 * computed and give the intervals of loss rate where a given FEC level is applied.
	 */
	void computeLossRateTables();

	/**
	 * @brief Compute the theoretical overhead if the source packets and the repair packet have the same size, for a
	 * given FEC protection configuration.
	 *
	 * The overhead computation depends on the FEC protection:
	 * - in 1D non interleaved, overhead = 1/L
	 * - in 1D interleaved, overhead = 1/D
	 * - in 2D, overhead = 1/L + 1/D.
	 *
	 * @param L Number of columns in a FEC block, not taken into account if D > 1 and is2D is false.
	 * @param D Number of rows in a FEC block.
	 * @param is2D True for 2D parity protection, false otherwise.
	 * @return The overhead computed.
	 */
	float computeOverhead(uint8_t L, uint8_t D, bool is2D);

	/**
	 * @brief Return the table of loss rates to use for the given value of available bandwidth and set the maximal
	 * overhead value mMaximalOverhead accordingly.
	 *
	 * @param availableBandwidth Available bandwidth, in micro seconds.
	 * @return Table of loss rates.
	 */
	std::array<float, 5> findBandwidthRange(int availableBandwidth);

	/**
	 * @brief Return the index of the interval that contains lossRate in the table lossRateLimits. Return 0 if the loss
	 * rate is smaller than the smallest value in the table.
	 *
	 * @param lossRate Loss rate value to compare to the table.
	 * @param lossRateLimits Table of loss rates.
	 * @return Index of the interval that contains lossRate.
	 */
	uint8_t findLevelGivenLossRate(float lossRate, std::array<float, 5> *lossRateLimits);

	std::vector<FecParamsSubscriber *> mSubscribers; /**< Subscribers to the FEC parameter controller.*/
	uint32_t mRepairWindow;                          /**< Duration of the repair window, in micro seconds.*/
	uint8_t mLevel;  /**< Current FEC level, from 0 (disabled) to mLvalues.size(). The other current parameters are set
	                    thanks to this index.*/
	bool mEnabled;   /**< True to enable the FEC, false otherwise.*/
	uint8_t mL;      /**< Number of columns L of a FEC block. Its current value is mLvalues.at(mLevel).*/
	uint8_t mD;      /**< Number of rows D of a FEC block. Its current value is mDvalues.at(mLevel).*/
	bool mIs2D;      /**< True if the FEC parity protection applies in 2D, false otherwise. Its current value is
	                    mIs2Dvalues.at(mLevel).*/
	float mOverhead; /**< Theoretical overhead, if the source and repair packets have the same size, for the current FEC
	                    parameters. 0 if the FEC is disabled. Its current value is mLvalues.at(mLevel).*/
	float mMaximalOverhead = 0.8f; /**< Maximal overhead allowed to not use too much bandwidth for FEC stream. It is
	                                 updated given the current available bandwidth by the function findBandwidthRange.*/
	const std::array<float, 3> mMaxOverheadList = {
	    0.5f, 0.7f, 0.9f}; /**< List of maximal overheads allowed given the available bandwidth, from low to high.*/
	std::array<float, 5> mLossRateLimitsLowBandwidth; /**< Table of loss rate given the FEC level from low to high, in
	                                                     case of low bandwidth.*/
	std::array<float, 5> mLossRateLimitsMediumBandwidth; /**< Table of loss rate given the FEC level from low to high,
	                                                        in case of medium bandwidth.*/
	std::array<float, 5> mLossRateLimitsHighBandwidth; /**< Table of loss rate given the FEC level from low to high, in
	                                                      case of high bandwidth.*/
	const float mMaxLossRate =
	    20.f; /**< Maximal loss rate taken to compute the FEC level. If the loss rate is greater
	            than this value, the FEC should be disabled, because there might be a congestion.*/
	int const mLowBandwidth =
	    100000; /**< Low bandwidth threshold: below that value, the FEC is limited to avoid congestion.*/
	int const mHighBandwidth = 300000; /**< High bandwidth threshold: above that value, the FEC level increases quickly
	                                      with the loss rate.*/
	std::array<float, 6> const mOverheadLimits = {
	    0.f,  0.1f,     0.2f, 0.4f,
	    0.5f, 2.f / 3.f}; /**< Theoretical overheads taken to compute the loss rate tables for an increasing FEC level.
	                         It is related to mLvalues, mDvalues and mIs2Dvalues.*/
	std::array<uint8_t, 6> const mLvalues = {0, 10, 5, 5,
	                                         4, 3}; /**< Table of FEC parameter L for an increasing
	       FEC level. It is related to mOverheadLimits, mDvalues and mIs2Dvalues.*/
	std::array<uint8_t, 6> const mDvalues = {0, 0, 5, 5,
	                                         4, 3}; /**< Table of FEC parameter D for an increasing
	       FEC level. It is related to mOverheadLimits, mLvalues and mIs2Dvalues.*/
	std::array<bool, 6> const mIs2Dvalues = {false, false, false, true,
	                                         true,  true}; /**< Table of FEC parameter 1D or 2D for
an increasing FEC level. It is related to mOverheadLimits, mLvalues and mDvalues.*/
};
} // namespace ortp
#endif // FEC_PARAMS_H