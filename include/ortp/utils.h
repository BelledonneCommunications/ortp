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

#ifndef ORTP_UTILS_H
#define ORTP_UTILS_H

#include "ortp/port.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Utility object to determine a maximum or minimum (but not both at the same
 * time), of a signal during a sliding period of time.
 */
typedef struct _OrtpExtremum {
	float current_extremum;
	float last_stable;
	uint64_t extremum_time;
	int period;
} OrtpExtremum;
ORTP_PUBLIC void ortp_extremum_reset(OrtpExtremum *obj);
ORTP_PUBLIC void ortp_extremum_init(OrtpExtremum *obj, int period);
/**
 * Record a new value for minimal.
 * @return TRUE if extremum has changed or false otherwise.
 */
ORTP_PUBLIC bool_t ortp_extremum_record_min(OrtpExtremum *obj, uint64_t curtime, float value);
ORTP_PUBLIC bool_t ortp_extremum_record_max(OrtpExtremum *obj, uint64_t curtime, float value);
ORTP_PUBLIC float ortp_extremum_get_current(OrtpExtremum *obj);
/**
 * Unlike ortp_extremum_get_current() which can be very fluctuating, ortp_extremum_get_previous() returns the extremum
 *found for the previous period.
 **/
ORTP_PUBLIC float ortp_extremum_get_previous(OrtpExtremum *obj);

/**
 * Utility object to interpolate linear model based on captures with 0-mean noise.
 * Based on the model (x, y) where y evolves depending on x with relation y = m*x+b,
 * it will estimate unknown values b, m using given noisy measures xmes and ymes, eg real
 * system is evolving with: y = m * x + b + noise.
 * Note: If noise is NOT white, the residue will be absorbed by one of the estimators.
 * It is an implementation of recursive least square algorithm, based on Kalman filter.
 */
typedef struct _OrtpKalmanRLS {
	/* Unknown parameters to estimate */
	double m, b;
	/* Gain matrix, must not be modified */
	double P[2][2];
	/** Forgetting factor in [94, .999]. Used when unknown parameters vary in time. **/
	double lambda;
} OrtpKalmanRLS;

ORTP_PUBLIC void ortp_kalman_rls_init(OrtpKalmanRLS *obj, double m0, double b0);
ORTP_PUBLIC void ortp_kalman_rls_record(OrtpKalmanRLS *obj, double xmes, double ymes);

/**
 * Object to compute bandwidth of incoming or outgoing streams.
 * Two variants are proposed for short-term (1 sec), or long term (3 secs).
 * The computation by doing a sliding average over the considered time interval
 **/
typedef struct _OrtpBandwidthMeasurer OrtpBandwidthMeasurer;

ORTP_PUBLIC OrtpBandwidthMeasurer *ortp_bandwidth_measurer_long_term_new(void);

ORTP_PUBLIC OrtpBandwidthMeasurer *ortp_bandwidth_measurer_short_term_new(void);

ORTP_PUBLIC void ortp_bandwidth_measurer_add_bytes(OrtpBandwidthMeasurer *obj, size_t bytes, const struct timeval *t);

ORTP_PUBLIC float ortp_bandwidth_measurer_get_bandwdith(OrtpBandwidthMeasurer *obj);

ORTP_PUBLIC void ortp_bandwidth_measurer_destroy(OrtpBandwidthMeasurer *obj);

#ifdef __cplusplus
}
#endif

#endif
