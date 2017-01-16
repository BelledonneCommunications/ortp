/*
 * The oRTP library is an RTP (Realtime Transport Protocol - rfc3550) implementation with additional features.
 * Copyright (C) 2017 Belledonne Communications SARL
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
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
typedef struct _OrtpExtremum{
	float current_extremum;
	float last_stable;
	uint64_t extremum_time;
	int period;
}OrtpExtremum;
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
 * Unlike ortp_extremum_get_current() which can be very fluctuating, ortp_extremum_get_previous() returns the extremum found for the previous period.
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
typedef struct _OrtpKalmanRLS{
	/* Unknown parameters to estimate */
	double m, b;
	/* Gain matrix, must not be modified */
	double P[2][2];
	/** Forgetting factor in [94, .999]. Used when unknown parameters vary in time. **/
	double lambda;
}OrtpKalmanRLS;

ORTP_PUBLIC void ortp_kalman_rls_init(OrtpKalmanRLS *obj, double m0, double b0);
ORTP_PUBLIC void ortp_kalman_rls_record(OrtpKalmanRLS *obj, double xmes, double ymes);


#ifdef __cplusplus
}
#endif

#endif
