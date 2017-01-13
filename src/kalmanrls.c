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

#include "ortp/utils.h"


void ortp_kalman_rls_init(OrtpKalmanRLS *rls, double m0, double b0) {
	memset(rls, 0, sizeof(OrtpKalmanRLS));
	rls->lambda = 1.;
	rls->P[0][0] = 1e-10;
	rls->P[1][1] = 1e-1;
	rls->m = m0;
	rls->b = b0;
}

void ortp_kalman_rls_record(OrtpKalmanRLS *rls, double xmes, double ymes) {
	// P = 	a b
	//		c d
	double a = rls->P[0][0];
	double b = rls->P[0][1];
	double c = rls->P[1][0];
	double d = rls->P[1][1];
	double e = xmes;
	double f = 1;

	double estim = rls->m * e + rls->b * f;
	double deno = rls->lambda + (e * a + f * b) * e + (e * c + f * d) * f;

	/** This is delta between the measure and our prediction based on previous model values:
	the more accurate the system, the smaller this value.
	**/
	double diff = ymes - estim;

	rls->m = rls->m + diff * (a*e+b*f);
	rls->b = rls->b + diff * (c*e+d*f);

	rls->P[0][0] = (a - (e*a+f*b)*(e*a+f*c) / deno) * 1.f / rls->lambda;
	rls->P[1][0] = (b - (e*a+f*b)*(e*b+f*d) / deno) * 1.f / rls->lambda;
	rls->P[0][1] = (c - (e*c+f*d)*(e*a+f*c) / deno) * 1.f / rls->lambda;
	rls->P[1][1] = (d - (e*c+f*d)*(e*b+f*d) / deno) * 1.f / rls->lambda;
}


