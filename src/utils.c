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
#ifdef HAVE_CONFIG_H
#include "ortp-config.h"
#endif
#include "math.h"
#include "ortp/logging.h"
#include "ortp/port.h"
#include "utils.h"

uint64_t ortp_timeval_to_ntp(const struct timeval *tv) {
	uint64_t msw;
	uint64_t lsw;
	msw = tv->tv_sec + 0x83AA7E80; /* 0x83AA7E80 is the number of seconds from 1900 to 1970 */
	lsw = (uint32_t)((double)tv->tv_usec * (double)(((uint64_t)1) << 32) * 1.0e-6);
	return msw << 32 | lsw;
}

/**
 * Bandwidth estimator
 * To get more precise download bandwidth estimator, the following algorithm is applied:
 * - timeline is divided in steps (typical value: 10ms)
 * - each time a packet is received, it is considered to have been received during the last step,
 *   all the previous step have an incoming data amount set to 0
 * - at each step, the previous value is kept pondered by a depreciation factor alpha (typical 0.95)
 * - when a packet arrives, the number of steps since the last packet is computed using the timestamp
 *   set on reception in the packet itself.
 * - the previous value part is computed as following: v*(alpha^steps_number)
 * - the current packet contribution: size*(1-alpha)
 * - the value is stored in bytes/steps
 *
 * Packets are supposed to arrive quite regularly at a max rate of one each 100ms, more likely 20ms
 * Having alpha=0.95 and step = 10ms gives a good measure on the last 850 ms(.95^85 ~= 1%)
 * Having alpha=0.985 and step = 10ms gives a good measure on the last 3 second(.99^300 ~= 1%)
 * (when packets arrive quite regularly at a max rate of one each 100ms)
 *
 */
void ortp_bw_estimator_init(OrtpBwEstimator *obj, float alpha, float step) {
	obj->one_minus_alpha = 1.0f - alpha;
	obj->inv_step = 1.0f / step;
	obj->exp_constant = logf(alpha) * obj->inv_step;
	obj->last_packet_recv.tv_sec = 0;
	obj->last_packet_recv.tv_usec = 0;
	obj->value = 0;
}

void ortp_bw_estimator_packet_received(OrtpBwEstimator *obj, size_t bytes, const struct timeval *recv_time) {
	float diff_time;

	if (obj->last_packet_recv.tv_sec == 0) {
		diff_time = 1.0f / obj->inv_step;
	} else {
		diff_time = (float)(recv_time->tv_sec - obj->last_packet_recv.tv_sec) +
		            1e-6f * (recv_time->tv_usec - obj->last_packet_recv.tv_usec);
	}
	obj->value = ((float)bytes * obj->one_minus_alpha) + expf(diff_time * obj->exp_constant) * obj->value;
	obj->last_packet_recv = *recv_time;
}

float ortp_bw_estimator_get_value(OrtpBwEstimator *obj) {
	struct timeval current;
	bctbx_gettimeofday(&current, NULL);
	ortp_bw_estimator_packet_received(obj, 0, &current);
	return obj->value * 8.0f * obj->inv_step;
}
