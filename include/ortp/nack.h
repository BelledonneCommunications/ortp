/*
 * Copyright (c) 2010-2019 Belledonne Communications SARL.
 *
 * This file is part of oRTP.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NACK_H
#define NACK_H

#include <bctoolbox/list.h>
#include <bctoolbox/port.h>
#include <ortp/port.h>
#include <ortp/rtpsession.h>

#ifdef __cplusplus
extern "C"{
#endif

struct _OrtpNackContext {
	RtpSession *session;
	OrtpEvDispatcher *ev_dispatcher;
	RtpTransportModifier *rtp_modifier;
	RtpTransportModifier *rtcp_modifier;
	queue_t sent_packets;
	bctbx_mutex_t sent_packets_mutex;
	int max_packets;
	int min_jitter_before_nack;
	bool_t decrease_jitter_timer_running;
	uint64_t decrease_jitter_timer_start;
};

typedef struct _OrtpNackContext OrtpNackContext;

ORTP_PUBLIC OrtpNackContext *ortp_nack_context_new(OrtpEvDispatcher *evt);
ORTP_PUBLIC void ortp_nack_context_destroy(OrtpNackContext *ctx);

ORTP_PUBLIC void ortp_nack_context_set_max_packet(OrtpNackContext *ctx, int max);

ORTP_PUBLIC void ortp_nack_context_process_timer(OrtpNackContext *ctx);

#ifdef __cplusplus
}
#endif

#endif
