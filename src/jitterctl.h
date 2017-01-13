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
/***************************************************************************
 *            jitterctl.h
 *
 *  Mon Nov  8 11:53:21 2004
 *  Copyright  2004  Simon MORLAT
 *  Email simon.morlat@linphone.org
 ****************************************************************************/

#ifndef JITTERCTL_H
#define JITTERCTL_H

#include <ortp/rtpsession.h>

void jitter_control_init(JitterControl *ctl, PayloadType *pt);
void jitter_control_enable_adaptive(JitterControl *ctl, bool_t val);
static ORTP_INLINE bool_t jitter_control_adaptive_enabled(JitterControl *ctl) { return ctl->params.adaptive; }
void jitter_control_set_payload(JitterControl *ctl, PayloadType *pt);
void jitter_control_update_corrective_slide(JitterControl *ctl);
void jitter_control_update_size(JitterControl *ctl, queue_t *q);
float jitter_control_compute_mean_size(JitterControl *ctl);
void jitter_control_new_packet(JitterControl *ctl, uint32_t packet_ts, uint32_t cur_str_ts);

void jitter_control_new_packet_basic(JitterControl *ctl, uint32_t packet_ts, uint32_t cur_str_ts);
void jitter_control_new_packet_rls(JitterControl *ctl, uint32_t packet_ts, uint32_t cur_str_ts);

uint32_t jitter_control_get_compensated_timestamp(JitterControl *obj , uint32_t user_ts);

#endif
