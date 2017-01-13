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

#include "ortp/ortp.h"
#include "rtptimer.h"

void rtp_timer_set_interval(RtpTimer *timer, struct timeval *interval)
{
	if (timer->state==RTP_TIMER_RUNNING){
		ortp_warning("Cannot change timer interval while it is running.\n");
		return;
	}
	timer->interval.tv_sec=interval->tv_sec;
	timer->interval.tv_usec=interval->tv_usec;
}


