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

#ifndef RTPTIMER_H
#define RTPTIMER_H

#if	!defined(_WIN32) && !defined(_WIN32_WCE)
#include <sys/time.h>
#else
#include <time.h>
#include "winsock2.h"
#endif

#include <ortp/port.h>


typedef void (*RtpTimerFunc)(void);
	
struct _RtpTimer
{
	int state;
#define RTP_TIMER_RUNNING 1
#define RTP_TIMER_STOPPED 0
	RtpTimerFunc timer_init;
	RtpTimerFunc timer_do;
	RtpTimerFunc timer_uninit;
	struct timeval interval;
};

typedef struct _RtpTimer RtpTimer;

ORTP_PUBLIC void rtp_timer_set_interval(RtpTimer *timer, struct timeval *interval);

ORTP_VAR_PUBLIC RtpTimer posix_timer;

#endif
