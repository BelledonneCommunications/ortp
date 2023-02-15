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

#include "ortp/ortp.h"
#include "rtptimer.h"

#if !defined(_WIN32) && !defined(_WIN32_WCE)

#ifdef __linux__
#include <sys/select.h>
#endif

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

static struct timeval orig, cur;
static uint32_t posix_timer_time = 0; /*in milisecond */

void posix_timer_init(void) {
	posix_timer.state = RTP_TIMER_RUNNING;
	bctbx_gettimeofday(&orig, NULL);
	posix_timer_time = 0;
}

void posix_timer_do(void) {
	int diff, time;
	struct timeval tv;
	bctbx_gettimeofday(&cur, NULL);
	time = ((cur.tv_usec - orig.tv_usec) / 1000) + ((cur.tv_sec - orig.tv_sec) * 1000);
	if ((diff = time - posix_timer_time) > 50) {
		ortp_warning("Must catchup %i miliseconds.", diff);
	}
	while ((diff = posix_timer_time - time) > 0) {
		tv.tv_sec = diff / 1000;
		tv.tv_usec = (diff % 1000) * 1000;
#if defined(_WIN32) || defined(_WIN32_WCE)
		/* this kind of select is not supported on windows */
		Sleep(tv.tv_usec / 1000 + tv.tv_sec * 1000);
#else
		select(0, NULL, NULL, NULL, &tv);
#endif
		bctbx_gettimeofday(&cur, NULL);
		time = ((cur.tv_usec - orig.tv_usec) / 1000) + ((cur.tv_sec - orig.tv_sec) * 1000);
	}
	posix_timer_time += POSIXTIMER_INTERVAL / 1000;
}

void posix_timer_uninit(void) {
	posix_timer.state = RTP_TIMER_STOPPED;
}

RtpTimer posix_timer = {0, posix_timer_init, posix_timer_do, posix_timer_uninit, {0, POSIXTIMER_INTERVAL}};

#else //_WIN32

#if defined(ENABLE_MICROSOFT_STORE_APP) || defined(ORTP_WINDOWS_UWP)

#include <mmsystem.h>
#include <windows.h>

PTP_TIMER timerId;
HANDLE TimeEvent;
int late_ticks;

static DWORD posix_timer_time;
static DWORD offset_time;

#define TIME_INTERVAL 50
#define TIME_RESOLUTION 10
#define TIME_TIMEOUT 100

static PTP_TIMER g_timerId = NULL;
static PTP_CLEANUP_GROUP g_cleanupgroup = NULL;
static PTP_POOL g_pool = NULL;

VOID CALLBACK timerCb(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_TIMER Timer) {
	if (Timer == g_timerId) {
		SetEvent(TimeEvent);
		posix_timer_time += TIME_INTERVAL;
	}
}

void win_timer_init(void) {
	BOOL bRet = FALSE;
	PTP_WORK work = NULL;
	FILETIME FileDueTime;
	TP_CALLBACK_ENVIRON CallBackEnviron;

	InitializeThreadpoolEnvironment(&CallBackEnviron);
	g_pool = CreateThreadpool(NULL); // Create a custom, dedicated thread pool.
	if (NULL == g_pool) {
		ortp_warning("CreateThreadpool failed. LastError: %u\n", GetLastError());
		return;
	}
	SetThreadpoolThreadMaximum(g_pool, 1);        // The thread pool is made persistent simply by setting
	bRet = SetThreadpoolThreadMinimum(g_pool, 1); // both the minimum and maximum threads to 1.
	if (FALSE == bRet) {
		ortp_warning("SetThreadpoolThreadMinimum failed. LastError: %u\n", GetLastError());
		return;
	}
	g_cleanupgroup = CreateThreadpoolCleanupGroup(); // Create a cleanup group for this thread pool.
	if (NULL == g_cleanupgroup) {
		ortp_warning("CreateThreadpoolCleanupGroup failed. LastError: %u\n", GetLastError());
		return;
	}
	SetThreadpoolCallbackPool(&CallBackEnviron, g_pool); // Associate the callback environment with our thread pool.
	// Associate the cleanup group with our thread pool. Objects created with the same callback environment as the
	// cleanup group become members of the cleanup group.
	SetThreadpoolCallbackCleanupGroup(&CallBackEnviron, g_cleanupgroup, NULL);
	g_timerId =
	    CreateThreadpoolTimer(timerCb, NULL, &CallBackEnviron); // Create a timer with the same callback environment.
	if (NULL == g_timerId) {
		ortp_warning("CreateThreadpoolTimer failed. LastError: %u\n", GetLastError());
		return;
	}

	SYSTEMTIME thesystemtime;
	GetSystemTime(&thesystemtime);
	thesystemtime.wYear++;
	SystemTimeToFileTime(&thesystemtime, &FileDueTime);
	// ULARGE_INTEGER ulDueTime;
	// ulDueTime.QuadPart = (ULONGLONG)604800 * 10 * 1000 * 1000;
	// FileDueTime.dwHighDateTime = ulDueTime.HighPart;
	// FileDueTime.dwLowDateTime  = ulDueTime.LowPart;
	SetThreadpoolTimer(timerId, &FileDueTime, TIME_INTERVAL, 0);
	TimeEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	late_ticks = 0;
	offset_time = GetTickCount();
	posix_timer_time = 0;
}

void win_timer_do(void) {
	if (g_timerId) {
		DWORD diff;
		// If timer have expired while we where out of this method
		// Try to run after lost time.
		if (late_ticks > 0) {
			late_ticks--;
			posix_timer_time += TIME_INTERVAL;
			return;
		}
		diff = GetTickCount() - posix_timer_time - offset_time;
		if (diff > TIME_INTERVAL && (diff < (1 << 31))) {
			late_ticks = diff / TIME_INTERVAL;
			ortp_warning("we must catchup %i ticks.", late_ticks);
			return;
		}
		WaitForSingleObject(TimeEvent, TIME_TIMEOUT);
		return;
	}
}

void win_timer_close(void) {
	if (g_timerId != NULL) {
		SetThreadpoolTimer(g_timerId, NULL, 0, 0);
		CloseThreadpoolTimer(g_timerId);
		g_timerId = NULL;
	}
	if (g_cleanupgroup != NULL) { // Clean up the cleanup group members.
		CloseThreadpoolCleanupGroupMembers(g_cleanupgroup, FALSE, NULL);
		CloseThreadpoolCleanupGroup(g_cleanupgroup);
		g_cleanupgroup = NULL;
	}
	if (g_pool != NULL) { // Clean up the pool.
		CloseThreadpool(g_pool);
		g_pool = NULL;
	}
}

RtpTimer toto;

RtpTimer posix_timer = {0, win_timer_init, win_timer_do, win_timer_close, {0, TIME_INTERVAL * 1000}};

#elif defined ORTP_WINDOWS_DESKTOP

#include <mmsystem.h>
#include <windows.h>

MMRESULT timerId;
HANDLE TimeEvent;
int late_ticks;

static DWORD posix_timer_time;
static DWORD offset_time;

#define TIME_INTERVAL 50
#define TIME_RESOLUTION 10
#define TIME_TIMEOUT 100

void CALLBACK timerCb(UINT uID, UINT uMsg, DWORD_PTR dwUser, DWORD_PTR dw1, DWORD_PTR dw2) {
	// Check timerId
	if (timerId == uID) {
		SetEvent(TimeEvent);
		posix_timer_time += TIME_INTERVAL;
	}
}

void win_timer_init(void) {
	timerId = timeSetEvent(TIME_INTERVAL, 10, timerCb, (DWORD)0, (UINT)(TIME_PERIODIC | TIME_CALLBACK_FUNCTION));
	TimeEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	late_ticks = 0;

	offset_time = GetTickCount();
	posix_timer_time = 0;
}

void win_timer_do(void) {
	DWORD diff;

	// If timer have expired while we where out of this method
	// Try to run after lost time.
	if (late_ticks > 0) {
		late_ticks--;
		posix_timer_time += TIME_INTERVAL;
		return;
	}

	diff = GetTickCount() - posix_timer_time - offset_time;
	if (diff > TIME_INTERVAL && (diff < (1 << 31))) {
		late_ticks = diff / TIME_INTERVAL;
		ortp_warning("we must catchup %i ticks.", late_ticks);
		return;
	}

	WaitForSingleObject(TimeEvent, TIME_TIMEOUT);
	return;
}

void win_timer_close(void) {
	timeKillEvent(timerId);
}

RtpTimer toto;

RtpTimer posix_timer = {0, win_timer_init, win_timer_do, win_timer_close, {0, TIME_INTERVAL * 1000}};

#elif defined(ORTP_WINDOWS_PHONE)

#include "winrttimer.h"

RtpTimer posix_timer = {0, winrt_timer_init, winrt_timer_do, winrt_timer_close, {0, TIME_INTERVAL * 1000}};

#endif

#endif // _WIN32
