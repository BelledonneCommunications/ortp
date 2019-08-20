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
#include <windows.h>

#include "winrttimer.h"
#include "ortp/logging.h"

#ifndef ORTP_WINDOWS_DESKTOP

#ifdef ORTP_WINDOWS_PHONE
#using <Windows.winmd>
#endif

using namespace Windows::Foundation;
using namespace Windows::System::Threading;

class WinRTTimer
{
public:
	WinRTTimer();
	~WinRTTimer();
	void run();
private:
	ThreadPoolTimer^ PeriodicTimer;
	HANDLE SleepEvent;
	ULONGLONG LateTicks;
	ULONGLONG PosixTimerTime;
	ULONGLONG OffsetTime;
};


WinRTTimer::WinRTTimer()
	: LateTicks(0), PosixTimerTime(0), OffsetTime(GetTickCount64())
{
	TimeSpan period;
	period.Duration = TIME_INTERVAL * 10000;
	SleepEvent = CreateEventEx(NULL, NULL, CREATE_EVENT_MANUAL_RESET, EVENT_ALL_ACCESS);
	PeriodicTimer = ThreadPoolTimer::CreatePeriodicTimer(
		ref new TimerElapsedHandler([this](ThreadPoolTimer^ source)
		{
			if (source == PeriodicTimer) {
				PosixTimerTime += TIME_INTERVAL;
			}
		}), period);
}

WinRTTimer::~WinRTTimer()
{
	PeriodicTimer->Cancel();
}

void WinRTTimer::run()
{
	// If timer have expired while we where out of this method
	// Try to run after lost time.
	if (LateTicks > 0) {
		LateTicks--;
		PosixTimerTime += TIME_INTERVAL;
		return;
	}

	ULONGLONG diff = GetTickCount64() - PosixTimerTime - OffsetTime;
	if (diff > TIME_INTERVAL) {
		LateTicks = diff / TIME_INTERVAL;
		ortp_warning("We must catchup %i ticks.", LateTicks);
		return;
	}

	WaitForSingleObjectEx(SleepEvent, TIME_TIMEOUT, FALSE);
}

static WinRTTimer *timer;

void winrt_timer_init(void)
{
	timer = new WinRTTimer();
}

void winrt_timer_do(void)
{
	timer->run();
}

void winrt_timer_close(void)
{
	delete timer;
}

#endif
