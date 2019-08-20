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


#include "../rtptimer.h"
#include <stdio.h>

int main(int argc, char *argv[])
{
	RtpTimer *timer=&posix_timer;
	int i;
	struct timeval interval;
	
	interval.tv_sec=0;
	interval.tv_usec=500000;
	
	rtp_timer_set_interval(timer,&interval);
	
	timer->timer_init();
	for (i=0;i<10;i++)
	{
		printf("doing something...\n");
		timer->timer_do();
	}
	timer->timer_uninit();
	return 0;
}
