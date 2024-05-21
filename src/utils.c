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
