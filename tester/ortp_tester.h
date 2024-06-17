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

#ifndef _ORTP_TESTER_H
#define _ORTP_TESTER_H

#include <bctoolbox/tester.h>

#include <ortp/ortp.h>

#ifdef HAVE_CONFIG_H
#include "ortp-config.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern test_suite_t extension_header_test_suite;
extern test_suite_t fec_test_suite;
extern test_suite_t rtp_test_suite;
extern test_suite_t bundle_test_suite;

void ortp_tester_init(void (*ftester_printf)(int level, const char *fmt, va_list args));
void ortp_tester_uninit(void);

#ifdef __cplusplus
}
#endif

#endif
