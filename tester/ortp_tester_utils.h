/*
 * Copyright (c) 2010-2023 Belledonne Communications SARL.
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

#ifndef ORTP_TESTER_UTILS_H
#define ORTP_TESTER_UTILS_H

#include "ortp/ortp.h"

#ifdef __cplusplus
extern "C" {
#endif

bool_t ortp_tester_is_executable_installed(const char *executable, const char *resource);

mblk_t *ortp_tester_make_dummy_rtcp_fb_pli(RtpSession *session, uint32_t sender_ssrc, uint32_t media_ssrc);

#ifdef __cplusplus
}
#endif

#endif // ORTP_TESTER_UTILS_H
