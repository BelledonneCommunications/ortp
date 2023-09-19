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
#include "bctoolbox/charconv.h"
#include "bctoolbox/port.h"
#include "ortp/logging.h"
#include "ortp/port.h"
#include "ortp/str_utils.h"
#include "utils.h"

#if defined(_WIN32) && !defined(_WIN32_WCE)
#include <process.h>
#endif

/*
 * this method is an utility method that calls fnctl() on UNIX or
 * ioctlsocket on Win32.
 * int retrun the result of the system method
 */
int set_non_blocking_socket(ortp_socket_t sock) {
#if !defined(_WIN32) && !defined(_WIN32_WCE)
	return fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK);
#else
	unsigned long nonBlock = 1;
	return ioctlsocket(sock, FIONBIO, &nonBlock);
#endif
}

/*
 * this method is an utility method that calls fnctl() on UNIX or
 * ioctlsocket on Win32.
 * int retrun the result of the system method
 */
int set_blocking_socket(ortp_socket_t sock) {
#if !defined(_WIN32) && !defined(_WIN32_WCE)
	return fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) & ~O_NONBLOCK);
#else
	unsigned long nonBlock = 0;
	return ioctlsocket(sock, FIONBIO, &nonBlock);
#endif
}

/*
 * this method is an utility method that calls close() on UNIX or
 * closesocket on Win32.
 * int retrun the result of the system method
 */
int close_socket(ortp_socket_t sock) {
#if !defined(_WIN32) && !defined(_WIN32_WCE)
	return close(sock);
#else
	return closesocket(sock);
#endif
}

#ifdef _WORKAROUND_MINGW32_BUGS
char *WSAAPI gai_strerror(int errnum) {
	return (char *)getSocketErrorWithCode(errnum);
}
#endif
