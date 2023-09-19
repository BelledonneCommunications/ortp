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
/* this file is responsible of the portability of the stack */

#ifndef ORTP_PORT_H
#define ORTP_PORT_H

#include "bctoolbox/port.h"

#ifndef ORTP_DEPRECATED
#if defined(_MSC_VER)
#define ORTP_DEPRECATED __declspec(deprecated)
#else
#define ORTP_DEPRECATED __attribute__((deprecated))
#endif // _MSC_VER
#endif // ORTP_DEPRECATED

#if __APPLE__
#include "TargetConditionals.h"
#endif

typedef bctbx_socket_t ortp_socket_t;
typedef bctbx_cond_t ortp_cond_t;
typedef bctbx_mutex_t ortp_mutex_t;
typedef bctbx_thread_t ortp_thread_t;

#define ortp_thread_create bctbx_thread_create
#define ortp_thread_join bctbx_thread_join
#define ortp_thread_self bctbx_thread_self
#define ortp_thread_exit(arg) bctbx_thread_exit
#define ortp_mutex_init bctbx_mutex_init
#define ortp_mutex_lock bctbx_mutex_lock
#define ortp_mutex_unlock bctbx_mutex_unlock
#define ortp_mutex_destroy bctbx_mutex_destroy
#define ortp_cond_init bctbx_cond_init
#define ortp_cond_signal bctbx_cond_signal
#define ortp_cond_broadcast bctbx_cond_broadcast
#define ortp_cond_wait bctbx_cond_wait
#define ortp_cond_destroy bctbx_cond_destroy

#if !defined(_WIN32) && !defined(_WIN32_WCE)
/********************************/
/* definitions for UNIX flavour */
/********************************/

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#include <stdint.h>
#endif

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#if defined(_XOPEN_SOURCE_EXTENDED) || !defined(__hpux)
#include <arpa/inet.h>
#endif

#include <sys/time.h>

#include <netdb.h>

#ifdef __INTEL_COMPILER

#pragma warning(disable : 111)  // statement is unreachable
#pragma warning(disable : 181)  // argument is incompatible with corresponding format string conversion
#pragma warning(disable : 188)  // enumerated type mixed with another type
#pragma warning(disable : 593)  // variable "xxx" was set but never used
#pragma warning(disable : 810)  // conversion from "int" to "unsigned short" may lose significant bits
#pragma warning(disable : 869)  // parameter "xxx" was never referenced
#pragma warning(disable : 981)  // operands are evaluated in unspecified order
#pragma warning(disable : 1418) // external function definition with no prior declaration
#pragma warning(disable : 1419) // external declaration in primary source file
#pragma warning(disable : 1469) // "cc" clobber ignored
#endif                          // __INTEL_COMPILER

#define ORTP_PUBLIC
#define ORTP_INLINE inline

#define SOCKET_OPTION_VALUE void *
#define SOCKET_BUFFER void *

#define ortp_log10f(x) log10f(x)

#else // !defined(_WIN32) && !defined(_WIN32_WCE)
/*********************************/
/* definitions for WIN32 flavour */
/*********************************/

#include <stdio.h>
#define _CRT_RAND_S
#include <stdarg.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef _MSC_VER
#include <io.h>
#endif // _MSC_VER

#if defined(__MINGW32__) || !defined(WINAPI_FAMILY_PARTITION) || !defined(WINAPI_PARTITION_DESKTOP)
#define ORTP_WINDOWS_DESKTOP 1
#elif defined(WINAPI_FAMILY_PARTITION)
// See bctoolbox/include/port.h for WINAPI_PARTITION checker
#if defined(WINAPI_PARTITION_DESKTOP) && WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
#define ORTP_WINDOWS_DESKTOP 1
#elif defined(WINAPI_PARTITION_PC_APP) && WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_PC_APP)
#define ORTP_WINDOWS_DESKTOP 1
#define ORTP_WINDOWS_UWP 1
#elif defined(WINAPI_PARTITION_PHONE_APP) && WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_PHONE_APP)
#define ORTP_WINDOWS_PHONE 1
#elif defined(WINAPI_PARTITION_APP) && WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_APP)
#define ORTP_WINDOWS_UNIVERSAL 1
#endif // defined(WINAPI_PARTITION_DESKTOP) && WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
#endif // defined(WINAPI_FAMILY_PARTITION)

#ifdef _MSC_VER
#ifdef ORTP_STATIC
#define ORTP_PUBLIC
#else
#ifdef ORTP_EXPORTS
#define ORTP_PUBLIC __declspec(dllexport)
#else
#define ORTP_PUBLIC __declspec(dllimport)
#endif
#endif
#pragma push_macro("_WINSOCKAPI_")
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

typedef unsigned __int64 uint64_t;
typedef __int64 int64_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned char uint8_t;
typedef __int16 int16_t;
#else // _MSC_VER
#include <io.h>
#include <stdint.h> /*provided by mingw32*/

#endif // _MSC_VER

#define SOCKET_OPTION_VALUE char *
#define SOCKET_BUFFER void *
#define ORTP_INLINE __inline

#if defined(_WIN32_WCE)

#define ortp_log10f(x) (float)log10((double)x)

#ifdef assert
#undef assert
#endif /*assert*/
#define assert(exp) ((void)0)

#ifdef errno
#undef errno
#endif /*errno*/
#define errno GetLastError()
#ifdef strerror
#undef strerror
#endif /*strerror*/
const char *ortp_strerror(DWORD value);
#define strerror ortp_strerror

#else /*_WIN32_WCE*/

#define ortp_log10f(x) log10f(x)

#endif // defined(_WIN32_WCE)

#ifdef __cplusplus
extern "C" {
#endif

#ifndef F_OK
#define F_OK 00 /* Visual Studio does not define F_OK */
#endif

#ifdef _WORKAROUND_MINGW32_BUGS
char *WSAAPI gai_strerror(int errnum);
#endif

#ifdef __cplusplus
}
#endif

#endif // _MSC_VER

#ifndef _BOOL_T_
#define _BOOL_T_
typedef unsigned char bool_t;
#endif /* _BOOL_T_ */
#undef TRUE
#undef FALSE
#define TRUE 1
#define FALSE 0

typedef struct bctoolboxTimeSpec ortpTimeSpec;

#ifdef __cplusplus
extern "C" {
#endif

#define ortp_malloc(sz) bctbx_malloc(sz)
#define ortp_free(ptr) bctbx_free(ptr)
#define ortp_realloc(ptr, sz) bctbx_realloc(ptr, sz)
#define ortp_malloc0(sz) bctbx_malloc0(sz)
#define ortp_strdup(str) bctbx_strdup(str)
#define ortp_strndup(str, n) bctbx_strndup(str, n)

#define ortp_new(type, count) (type *)ortp_malloc(sizeof(type) * (count))
#define ortp_new0(type, count) (type *)ortp_malloc0(sizeof(type) * (count))

ORTP_PUBLIC int close_socket(ortp_socket_t sock);
ORTP_PUBLIC int set_non_blocking_socket(ortp_socket_t sock);
ORTP_PUBLIC int set_blocking_socket(ortp_socket_t sock);

#define ortp_strdup_printf bctbx_strdup_printf
#define ortp_strdup_vprintf bctbx_strdup_vprintf
#define ortp_strcat_printf bctbx_strcat_printf
#define ortp_strcat_vprintf bctbx_strcat_vprintf

#define ortp_file_exist(pathname) bctbx_file_exist(pathname)

#define ortp_get_cur_time(ts) bctbx_get_cur_time(ts)
#define ortp_get_cur_time_ms(void) bctbx_get_cur_time_ms(void)
#define ortp_sleep_ms(ms) bctbx_sleep_ms(ms)
#define ortp_sleep_until(ts) bctbx_sleep_until(ts)
#define ortp_timespec_compare(t1, t2) bctbx_timespec_compare(t1, t2)
#define ortp_random(void) bctbx_random(void)

/* portable named pipes  and shared memory*/
#if !defined(_WIN32_WCE)
#ifdef _WIN32
typedef HANDLE ortp_pipe_t;
#define ORTP_PIPE_INVALID INVALID_HANDLE_VALUE
#else
typedef int ortp_pipe_t;
#define ORTP_PIPE_INVALID (-1)
#endif

#define ortp_server_pipe_create(name) bctbx_server_pipe_create(name)
/*
 * warning: on win32 ortp_server_pipe_accept_client() might return INVALID_HANDLE_VALUE without
 * any specific error, this happens when ortp_server_pipe_close() is called on another pipe.
 * This pipe api is not thread-safe.
 */
#define ortp_server_pipe_accept_client(server) bctbx_server_pipe_accept_client(server)

#define ortp_server_pipe_close(spipe) bctbx_server_pipe_close(spipe)
#define ortp_server_pipe_close_client(client) bctbx_server_pipe_close_client(client)

#define ortp_client_pipe_connect(name) bctbx_client_pipe_connect(name)
#define ortp_client_pipe_close(sock) bctbx_client_pipe_close(sock)

#define ortp_pipe_read(p, buf, len) bctbx_pipe_read(b, buf, len)
#define ortp_pipe_write(p, buf, len) bctbx_pipe_write(p, buf, len)

#define ortp_shm_open(keyid, size, create) bctbx_shm_open(keyid, size, create)
#define ortp_shm_close(keyid, size, create) bctbx_shm_close(keyid, size, create)

#define ortp_is_multicast_addr(addr) bctbx_is_multicast_addr(addr)

#endif

#ifdef __cplusplus
}
#endif

#if (defined(_WIN32) || defined(_WIN32_WCE)) && !defined(ORTP_STATIC)
#ifdef ORTP_EXPORTS
#define ORTP_VAR_PUBLIC extern __declspec(dllexport)
#else
#define ORTP_VAR_PUBLIC __declspec(dllimport)
#endif
#else
#define ORTP_VAR_PUBLIC extern
#endif

#ifndef IN6_IS_ADDR_MULTICAST
#define IN6_IS_ADDR_MULTICAST(i) (((uint8_t *)(i))[0] == 0xff)
#endif

/*define __ios when we are compiling for ios.
 The TARGET_OS_IPHONE macro is stupid, it is defined to 0 when compiling on mac os x.
*/
#if TARGET_OS_IPHONE
#define __ios 1
#endif

#endif // ORTP_PORT_H
