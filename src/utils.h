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

#ifndef UTILS_H
#define UTILS_H

#include "ortp/event.h"
#include "ortp/rtpsession.h"
#if HAVE_STDATOMIC_H
#include <stdatomic.h>
#endif

void ortp_init_logger(void);
void ortp_uninit_logger(void);

struct datab {
	unsigned char *db_base;
	unsigned char *db_lim;
	void (*db_freefn)(void*);
#if HAVE_STDATOMIC_H
	atomic_int db_ref;
#else
	int db_ref;
#endif
};

#define OList bctbx_list_t


#define o_list_next(elem) ((elem)->next)
#define o_list_prev(elem) ((elem)->prev)

#define o_list_append bctbx_list_append
#define o_list_prepend bctbx_list_prepend
#define o_list_remove bctbx_list_remove
#define o_list_free bctbx_list_free
#define o_list_remove_link bctbx_list_erase_link
#define o_list_free_with_data bctbx_list_free_with_data


#define ORTP_POINTER_TO_INT(p) ((int)(intptr_t)(p))
#define ORTP_INT_TO_POINTER(i) ((void *)(intptr_t)(i))


typedef struct _dwsplit_t{
#ifdef ORTP_BIGENDIAN
	uint16_t hi;
	uint16_t lo;
#else
	uint16_t lo;
	uint16_t hi;
#endif
} dwsplit_t;

typedef union{
	dwsplit_t split;
	uint32_t one;
} poly32_t;

#ifdef ORTP_BIGENDIAN
#define hton24(x) (x)
#else
#define hton24(x) ((( (x) & 0x00ff0000) >>16) | (( (x) & 0x000000ff) <<16) | ( (x) & 0x0000ff00) )
#endif
#define ntoh24(x) hton24(x)

#if defined(_WIN32) || defined(_WIN32_WCE)
#define is_would_block_error(errnum)	(errnum==WSAEWOULDBLOCK)
#else
#define is_would_block_error(errnum)	(errnum==EWOULDBLOCK || errnum==EAGAIN)
#endif

void ortp_ev_queue_put(OrtpEvQueue *q, OrtpEvent *ev);

uint64_t ortp_timeval_to_ntp(const struct timeval *tv);

int _ortp_sendto(ortp_socket_t sockfd, mblk_t *m, int flags, const struct sockaddr *destaddr, socklen_t destlen);
void _rtp_session_release_sockets(RtpSession *session, bool_t release_transports);
#endif
