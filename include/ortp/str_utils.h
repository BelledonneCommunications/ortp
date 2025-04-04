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

#ifndef STR_UTILS_H
#define STR_UTILS_H

#include <ortp/port.h>
#if defined(ORTP_TIMESTAMP)
#include <time.h>
#endif

#ifndef MIN
#define MIN(a, b) (((a) > (b)) ? (b) : (a))
#endif
#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define return_if_fail(expr)                                                                                           \
	if (!(expr)) {                                                                                                     \
		printf("%s:%i- assertion" #expr "failed\n", __FILE__, __LINE__);                                               \
		return;                                                                                                        \
	}
#define return_val_if_fail(expr, ret)                                                                                  \
	if (!(expr)) {                                                                                                     \
		printf("%s:%i- assertion" #expr "failed\n", __FILE__, __LINE__);                                               \
		return (ret);                                                                                                  \
	}

typedef struct ortp_recv_addr {
	int family;
	union {
		struct in_addr ipi_addr;
		struct in6_addr ipi6_addr;
	} addr;
	unsigned short port;
} ortp_recv_addr_t;

typedef struct ortp_recv_addr_map {
	struct sockaddr_storage ss;
	ortp_recv_addr_t recv_addr;
	uint64_t ts;
} ortp_recv_addr_map_t;

typedef struct msgb {
	struct msgb *b_prev;
	struct msgb *b_next;
	struct msgb *b_cont;
	struct datab *b_datap;
	unsigned char *b_rptr;
	unsigned char *b_wptr;
	uint32_t reserved1;
	uint32_t reserved2;
	struct timeval timestamp;
	ortp_recv_addr_t recv_addr;       /*contains the destination address of incoming packets, used for ICE processing*/
	struct sockaddr_storage net_addr; /*source address of incoming packet, or dest address of outgoing packet, used only
	                                     by simulator and modifiers*/
	socklen_t
	    net_addrlen; /*source (dest) address of incoming (outgoing) packet length used by simulator and modifiers*/
	uint8_t ttl_or_hl;
} mblk_t;

// Data Block
typedef struct datab {
	unsigned char *db_base;
	unsigned char *db_lim;
	void (*db_freefn)(void *);
	void *db_ref; // Atomic variable
} dblk_t;

typedef struct _queue {
	mblk_t _q_stopper;
	int q_mcount; /*number of packet in the q */
} queue_t;

#ifdef __cplusplus
extern "C" {
#endif

ORTP_PUBLIC dblk_t *dblk_alloc(size_t size);
ORTP_PUBLIC dblk_t *dblk_alloc2(uint8_t *buf, size_t size, void (*freefn)(void *));
ORTP_PUBLIC void dblk_ref(dblk_t *d);
ORTP_PUBLIC void dblk_unref(dblk_t *d);
ORTP_PUBLIC int dblk_ref_value(dblk_t *db);
ORTP_PUBLIC unsigned char *dblk_base(dblk_t *db);
ORTP_PUBLIC unsigned char *dblk_lim(dblk_t *db);

ORTP_PUBLIC void qinit(queue_t *q);

ORTP_PUBLIC void putq(queue_t *q, mblk_t *m);

ORTP_PUBLIC mblk_t *getq(queue_t *q);

ORTP_PUBLIC void insq(queue_t *q, mblk_t *emp, mblk_t *mp);

ORTP_PUBLIC void remq(queue_t *q, mblk_t *mp);

ORTP_PUBLIC mblk_t *peekq(queue_t *q);

/* remove and free all messages in the q */
#define FLUSHALL 0
ORTP_PUBLIC void flushq(queue_t *q, int how);

ORTP_PUBLIC void mblk_init(mblk_t *mp);

ORTP_PUBLIC void mblk_meta_copy(const mblk_t *source, mblk_t *dest);

/* allocates a mblk_t, that points to a datab_t, that points to a buffer of size size. */
ORTP_PUBLIC mblk_t *allocb(size_t size, int unused);
#define BPRI_MED 0

/* allocates a mblk_t, that points to a datab_t, that points to buf; buf will be freed using freefn */
ORTP_PUBLIC mblk_t *esballoc(uint8_t *buf, size_t size, int pri, void (*freefn)(void *));

/* frees a mblk_t, and if the datab ref_count is 0, frees it and the buffer too */
ORTP_PUBLIC void freeb(mblk_t *m);

/* frees recursively (follow b_cont) a mblk_t, and if the datab
ref_count is 0, frees it and the buffer too */
ORTP_PUBLIC void freemsg(mblk_t *mp);

/* duplicates a mblk_t , buffer is not duplicated*/
ORTP_PUBLIC mblk_t *dupb(mblk_t *m);

/* duplicates a complex mblk_t, buffer is not duplicated */
ORTP_PUBLIC mblk_t *dupmsg(mblk_t *m);

/* returns the size of data of a message */
ORTP_PUBLIC size_t msgdsize(const mblk_t *mp);

/* concatenates all fragment of a complex message and crop or extend the buffer to the given length */
ORTP_PUBLIC void msgpullup(mblk_t *mp, size_t len);

/* concatenates all fragment of a complex message and insert an empty buffer of the given length at the given offset */
ORTP_PUBLIC void msgpullup_with_insert(mblk_t *mp, size_t offset, size_t len);

/* duplicates a single message, but with buffer included */
ORTP_PUBLIC mblk_t *copyb(const mblk_t *mp);

/* duplicates a complex message with buffer included */
ORTP_PUBLIC mblk_t *copymsg(const mblk_t *mp);

ORTP_PUBLIC mblk_t *appendb(mblk_t *mp, const char *data, size_t size, bool_t pad);
ORTP_PUBLIC void msgappend(mblk_t *mp, const char *data, size_t size, bool_t pad);

ORTP_PUBLIC mblk_t *concatb(mblk_t *mp, mblk_t *newm);

/*Make sure the message has a unique owner, if not duplicate the underlying data buffer so that it can be changed
 without impacting others. Note that in case of copy, the message will be un-fragmented, exactly the way msgpullup()
 does. Always returns mp.*/
ORTP_PUBLIC mblk_t *msgown(mblk_t *mp);

#define qempty(q) (&(q)->_q_stopper == (q)->_q_stopper.b_next)
#define qfirst(q) ((q)->_q_stopper.b_next != &(q)->_q_stopper ? (q)->_q_stopper.b_next : NULL)
#define qbegin(q) ((q)->_q_stopper.b_next)
#define qlast(q) ((q)->_q_stopper.b_prev != &(q)->_q_stopper ? (q)->_q_stopper.b_prev : NULL)
#define qend(q, mp) ((mp) == &(q)->_q_stopper)
#define qnext(q, mp) ((mp)->b_next)

typedef struct _msgb_allocator {
	queue_t q;
	int max_blocks;
} msgb_allocator_t;

ORTP_PUBLIC void msgb_allocator_init(msgb_allocator_t *pa);
/* Set a maximum number of blocks that can be managed by the allocator.
   Only blocks satisfying the "size" argument of msgb_allocator_alloc() are counted.*/
ORTP_PUBLIC void msgb_allocator_set_max_blocks(msgb_allocator_t *pa, int max_blocks);
ORTP_PUBLIC mblk_t *msgb_allocator_alloc(msgb_allocator_t *pa, size_t size);
ORTP_PUBLIC void msgb_allocator_uninit(msgb_allocator_t *pa);

ORTP_PUBLIC void ortp_recvaddr_to_sockaddr(ortp_recv_addr_t *recvaddr, struct sockaddr *addr, socklen_t *socklen);
ORTP_PUBLIC void ortp_sockaddr_to_recvaddr(const struct sockaddr *addr, ortp_recv_addr_t *recvaddr);

/* API to store retrieve a sequence number, payload type, ekt tag flag and netsim rtp flag in the packet
 * These informations are used by double encryption to store the original seqnum/pt in the paquet
 * and allows ms2 to force the full ekt on specific video frames.
 *
 * The information is stored in reserved1. reserved1 is also used by netsim. The mapping is:
 * 32        24          16          8         1
 * | RuuuuuuE |   PType  |    Sequence number  |
 * With u unused, R netsim RTP flag, E force EKT tag flag
 * reserved1 is "locked" by the seqnum/pt from the begining of rtp_session_send_with_ts
 * until all the modifiers are passed (SRTP needs this info and is the last modifier) */
#define ortp_mblk_set_original_seqnum(m, seqnum) (m)->reserved1 = ((m)->reserved1 & 0xFFFF0000) | (seqnum & 0x0000FFFF)
#define ortp_mblk_get_original_seqnum(m) (((m)->reserved1) & 0x0000FFFF)

#define ortp_mblk_set_original_pt(m, pt) (m)->reserved1 = ((m)->reserved1 & 0xFF00FFFF) | ((pt & 0x000000FF) << 16)
#define ortp_mblk_get_original_pt(m) ((((m)->reserved1) & 0x00FF0000) >> 16)

#define ortp_mblk_set_ekt_tag_flag(m, f) (m)->reserved1 = ((m)->reserved1 & 0xFEFFFFFF) | ((f & 0x00000001) << 24)
#define ortp_mblk_get_ekt_tag_flag(m) ((((m)->reserved1) & 0x01000000) >> 24)

#define ortp_mblk_set_netsim_is_rtp_flag(m, f) (m)->reserved1 = ((m)->reserved1 & 0x7FFFFFFF) | ((f & 0x00000001) << 31)
#define ortp_mblk_get_netsim_is_rtp_flag(m) ((((m)->reserved1) & 0x80000000) >> 31)
#ifdef __cplusplus
}
#endif

#endif
