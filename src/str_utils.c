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

#include <bctoolbox/defs.h>

#ifdef HAVE_CONFIG_H
#include "ortp-config.h"
#endif

#include "ortp/ortp.h"
#include "ortp/str_utils.h"
#include "utils.h"

void qinit(queue_t *q) {
	mblk_init(&q->_q_stopper);
	q->_q_stopper.b_next = &q->_q_stopper;
	q->_q_stopper.b_prev = &q->_q_stopper;
	q->q_mcount = 0;
}

void mblk_init(mblk_t *mp) {
	memset(mp, 0, sizeof(mblk_t));
}

void mblk_meta_copy(const mblk_t *source, mblk_t *dest) {
	dest->reserved1 = source->reserved1;
	dest->reserved2 = source->reserved2;
	memcpy(&dest->net_addr, &source->net_addr, source->net_addrlen);
	dest->net_addrlen = source->net_addrlen;
	dest->timestamp = source->timestamp;
	dest->ttl_or_hl = source->ttl_or_hl;
}

unsigned char *dblk_base(dblk_t *db) {
	return db->db_base;
}

unsigned char *dblk_lim(dblk_t *db) {
	return db->db_lim;
}

mblk_t *allocb(size_t size, BCTBX_UNUSED(int pri)) {
	mblk_t *mp;
	dblk_t *datab;

	mp = (mblk_t *)ortp_malloc0(sizeof(mblk_t));
	datab = dblk_alloc(size);

	mp->b_datap = datab;
	mp->b_rptr = mp->b_wptr = datab->db_base;
	mp->b_next = mp->b_prev = mp->b_cont = NULL;
	return mp;
}

mblk_t *esballoc(uint8_t *buf, size_t size, BCTBX_UNUSED(int pri), void (*freefn)(void *)) {
	mblk_t *mp;
	dblk_t *datab;

	mp = (mblk_t *)ortp_malloc0(sizeof(mblk_t));
	datab = dblk_alloc2(buf, size, freefn);

	mp->b_datap = datab;
	mp->b_rptr = mp->b_wptr = buf;
	mp->b_next = mp->b_prev = mp->b_cont = NULL;
	return mp;
}

void freeb(mblk_t *mp) {
	return_if_fail(mp->b_datap != NULL);
	return_if_fail(mp->b_datap->db_base != NULL);

	dblk_unref(mp->b_datap);
	ortp_free(mp);
}

void freemsg(mblk_t *mp) {
	mblk_t *tmp1, *tmp2;
	tmp1 = mp;
	while (tmp1 != NULL) {
		tmp2 = tmp1->b_cont;
		freeb(tmp1);
		tmp1 = tmp2;
	}
}

mblk_t *dupb(mblk_t *mp) {
	mblk_t *newm;
	return_val_if_fail(mp->b_datap != NULL, NULL);
	return_val_if_fail(mp->b_datap->db_base != NULL, NULL);

	dblk_ref(mp->b_datap);
	newm = (mblk_t *)ortp_malloc0(sizeof(mblk_t));
	mblk_meta_copy(mp, newm);
	newm->b_datap = mp->b_datap;
	newm->b_rptr = mp->b_rptr;
	newm->b_wptr = mp->b_wptr;
	return newm;
}

/* duplicates a complex mblk_t */
mblk_t *dupmsg(mblk_t *m) {
	mblk_t *newm = NULL, *mp, *prev;
	prev = newm = dupb(m);
	m = m->b_cont;
	while (m != NULL) {
		mp = dupb(m);
		prev->b_cont = mp;
		prev = mp;
		m = m->b_cont;
	}
	return newm;
}

void putq(queue_t *q, mblk_t *mp) {
	q->_q_stopper.b_prev->b_next = mp;
	mp->b_prev = q->_q_stopper.b_prev;
	mp->b_next = &q->_q_stopper;
	q->_q_stopper.b_prev = mp;
	q->q_mcount++;
}

mblk_t *getq(queue_t *q) {
	mblk_t *tmp;
	tmp = q->_q_stopper.b_next;
	if (tmp == &q->_q_stopper) return NULL;
	q->_q_stopper.b_next = tmp->b_next;
	tmp->b_next->b_prev = &q->_q_stopper;
	tmp->b_prev = NULL;
	tmp->b_next = NULL;
	q->q_mcount--;
	return tmp;
}

mblk_t *peekq(queue_t *q) {
	mblk_t *tmp;
	tmp = q->_q_stopper.b_next;
	if (tmp == &q->_q_stopper) return NULL;
	return tmp;
}

/* insert mp in q just before emp */
void insq(queue_t *q, mblk_t *emp, mblk_t *mp) {
	if (emp == NULL) {
		putq(q, mp);
		return;
	}
	q->q_mcount++;
	emp->b_prev->b_next = mp;
	mp->b_prev = emp->b_prev;
	emp->b_prev = mp;
	mp->b_next = emp;
}

void remq(queue_t *q, mblk_t *mp) {
	q->q_mcount--;
	mp->b_prev->b_next = mp->b_next;
	mp->b_next->b_prev = mp->b_prev;
	mp->b_next = NULL;
	mp->b_prev = NULL;
}

/* remove and free all messages in the q */
void flushq(queue_t *q, BCTBX_UNUSED(int how)) {
	mblk_t *mp;

	while ((mp = getq(q)) != NULL) {
		freemsg(mp);
	}
}

size_t msgdsize(const mblk_t *mp) {
	size_t msgsize = 0;
	while (mp != NULL) {
		msgsize += (size_t)(mp->b_wptr - mp->b_rptr);
		mp = mp->b_cont;
	}
	return msgsize;
}

void msgpullup(mblk_t *mp, size_t len) {
	mblk_t *firstm = mp;
	dblk_t *db;
	size_t wlen = 0;
	unsigned char *base;

	if (mp->b_cont == NULL) {
		/* Special case optimisations */
		if (len == (size_t)-1) return; /*nothing to do, message is not fragmented. */
		if (mp->b_datap->db_base + len <= mp->b_datap->db_lim) {
			/* The underlying data block is larger than the requested size, nothing to do. */
			return;
		}
	}

	if (len == (size_t)-1) len = msgdsize(mp);
	db = dblk_alloc(len);
	base = db->db_base;
	while (wlen < len && mp != NULL) {
		int remain = (int)(len - wlen);
		int mlen = (int)(mp->b_wptr - mp->b_rptr);
		if (mlen <= remain) {
			memcpy(&base[wlen], mp->b_rptr, mlen);
			wlen += mlen;
			mp = mp->b_cont;
		} else {
			memcpy(&base[wlen], mp->b_rptr, remain);
			wlen += remain;
		}
	}
	/*set firstm to point to the new datab */
	freemsg(firstm->b_cont);
	firstm->b_cont = NULL;
	dblk_unref(firstm->b_datap);
	firstm->b_datap = db;
	firstm->b_rptr = db->db_base;
	firstm->b_wptr = firstm->b_rptr + wlen;
}

/* pullup message but insert an insert_size zeroised buffer at offset */
/* final size will be current size + insert size
 * b->w_bptr is set at the end of the message even if the insertion if performed at the end of the message */
void msgpullup_with_insert(mblk_t *mp, size_t offset, size_t insert_size) {
	mblk_t *firstm = mp;
	dblk_t *db;
	size_t wlen = 0;
	size_t len = msgdsize(mp);
	if (offset >= len) {
		msgpullup(mp, len + insert_size); /* we want to insert it at the end, that's what regular pullup does */
		mp->b_wptr += offset - len + insert_size;
		return;
	}

	len += insert_size;
	db = dblk_alloc(len);

	while (mp != NULL) { /* copy the whole original content, we do not crop as in regular pullup */
		int mlen = (int)(mp->b_wptr - mp->b_rptr);
		if (wlen + mlen <= offset ||
		    wlen > offset) { /* this whole chunk fit before the blank insert or we already made the insert */
			memcpy(&db->db_base[wlen], mp->b_rptr, mlen);
			wlen += mlen;
		} else {
			/* split this chunk */
			memcpy(&db->db_base[wlen], mp->b_rptr, offset - wlen); /* write up to offset */
			memset(&db->db_base[offset], 0, insert_size);          /* zeroise the inserted part */
			memcpy(&db->db_base[offset + insert_size], mp->b_rptr + offset - wlen,
			       wlen + mlen - offset); /* copy the rest of this chunk */
			wlen += mlen + insert_size;
		}
		mp = mp->b_cont;
	}

	freemsg(firstm->b_cont);
	firstm->b_cont = NULL;
	dblk_unref(firstm->b_datap);
	firstm->b_datap = db;
	firstm->b_rptr = db->db_base;
	firstm->b_wptr = firstm->b_rptr + wlen;
}

mblk_t *copyb(const mblk_t *mp) {
	mblk_t *newm;
	int len = (int)(mp->b_wptr - mp->b_rptr);
	newm = allocb(len, BPRI_MED);
	memcpy(newm->b_wptr, mp->b_rptr, len);
	newm->b_wptr += len;
	memcpy(&newm->recv_addr, &mp->recv_addr, sizeof(newm->recv_addr));
	return newm;
}

mblk_t *copymsg(const mblk_t *mp) {
	mblk_t *newm = 0, *m;
	m = newm = copyb(mp);
	mp = mp->b_cont;
	while (mp != NULL) {
		m->b_cont = copyb(mp);
		m = m->b_cont;
		mp = mp->b_cont;
	}
	return newm;
}

mblk_t *appendb(mblk_t *mp, const char *data, size_t size, bool_t pad) {
	size_t padcnt = 0;
	size_t i;
	unsigned char *lim;
	if (pad) {
		padcnt = (size_t)(4 - ((((intptr_t)mp->b_wptr) + size) % 4)) % 4;
	}
	lim = mp->b_datap->db_lim;
	if ((mp->b_wptr + size + padcnt) > lim) {
		/* buffer is not large enough: append a new block (with the same size ?)*/
		size_t plen = (size_t)((char *)lim - (char *)mp->b_datap->db_base);
		mp->b_cont = allocb(MAX(plen, size), 0);
		mp = mp->b_cont;
	}
	if (size) memcpy(mp->b_wptr, data, size);
	mp->b_wptr += size;
	for (i = 0; i < padcnt; i++) {
		mp->b_wptr[0] = 0;
		mp->b_wptr++;
	}
	return mp;
}

void msgappend(mblk_t *mp, const char *data, size_t size, bool_t pad) {
	while (mp->b_cont != NULL)
		mp = mp->b_cont;
	appendb(mp, data, size, pad);
}

mblk_t *concatb(mblk_t *mp, mblk_t *newm) {
	while (mp->b_cont != NULL)
		mp = mp->b_cont;
	mp->b_cont = newm;
	while (newm->b_cont != NULL)
		newm = newm->b_cont;
	return newm;
}

void msgb_allocator_init(msgb_allocator_t *a) {
	qinit(&a->q);
	a->max_blocks = 0; /* no limit */
}

void msgb_allocator_set_max_blocks(msgb_allocator_t *pa, int max_blocks) {
	pa->max_blocks = max_blocks;
}

static void msgb_allocator_free_db(BCTBX_UNUSED(void *unused)) {
}

mblk_t *msgb_allocator_alloc(msgb_allocator_t *a, size_t size) {
	queue_t *q = &a->q;
	mblk_t *m, *found = NULL;
	int busy_blocks = 0;

	/*lookup for an unused msgb (data block with ref count ==1)*/
	for (m = qbegin(q); !qend(q, m); m = qnext(q, m)) {
		if ((size_t)(m->b_datap->db_lim - m->b_datap->db_base) >= size) {
			if (dblk_ref_value(m->b_datap) == 1) {
				found = m;
				break;
			} else {
				busy_blocks++;
			}
		}
	}
	if (a->max_blocks != 0 && busy_blocks >= a->max_blocks) {
		return NULL;
	}
	if (found == NULL) {
		found = allocb(size, 0);
		/*Hack: we put a special freefn impletation to be able to recognize mblk_t allocated by the msgb_allocator_t */
		found->b_datap->db_freefn = msgb_allocator_free_db;
		putq(q, found);
	}
	return dupb(found);
}

void msgb_allocator_uninit(msgb_allocator_t *a) {
	flushq(&a->q, -1);
}

/*Same as ownb(), but invoke it for each mblk_t of the chain*/
mblk_t *msgown(mblk_t *mp) {
	int single_owner_ref = (mp->b_datap->db_freefn == msgb_allocator_free_db) ? 2 : 1;

	if (dblk_ref_value(mp->b_datap) > single_owner_ref) {
		// ortp_message("msgown(): datab copied db_ref=%i  single_owner_ref=%i", dblk_ref_value(mp->b_datap),
		// single_owner_ref);
		msgpullup(mp, msgdsize(mp));
	}
	return mp;
}

void ortp_recvaddr_to_sockaddr(ortp_recv_addr_t *recvaddr, struct sockaddr *addr, socklen_t *socklen) {
	if (recvaddr->family == AF_INET) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
		addr_in->sin_family = AF_INET;
		addr_in->sin_addr = recvaddr->addr.ipi_addr;
		addr_in->sin_port = recvaddr->port;
		*socklen = sizeof(struct sockaddr_in);
	} else if (recvaddr->family == AF_INET6) {
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
		addr_in6->sin6_family = AF_INET6;
		addr_in6->sin6_port = recvaddr->port;
		memcpy(&addr_in6->sin6_addr, &recvaddr->addr.ipi6_addr, sizeof(recvaddr->addr.ipi6_addr));
		*socklen = sizeof(struct sockaddr_in6);
	} else {
		*socklen = 0;
	}
}
void ortp_sockaddr_to_recvaddr(const struct sockaddr *addr, ortp_recv_addr_t *recvaddr) {
	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
		recvaddr->family = AF_INET;
		recvaddr->port = addr_in->sin_port;
		recvaddr->addr.ipi_addr = addr_in->sin_addr;
	} else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
		recvaddr->family = AF_INET6;
		recvaddr->port = addr_in6->sin6_port;
		memcpy(&recvaddr->addr.ipi6_addr, &addr_in6->sin6_addr, sizeof(addr_in6->sin6_addr));
	}
}
