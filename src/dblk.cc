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
#include <atomic>
#include <ortp/port.h>
#include <ortp/str_utils.h>

using namespace std;

extern "C" {
dblk_t *dblk_alloc(size_t size) {
	struct datab *db;
	size_t total_size = sizeof(struct datab) + size;
	db = (struct datab *)ortp_malloc(total_size);

	db->db_base = (uint8_t *)db + sizeof(struct datab);
	db->db_lim = db->db_base + size;
	db->db_ref = new atomic_int(1);
	db->db_freefn = NULL; /* the buffer pointed by db_base must never be freed !*/

	return db;
}
struct datab *dblk_alloc2(uint8_t *buf, size_t size, void (*freefn)(void *)) {
	struct datab *db;
	db = (struct datab *)ortp_malloc(sizeof(struct datab));

	db->db_base = buf;
	db->db_lim = buf + size;
	db->db_ref = new atomic_int(1);
	db->db_freefn = freefn;

	return db;
}

void dblk_ref(struct datab *data) {
	atomic_fetch_add_explicit(static_cast<atomic_int *>(data->db_ref), 1, memory_order_relaxed);
}

void dblk_unref(struct datab *data) {
	atomic_int previous_ref(
	    atomic_fetch_sub_explicit(static_cast<atomic_int *>(data->db_ref), 1, memory_order_release));
	if (previous_ref == 1) {
		if (data->db_freefn != NULL) data->db_freefn(data->db_base);
		delete static_cast<atomic_int *>(data->db_ref);
		data->db_ref = NULL;
		ortp_free(data);
	}
}

int dblk_ref_value(dblk_t *db) {
	return (int)static_cast<atomic_int *>(db->db_ref)->load();
}

} // extern "C"