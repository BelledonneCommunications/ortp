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

#include "utils.h"
#include <ortp/rtpsession.h>

void rtp_signal_table_init(RtpSignalTable *table, RtpSession *session, const char *signal_name) {
	memset(table, 0, sizeof(RtpSignalTable));
	table->session = session;
	table->signal_name = signal_name;
	session->signal_tables = o_list_append(session->signal_tables, (void *)table);
	bctbx_mutex_init(&table->callback_mutex, NULL);
}

void rtp_signal_table_uninit(RtpSignalTable *table) {
	bctbx_mutex_destroy(&table->callback_mutex);
}

int rtp_signal_table_add(RtpSignalTable *table, RtpCallback cb, void *user_data) {
	return rtp_signal_table_add_from_source_session(table, cb, user_data, NULL);
}

int rtp_signal_table_add_from_source_session(RtpSignalTable *table,
                                             RtpCallback cb,
                                             void *user_data,
                                             const struct _RtpSession *source) {
	bctbx_mutex_lock(&table->callback_mutex);

	for (int i = 0; i < RTP_CALLBACK_TABLE_MAX_ENTRIES; i++) {
		if (table->callback[i].cb == NULL) {
			table->callback[i].cb = cb;
			table->callback[i].user_data = user_data;
			table->callback[i].source = source;
			table->count++;

			bctbx_mutex_unlock(&table->callback_mutex);
			return 0;
		}
	}

	bctbx_mutex_unlock(&table->callback_mutex);
	return -1;
}

void rtp_signal_table_emit(RtpSignalTable *table) {
	rtp_signal_table_emit3(table, NULL, NULL);
}

void rtp_signal_table_emit2(RtpSignalTable *table, void *arg) {
	rtp_signal_table_emit3(table, arg, NULL);
}

void rtp_signal_table_emit3(RtpSignalTable *table, void *arg1, void *arg2) {
	for (int i = 0, c = 0; c < table->count; i++) {
		bctbx_mutex_lock(&table->callback_mutex);
		if (table->callback[i].cb != NULL) {
			c++; /*I like it*/

			// Place the user_data at the right place depending on which emits has been called
			if (arg1 == NULL && arg2 == NULL) {
				table->callback[i].cb(table->session, table->callback[i].user_data, NULL, NULL);
			} else if (arg2 == NULL) {
				table->callback[i].cb(table->session, arg1, table->callback[i].user_data, NULL);
			} else {
				table->callback[i].cb(table->session, arg1, arg2, table->callback[i].user_data);
			}
		}
		bctbx_mutex_unlock(&table->callback_mutex);
	}
}

int rtp_signal_table_remove_by_callback(RtpSignalTable *table, RtpCallback cb) {
	return rtp_signal_table_remove_by_callback_and_user_data(table, cb, NULL);
}

int rtp_signal_table_remove_by_callback_and_user_data(RtpSignalTable *table, RtpCallback cb, void *user_data) {
	bctbx_mutex_lock(&table->callback_mutex);

	for (int i = 0; i < RTP_CALLBACK_TABLE_MAX_ENTRIES; i++) {
		if (table->callback[i].cb == cb) {
			if (user_data == NULL || user_data == table->callback[i].user_data) {
				table->callback[i].cb = NULL;
				table->callback[i].user_data = NULL;
				table->callback[i].source = NULL;
				table->count--;

				bctbx_mutex_unlock(&table->callback_mutex);
				return 0;
			}
		}
	}

	bctbx_mutex_unlock(&table->callback_mutex);
	return -1;
}

int rtp_signal_table_remove_by_source_session(RtpSignalTable *table, const RtpSession *session) {
	bctbx_mutex_lock(&table->callback_mutex);

	for (int i = 0; i < RTP_CALLBACK_TABLE_MAX_ENTRIES; i++) {
		if (table->callback[i].source == session) {
			table->callback[i].cb = NULL;
			table->callback[i].user_data = NULL;
			table->callback[i].source = NULL;
			table->count--;

			bctbx_mutex_unlock(&table->callback_mutex);
			return 0;
		}
	}

	bctbx_mutex_unlock(&table->callback_mutex);
	return -1;
}
