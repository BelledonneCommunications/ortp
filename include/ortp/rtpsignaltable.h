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

#ifndef rtpsignaltable_h
#define rtpsignaltable_h

#include <bctoolbox/port.h>

#define RTP_CALLBACK_TABLE_MAX_ENTRIES 50

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*RtpCallback)(struct _RtpSession *, void *arg1, void *arg2, void *arg3);

struct _RtpSignalCallback {
	RtpCallback cb;
	void *user_data;

	// Callbacks can be added from other sessions (e.g. bundle).
	// If so, keep a reference to it so we can remove it easily.
	const struct _RtpSession *source;
};

typedef struct _RtpSignalCallback RtpSignalCallback;

struct _RtpSignalTable {
	RtpSignalCallback callback[RTP_CALLBACK_TABLE_MAX_ENTRIES];
	bctbx_mutex_t callback_mutex;
	struct _RtpSession *session;
	const char *signal_name;
	int count;
};

typedef struct _RtpSignalTable RtpSignalTable;

void rtp_signal_table_init(RtpSignalTable *table, struct _RtpSession *session, const char *signal_name);

void rtp_signal_table_uninit(RtpSignalTable *table);

int rtp_signal_table_add(RtpSignalTable *table, RtpCallback cb, void *user_data);

int rtp_signal_table_add_from_source_session(RtpSignalTable *table,
                                             RtpCallback cb,
                                             void *user_data,
                                             const struct _RtpSession *source);

void rtp_signal_table_emit(RtpSignalTable *table);

/* emit but with a second arg */
void rtp_signal_table_emit2(RtpSignalTable *table, void *arg);

/* emit but with a third arg */
void rtp_signal_table_emit3(RtpSignalTable *table, void *arg1, void *arg2);

int rtp_signal_table_remove_by_callback(RtpSignalTable *table, RtpCallback cb);

int rtp_signal_table_remove_by_callback_and_user_data(RtpSignalTable *table, RtpCallback cb, void *user_data);

int rtp_signal_table_remove_by_source_session(RtpSignalTable *table, const struct _RtpSession *session);

#ifdef __cplusplus
}
#endif

#endif
