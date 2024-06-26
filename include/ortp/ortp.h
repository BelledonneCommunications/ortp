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

/** \mainpage oRTP API documentation
 *
 * \section init Initializing oRTP
 *
 * see ortp.h documentation.
 *
 * \section rtpsession the RtpSession object
 *
 * see the rtpsession.h documentation.
 *
 * \section payloadtypes Managing PayloadType(s) and RtpProfile(s)
 *
 * see the payloadtype.h documentation.
 *
 * \section telephonevents Sending and receiving telephone-event (RFC2833)
 *
 * see the telephonyevents.h documentation.
 * To get informed about incoming telephone-event you can register a callback
 * using rtp_session_signal_connect() or by registering an event queue using
 * rtp_session_register_event_queue().
 *
 * \section sessionset Managing several RtpSession simultaneously
 *
 * see the sessionset.h documentation.
 *
 * \section rtcp Parsing incoming rtcp packets.
 *
 * The parsing api is defined in rtcp.h (not yet documented).
 *
 * \section examples Examples
 *
 * oRTP comes with a set of examples in src/tests.
 * - rtprecv.c rtpsend.c show how to receive and send a single RTP stream.
 * - mrtprecv.c mrtpsend.c show how to receive and send multiple RTP streams
 *   simultaneously
 *
 */

/**
 * \file ortp.h
 * \brief General purpose library functions.
 *
 **/

#ifndef ORTP_H
#define ORTP_H
#include "ortp/logging.h"
#include "ortp/rtpsession.h"
#include "ortp/sessionset.h"

#ifdef __cplusplus
extern "C" {
#endif

ORTP_PUBLIC bool_t ortp_min_version_required(int major, int minor, int micro);
ORTP_PUBLIC void ortp_init(void);
ORTP_PUBLIC void ortp_scheduler_init(void);
ORTP_PUBLIC void ortp_exit(void);

/****************/
/*statistics api*/
/****************/

extern rtp_stats_t ortp_global_stats;

ORTP_PUBLIC void ortp_global_stats_reset(void);
ORTP_PUBLIC rtp_stats_t *ortp_get_global_stats(void);

ORTP_PUBLIC void ortp_global_stats_display(void);
ORTP_PUBLIC void rtp_stats_display(const rtp_stats_t *stats, const char *header);
ORTP_PUBLIC void rtp_stats_display_all(const rtp_stats_t *stats1, const rtp_stats_t *stats2, const char *header);
ORTP_PUBLIC void rtp_stats_reset(rtp_stats_t *stats);

#ifdef __cplusplus
}
#endif

#endif
