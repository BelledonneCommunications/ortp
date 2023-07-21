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
#include "ortp/ortp.h"
#include "scheduler.h"
#include "utils.h"
#include <inttypes.h>

rtp_stats_t ortp_global_stats;

#ifdef ENABLE_MEMCHECK
int ortp_allocations = 0;
#endif

RtpScheduler *__ortp_scheduler;

extern void av_profile_init(RtpProfile *profile);

static void init_random_number_generator(void) {
#ifndef _WIN32
	struct timeval t;
	bctbx_gettimeofday(&t, NULL);
	srandom(t.tv_usec + t.tv_sec);
#endif
	/*on windows we're using rand_s, which doesn't require initialization*/
}

#ifdef _WIN32
static bool_t win32_init_sockets(void) {
	WORD wVersionRequested;
	WSADATA wsaData;
	int i;

	wVersionRequested = MAKEWORD(2, 0);
	if ((i = WSAStartup(wVersionRequested, &wsaData)) != 0) {
		ortp_error("Unable to initialize windows socket api, reason: %d (%s)", i, getSocketErrorWithCode(i));
		return FALSE;
	}
	return TRUE;
}
#endif

static int ortp_initialized = 0;

/**
 *	Initialize the oRTP library. You should call this function first before using
 *	oRTP API.
 **/
void ortp_init(void) {
	if (ortp_initialized++) return;

#ifdef _WIN32
	win32_init_sockets();
#endif
	av_profile_init(&av_profile);
	ortp_global_stats_reset();
	init_random_number_generator();
// HAVE_ATOMIC is mandatory but we let it there just in case we want to support other atomic algorithms.
#ifdef HAVE_ATOMIC
	ortp_message("oRTP-" ORTP_VERSION " initialized with Atomic protection.");
#else
	ortp_message("oRTP-" ORTP_VERSION " initialized.");
#endif
}

/**
 *	Initialize the oRTP scheduler. You only have to do that if you intend to use the
 *	scheduled mode of the RtpSession in your application.
 *
 **/
void ortp_scheduler_init(void) {
	static bool_t initialized = FALSE;
	if (initialized) return;
	initialized = TRUE;
#ifdef __hpux
	/* on hpux, we must block sigalrm on the main process, because signal delivery
	is ?random?, well, sometimes the SIGALRM goes to both the main thread and the
	scheduler thread */
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGALRM);
	sigprocmask(SIG_BLOCK, &set, NULL);
#endif /* __hpux */

	__ortp_scheduler = rtp_scheduler_new();
	rtp_scheduler_start(__ortp_scheduler);
}

/**
 * Gracefully uninitialize the library, including shutdowning the scheduler if it was started.
 *
 **/
void ortp_exit(void) {
	if (ortp_initialized == 0) {
		ortp_warning("ortp_exit() called without prior call to ortp_init(), ignored.");
		return;
	}
	ortp_initialized--;
	if (ortp_initialized == 0) {
		if (__ortp_scheduler != NULL) {
			rtp_scheduler_destroy(__ortp_scheduler);
			__ortp_scheduler = NULL;
		}
	}
}

RtpScheduler *ortp_get_scheduler(void) {
	if (__ortp_scheduler == NULL)
		ortp_error("Cannot use the scheduled mode: the scheduler is not "
		           "started. Call ortp_scheduler_init() at the begginning of the application.");
	return __ortp_scheduler;
}

/**
 * Display global statistics (cumulative for all RtpSession)
 **/
void ortp_global_stats_display(void) {
	rtp_stats_display(&ortp_global_stats, "Global statistics");
#ifdef ENABLE_MEMCHECK
	printf("Unfreed allocations: %i\n", ortp_allocations);
#endif
}

/**
 * Print RTP statistics.
 **/
void rtp_stats_display(const rtp_stats_t *stats, const char *header) {
	ortp_log(ORTP_MESSAGE, "===========================================================");
	ortp_log(ORTP_MESSAGE, "%s", header);
	ortp_log(ORTP_MESSAGE, "-----------------------------------------------------------");
	ortp_log(ORTP_MESSAGE, "sent                                 %10" PRId64 " packets", stats->packet_sent);
	ortp_log(ORTP_MESSAGE, "                                     %10" PRId64 " duplicated packets",
	         stats->packet_dup_sent);
	ortp_log(ORTP_MESSAGE, "                                     %10" PRId64 " bytes  ", stats->sent);
	ortp_log(ORTP_MESSAGE, "received                             %10" PRId64 " packets", stats->packet_recv);
	ortp_log(ORTP_MESSAGE, "                                     %10" PRId64 " duplicated packets",
	         stats->packet_dup_recv);
	ortp_log(ORTP_MESSAGE, "                                     %10" PRId64 " bytes  ", stats->hw_recv);
	ortp_log(ORTP_MESSAGE, "incoming delivered to the app        %10" PRId64 " bytes  ", stats->recv);
	ortp_log(ORTP_MESSAGE, "incoming cumulative lost             %10" PRId64 " packets", stats->cum_packet_loss);
	ortp_log(ORTP_MESSAGE, "incoming received too late           %10" PRId64 " packets", stats->outoftime);
	ortp_log(ORTP_MESSAGE, "incoming bad formatted               %10" PRId64 " packets", stats->bad);
	ortp_log(ORTP_MESSAGE, "incoming discarded (queue overflow)  %10" PRId64 " packets", stats->discarded);
	ortp_log(ORTP_MESSAGE, "sent rtcp                            %10" PRId64 " packets", stats->sent_rtcp_packets);
	ortp_log(ORTP_MESSAGE, "received rtcp                        %10" PRId64 " packets", stats->recv_rtcp_packets);
	ortp_log(ORTP_MESSAGE, "===========================================================");
}

/**
 * Print all RTP statistics.
 **/
void rtp_stats_display_all(const rtp_stats_t *stats1, const rtp_stats_t *stats2, const char *header) {
	ortp_log(ORTP_MESSAGE, "=================================================================================");
	ortp_log(ORTP_MESSAGE, "%s", header);
	ortp_log(ORTP_MESSAGE, "---------------------------------------------------------------------------------");
	ortp_log(ORTP_MESSAGE, "                                            SRC        FEC    SRC+FEC");
	ortp_log(ORTP_MESSAGE, "---------------------------------------------------------------------------------");
	ortp_log(ORTP_MESSAGE, "sent                                 %10" PRId64 " %10" PRId64 " %10" PRId64 " packets",
	         stats1->packet_sent, stats2->packet_sent, stats1->packet_sent + stats2->packet_sent);
	ortp_log(ORTP_MESSAGE,
	         "                                     %10" PRId64 " %10" PRId64 " %10" PRId64 " duplicated packets",
	         stats1->packet_dup_sent, stats2->packet_dup_sent, stats1->packet_dup_sent + stats2->packet_dup_sent);
	ortp_log(ORTP_MESSAGE, "                                     %10" PRId64 " %10" PRId64 " %10" PRId64 " bytes  ",
	         stats1->sent, stats2->sent, stats1->sent + stats2->sent);
	ortp_log(ORTP_MESSAGE, "received                             %10" PRId64 " %10" PRId64 " %10" PRId64 " packets",
	         stats1->packet_recv, stats2->packet_recv, stats1->packet_recv + stats2->packet_recv);
	ortp_log(ORTP_MESSAGE,
	         "                                     %10" PRId64 " %10" PRId64 " %10" PRId64 " duplicated packets",
	         stats1->packet_dup_recv, stats2->packet_dup_recv, stats1->packet_dup_recv + stats2->packet_dup_recv);
	ortp_log(ORTP_MESSAGE, "                                     %10" PRId64 " %10" PRId64 " %10" PRId64 " bytes  ",
	         stats1->hw_recv, stats2->hw_recv, stats1->hw_recv + stats2->hw_recv);
	ortp_log(ORTP_MESSAGE, "incoming delivered to the app        %10" PRId64 " %10" PRId64 " %10" PRId64 " bytes  ",
	         stats1->recv, stats2->recv, stats1->recv + stats2->recv);
	ortp_log(ORTP_MESSAGE, "incoming cumulative lost             %10" PRId64 " %10" PRId64 " %10" PRId64 " packets",
	         stats1->cum_packet_loss, stats2->cum_packet_loss, stats1->cum_packet_loss + stats2->cum_packet_loss);
	ortp_log(ORTP_MESSAGE, "incoming received too late           %10" PRId64 " %10" PRId64 " %10" PRId64 " packets",
	         stats1->outoftime, stats2->outoftime, stats1->outoftime + stats2->outoftime);
	ortp_log(ORTP_MESSAGE, "incoming bad formatted               %10" PRId64 " %10" PRId64 " %10" PRId64 " packets",
	         stats1->bad, stats2->bad, stats1->bad + stats2->bad);
	ortp_log(ORTP_MESSAGE, "incoming discarded (queue overflow)  %10" PRId64 " %10" PRId64 " %10" PRId64 " packets",
	         stats1->discarded, stats2->discarded, stats1->discarded + stats2->discarded);
	ortp_log(ORTP_MESSAGE, "sent rtcp                            %10" PRId64 " %10" PRId64 " %10" PRId64 " packets",
	         stats1->sent_rtcp_packets, stats2->sent_rtcp_packets,
	         stats1->sent_rtcp_packets + stats2->sent_rtcp_packets);
	ortp_log(ORTP_MESSAGE, "received rtcp                        %10" PRId64 " %10" PRId64 " %10" PRId64 " packets",
	         stats1->recv_rtcp_packets, stats2->recv_rtcp_packets,
	         stats1->recv_rtcp_packets + stats2->recv_rtcp_packets);
	ortp_log(ORTP_MESSAGE, "=================================================================================");
}

void ortp_global_stats_reset(void) {
	memset(&ortp_global_stats, 0, sizeof(rtp_stats_t));
}

rtp_stats_t *ortp_get_global_stats(void) {
	return &ortp_global_stats;
}

void rtp_stats_reset(rtp_stats_t *stats) {
	memset((void *)stats, 0, sizeof(rtp_stats_t));
}

/**
 * This function give the opportunity to programs to check if the libortp they link to
 * has the minimum version number they need.
 *
 * Returns: true if ortp has a version number greater or equal than the required one.
 **/
bool_t ortp_min_version_required(int major, int minor, int micro) {
	return ((major * 1000000) + (minor * 1000) + micro) <=
	       ((ORTP_MAJOR_VERSION * 1000000) + (ORTP_MINOR_VERSION * 1000) + ORTP_MICRO_VERSION);
}
