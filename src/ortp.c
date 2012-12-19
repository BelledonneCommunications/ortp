/*
  The oRTP library is an RTP (Realtime Transport Protocol - rfc3550) stack.
  Copyright (C) 2001  Simon MORLAT simon.morlat@linphone.org

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/


#ifdef _MSC_VER
#include "ortp-config-win32.h"
#elif HAVE_CONFIG_H
#include "ortp-config.h"
#endif
#include "ortp/ortp.h"
#include "scheduler.h"

rtp_stats_t ortp_global_stats;

#ifdef ENABLE_MEMCHECK
int ortp_allocations=0;
#endif


#ifdef HAVE_SRTP
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include "ortp/ortp_srtp.h"
#endif

RtpScheduler *__ortp_scheduler;



extern void av_profile_init(RtpProfile *profile);

static void init_random_number_generator(){
	struct timeval t;
	gettimeofday(&t,NULL);
	srandom(t.tv_usec+t.tv_sec);
}


#ifdef WIN32
static bool_t win32_init_sockets(void){
	WORD wVersionRequested;
	WSADATA wsaData;
	int i;
	
	wVersionRequested = MAKEWORD(2,0);
	if( (i = WSAStartup(wVersionRequested,  &wsaData))!=0)
	{
		ortp_error("Unable to initialize windows socket api, reason: %d (%s)",i,getWinSocketError(i));
		return FALSE;
	}
	return TRUE;
}
#endif

static int ortp_initialized=0;

/**
 *	Initialize the oRTP library. You should call this function first before using
 *	oRTP API.
**/
void ortp_init()
{
	if (ortp_initialized) return;
	ortp_initialized++;

#ifdef WIN32
	win32_init_sockets();
#endif

	av_profile_init(&av_profile);
	ortp_global_stats_reset();
	init_random_number_generator();

#ifdef HAVE_SRTP
	ortp_srtp_init();
#endif
	ortp_message("oRTP-" ORTP_VERSION " initialized.");
}


/**
 *	Initialize the oRTP scheduler. You only have to do that if you intend to use the
 *	scheduled mode of the #RtpSession in your application.
 *	
**/
void ortp_scheduler_init()
{
	static bool_t initialized=FALSE;
	if (initialized) return;
	initialized=TRUE;
#ifdef __hpux
	/* on hpux, we must block sigalrm on the main process, because signal delivery
	is ?random?, well, sometimes the SIGALRM goes to both the main thread and the 
	scheduler thread */
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set,SIGALRM);
	sigprocmask(SIG_BLOCK,&set,NULL);
#endif /* __hpux */

	__ortp_scheduler=rtp_scheduler_new();
	rtp_scheduler_start(__ortp_scheduler);
	//sleep(1);
}


/**
 * Gracefully uninitialize the library, including shutdowning the scheduler if it was started.
 *	
**/
void ortp_exit()
{
	ortp_initialized--;
	if (ortp_initialized==0){
		if (__ortp_scheduler!=NULL)
		{
			rtp_scheduler_destroy(__ortp_scheduler);
			__ortp_scheduler=NULL;
		}
		ortp_srtp_shutdown();
	}
}

RtpScheduler * ortp_get_scheduler()
{
	if (__ortp_scheduler==NULL) ortp_error("Cannot use the scheduled mode: the scheduler is not "
									"started. Call ortp_scheduler_init() at the begginning of the application.");
	return __ortp_scheduler;
}


/**
 * Display global statistics (cumulative for all RtpSession)
**/
void ortp_global_stats_display()
{
	rtp_stats_display(&ortp_global_stats,"Global statistics");
#ifdef ENABLE_MEMCHECK	
	printf("Unfreed allocations: %i\n",ortp_allocations);
#endif
}

/**
 * Print RTP statistics.
**/
void rtp_stats_display(const rtp_stats_t *stats, const char *header)
{
#ifndef WIN32
  ortp_log(ORTP_MESSAGE,
	   "oRTP-stats:\n   %s :",
	   header);
  ortp_log(ORTP_MESSAGE,
	   " number of rtp packet sent=%lld",
	   (long long)stats->packet_sent);
  ortp_log(ORTP_MESSAGE,
	   " number of rtp bytes sent=%lld bytes",
	   (long long)stats->sent);
  ortp_log(ORTP_MESSAGE,
	   " number of rtp packet received=%lld",
	   (long long)stats->packet_recv);
  ortp_log(ORTP_MESSAGE,
	   " number of rtp bytes received=%lld bytes",
	   (long long)stats->hw_recv);
  ortp_log(ORTP_MESSAGE,
	   " number of incoming rtp bytes successfully delivered to the application=%lld ",
	   (long long)stats->recv);
  ortp_log(ORTP_MESSAGE,
	   " number of rtp packet lost=%lld",
	   (long long) stats->cum_packet_loss);
  ortp_log(ORTP_MESSAGE,
	   " number of rtp packets received too late=%lld",
	   (long long)stats->outoftime);
  ortp_log(ORTP_MESSAGE,
	   " number of bad formatted rtp packets=%lld",
	   (long long)stats->bad);
  ortp_log(ORTP_MESSAGE,
	   " number of packet discarded because of queue overflow=%lld",
	   (long long)stats->discarded);
#else
  ortp_log(ORTP_MESSAGE,
	   "oRTP-stats:\n   %s :",
	   header);
  ortp_log(ORTP_MESSAGE,
	   " number of rtp packet sent=%I64d",
	   (uint64_t)stats->packet_sent);
  ortp_log(ORTP_MESSAGE,
	   " number of rtp bytes sent=%I64d bytes",
	   (uint64_t)stats->sent);
  ortp_log(ORTP_MESSAGE,
	   " number of rtp packet received=%I64d",
	   (uint64_t)stats->packet_recv);
  ortp_log(ORTP_MESSAGE,
	   " number of rtp bytes received=%I64d bytes",
	   (uint64_t)stats->hw_recv);
  ortp_log(ORTP_MESSAGE,
	   " number of incoming rtp bytes successfully delivered to the application=%I64d ",
	   (uint64_t)stats->recv);
  ortp_log(ORTP_MESSAGE,
	   " number of rtp packet lost=%I64d",
	   (uint64_t) stats->cum_packet_loss);
  ortp_log(ORTP_MESSAGE,
	   " number of rtp packets received too late=%I64d",
	   (uint64_t)stats->outoftime);
  ortp_log(ORTP_MESSAGE,
		 " number of bad formatted rtp packets=%I64d",
	   (uint64_t)stats->bad);
  ortp_log(ORTP_MESSAGE,
	   " number of packet discarded because of queue overflow=%I64d",
	   (uint64_t)stats->discarded);
#endif
}

void ortp_global_stats_reset(){
	memset(&ortp_global_stats,0,sizeof(rtp_stats_t));
}

rtp_stats_t *ortp_get_global_stats(){
	return &ortp_global_stats;
}

void rtp_stats_reset(rtp_stats_t *stats){
	memset((void*)stats,0,sizeof(rtp_stats_t));
}


/**
 * This function give the opportunity to programs to check if the libortp they link to
 * has the minimum version number they need.
 *
 * Returns: true if ortp has a version number greater or equal than the required one.
**/
bool_t ortp_min_version_required(int major, int minor, int micro){
	return ((major*1000000) + (minor*1000) + micro) <= 
		   ((ORTP_MAJOR_VERSION*1000000) + (ORTP_MINOR_VERSION*1000) + ORTP_MICRO_VERSION);
}
