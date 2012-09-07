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


#include "ortp/logging.h"


static FILE *__log_file=0;

/**
 *@param file a FILE pointer where to output the ortp logs.
 *
**/
void ortp_set_log_file(FILE *file)
{
	__log_file=file;
}

static void __ortp_logv_out(OrtpLogLevel lev, const char *fmt, va_list args);

OrtpLogFunc ortp_logv_out=__ortp_logv_out;

/**
 *@param func: your logging function, compatible with the OrtpLogFunc prototype.
 *
**/
void ortp_set_log_handler(OrtpLogFunc func){
	ortp_logv_out=func;
}


unsigned int __ortp_log_mask=ORTP_WARNING|ORTP_ERROR|ORTP_FATAL;

/**
 * @ param levelmask a mask of ORTP_DEBUG, ORTP_MESSAGE, ORTP_WARNING, ORTP_ERROR
 * ORTP_FATAL .
**/
void ortp_set_log_level_mask(int levelmask){
	__ortp_log_mask=levelmask;
}

char * ortp_strdup_vprintf(const char *fmt, va_list ap)
{
	/* Guess we need no more than 100 bytes. */
	int n, size = 200;
	char *p,*np;
#ifndef WIN32
	va_list cap;/*copy of our argument list: a va_list cannot be re-used (SIGSEGV on linux 64 bits)*/
#endif
	if ((p = (char *) ortp_malloc (size)) == NULL)
		return NULL;
	while (1)
	{
		/* Try to print in the allocated space. */
#ifndef WIN32
		va_copy(cap,ap);
		n = vsnprintf (p, size, fmt, cap);
		va_end(cap);
#else
		/*this works on 32 bits, luckily*/
		n = vsnprintf (p, size, fmt, ap);
#endif
		/* If that worked, return the string. */
		if (n > -1 && n < size)
			return p;
		//printf("Reallocing space.\n");
		/* Else try again with more space. */
		if (n > -1)	/* glibc 2.1 */
			size = n + 1;	/* precisely what is needed */
		else		/* glibc 2.0 */
			size *= 2;	/* twice the old size */
		if ((np = (char *) ortp_realloc (p, size)) == NULL)
		  {
		    free(p);
		    return NULL;
		  }
		else
		  {
		    p = np;
		  }
	}
}

char *ortp_strdup_printf(const char *fmt,...){
	char *ret;
	va_list args;
	va_start (args, fmt);
	ret=ortp_strdup_vprintf(fmt, args);
	va_end (args);
	return ret;
}

#if	defined(WIN32) || defined(_WIN32_WCE)
#define ENDLINE "\r\n"
#else
#define ENDLINE "\n"
#endif

#if	defined(WIN32) || defined(_WIN32_WCE)
void ortp_logv(int level, const char *fmt, va_list args)
{
	if (ortp_logv_out!=NULL && ortp_log_level_enabled(level))
		ortp_logv_out(level,fmt,args);
#if !defined(_WIN32_WCE)
	if ((level)==ORTP_FATAL) abort();
#endif
}
#endif

static void __ortp_logv_out(OrtpLogLevel lev, const char *fmt, va_list args){
	const char *lname="undef";
	char *msg;
	if (__log_file==NULL) __log_file=stderr;
	switch(lev){
		case ORTP_DEBUG:
			lname="debug";
			break;
		case ORTP_MESSAGE:
			lname="message";
			break;
		case ORTP_WARNING:
			lname="warning";
			break;
		case ORTP_ERROR:
			lname="error";
			break;
		case ORTP_FATAL:
			lname="fatal";
			break;
		default:
			ortp_fatal("Bad level !");
	}
	msg=ortp_strdup_vprintf(fmt,args);
#if defined(_MSC_VER) && !defined(_WIN32_WCE)
	OutputDebugString(msg);
	OutputDebugString("\r\n");
#endif
	fprintf(__log_file,"ortp-%s-%s" ENDLINE,lname,msg);
	fflush(__log_file);
	ortp_free(msg);
}
