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

/**
 * \file logging.h
 * \brief Logging API.
 *
**/

#ifndef ORTP_LOGGING_H
#define ORTP_LOGGING_H

#include <ortp/port.h>

#define ORTP_LOG_DOMAIN BCTBX_LOG_DOMAIN

#include "bctoolbox/logging.h"

#ifdef __cplusplus
extern "C"
{
#endif

/***************/
/* logging api */
/***************/
	
#define ORTP_FATAL BCTBX_LOG_FATAL
#define	ORTP_ERROR BCTBX_LOG_ERROR
#define	ORTP_WARNING BCTBX_LOG_WARNING
#define	ORTP_MESSAGE BCTBX_LOG_MESSAGE
#define	ORTP_TRACE	BCTBX_LOG_TRACE
#define	ORTP_DEBUG	BCTBX_LOG_DEBUG
#define	ORTP_END BCTBX_LOG_END
#define ORTP_LOGLEV_END BCTBX_LOG_LOGLEV_END
#define OrtpLogLevel BctbxLogLevel
	
#define OrtpLogFunc BctbxLogFunc

	

/*#define ortp_set_log_file bctbx_set_log_file*/
ORTP_PUBLIC void ortp_set_log_file(FILE *file);

/*#define ortp_set_log_handler bctbx_set_log_handler*/
ORTP_PUBLIC void ortp_set_log_handler(OrtpLogFunc func);


/* This function does not have any means by now, as even bctbx_set_log_handler is deprecated. use bctbx_log_handler_t instead*/
 ORTP_PUBLIC OrtpLogFunc ortp_get_log_handler(void);


#define ortp_logv_out bctbx_logv_out
/*ORTP_PUBLIC void ortp_logv_out(const char *domain, OrtpLogLevel level, const char *fmt, va_list args);*/

#define ortp_log_level_enabled(domain, level)	(bctbx_get_log_level_mask(domain) & (level))
#define ortp_logv bctbx_logv
/*ORTP_PUBLIC void ortp_logv(const char *domain, OrtpLogLevel level, const char *fmt, va_list args);*/

/**
 * Flushes the log output queue.
 * WARNING: Must be called from the thread that has been defined with ortp_set_log_thread_id().
 */
#define ortp_logv_flush bctbx_logv_flush
/*ORTP_PUBLIC void ortp_logv_flush(void);*/

/**
 * Activate all log level greater or equal than specified level argument.
**/
#define ortp_set_log_level bctbx_set_log_level
/*ORTP_PUBLIC void ortp_set_log_level(const char *domain, OrtpLogLevel level);*/

#define ortp_set_log_level_mask bctbx_set_log_level_mask
/*ORTP_PUBLIC void ortp_set_log_level_mask(const char *domain, int levelmask);*/
#define ortp_get_log_level_mask bctbx_get_log_level_mask
/*ORTP_PUBLIC unsigned int ortp_get_log_level_mask(const char *domain);*/

/**
 * Tell oRTP the id of the thread used to output the logs.
 * This is meant to output all the logs from the same thread to prevent deadlock problems at the application level.
 * @param[in] thread_id The id of the thread that will output the logs (can be obtained using ortp_thread_self()).
 */
#define ortp_set_log_thread_id bctbx_set_log_thread_id
/*ORTP_PUBLIC void ortp_set_log_thread_id(unsigned long thread_id);*/

#ifdef ORTP_DEBUG_MODE
#define ortp_debug bctbx_debug
#else

#define ortp_debug(...)

#endif

#ifdef ORTP_NOMESSAGE_MODE

#define ortp_log(...)
#define ortp_message(...)
#define ortp_warning(...)

#else

static ORTP_INLINE void CHECK_FORMAT_ARGS(2,3) ortp_log(OrtpLogLevel lev, const char *fmt,...) {
	va_list args;
	va_start (args, fmt);
	bctbx_logv(ORTP_LOG_DOMAIN, lev, fmt, args);
	va_end (args);
}
	
#define ortp_message bctbx_message
#define ortp_warning bctbx_warning
#define ortp_error bctbx_error
#define ortp_fatal bctbx_fatal
#endif /*ORTP_NOMESSAGE_MODE*/
	
#ifdef __QNX__
#define ortp_qnx_log_handler bctbx_qnx_log_handler
/*void ortp_qnx_log_handler(const char *domain, OrtpLogLevel lev, const char *fmt, va_list args);*/
#endif


#ifdef __cplusplus
}
#endif

#endif
