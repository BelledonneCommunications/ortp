/*
  The oRTP library is an RTP (Realtime Transport Protocol - rfc3550) stack.
  Copyright (C) 2011 Belledonne Communications

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

#if defined(_MSC_VER)  && (defined(WIN32) || defined(_WIN32_WCE))
#include "ortp-config-win32.h"
#elif HAVE_CONFIG_H
#include "ortp-config.h"
#endif

#include "ortp/ortp.h"

#include "ortp/zrtp.h"


OrtpZrtpContext* ortp_zrtp_context_new(RtpSession *s, OrtpZrtpParams *params){
	ortp_message("ZRTP is disabled - not implemented yet");
	return NULL;
}

OrtpZrtpContext* ortp_zrtp_multistream_new(OrtpZrtpContext* activeContext, RtpSession *s, OrtpZrtpParams *params) {
	ortp_message("ZRTP is disabled - not implemented yet - not adding stream");
	return NULL;
}

bool_t ortp_zrtp_available(){return FALSE;}
void ortp_zrtp_sas_verified(OrtpZrtpContext* ctx){}
void ortp_zrtp_sas_reset_verified(OrtpZrtpContext* ctx){}
void ortp_zrtp_context_destroy(OrtpZrtpContext *ctx){}


