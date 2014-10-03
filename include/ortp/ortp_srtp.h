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

#ifndef ortp_srtp_h
#define ortp_srtp_h

#if defined(HAVE_SRTP) || defined(ORTP_HAVE_SRTP)
#if defined(ANDROID) || !WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
// Android and Windows phone don't use make install
#	include <srtp.h>
#	else
#	include <srtp/srtp.h>
#	endif
#else

typedef void* srtp_t;
typedef int err_status_t;
typedef struct srtp_policy srtp_policy_t;

#endif

/*srtp defines all this stuff*/
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <ortp/rtpsession.h>



#ifdef __cplusplus
extern "C"{
#endif

enum ortp_srtp_crypto_suite_t {
	AES_128_SHA1_80 = 1,
	AES_128_SHA1_32,
	AES_128_NO_AUTH,
	NO_CIPHER_SHA1_80,
	AES_256_SHA1_80,
	AES_256_SHA1_32
};

ORTP_PUBLIC err_status_t ortp_srtp_init(void);
ORTP_PUBLIC err_status_t ortp_srtp_create(srtp_t *session, const srtp_policy_t *policy);
ORTP_PUBLIC err_status_t ortp_srtp_dealloc(srtp_t session);
ORTP_PUBLIC err_status_t ortp_srtp_add_stream(srtp_t session, const srtp_policy_t *policy);
ORTP_PUBLIC err_status_t ortp_srtp_remove_stream(srtp_t session, uint32_t ssrc);
ORTP_PUBLIC err_status_t ortp_crypto_get_random(uint8_t *tmp, int size);
ORTP_PUBLIC bool_t ortp_srtp_supported(void);

/**
  * @deprecated Use srtp_transport_modifier_new() instead. Using #srtp_transport_new will prevent usage of multiple
  * encryptions and/or custom packets transmission.
*/
ORTP_PUBLIC int srtp_transport_new(srtp_t srtp, RtpTransport **rtpt, RtpTransport **rtcpt );
ORTP_PUBLIC void srtp_transport_destroy(RtpTransport *tp);

ORTP_PUBLIC srtp_t ortp_srtp_create_configure_session(enum ortp_srtp_crypto_suite_t suite, uint32_t ssrc, const char* snd_key, const char* rcv_key);

ORTP_PUBLIC int srtp_transport_modifier_new(srtp_t srtp, RtpTransportModifier **rtpt, RtpTransportModifier **rtcpt );
ORTP_PUBLIC void srtp_transport_modifier_destroy(RtpTransportModifier *tp);

ORTP_PUBLIC void ortp_srtp_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif
