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

#ifdef HAVE_SRTP
#ifndef ANDROID
#include <srtp/srtp.h>
#else
// Android doesn't use make install
#include <srtp.h>
#endif
#else

typedef  void* srtp_t;
typedef int err_status_t;
typedef int srtp_policy_t;

#endif

#include <ortp/rtpsession.h>

/*srtp defines all this stuff*/
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#ifdef __cplusplus
extern "C"{
#endif

enum ortp_srtp_crypto_suite_t {
	AES_128_SHA1_80 = 1,
	AES_128_SHA1_32,
	AES_128_NO_AUTH,
	NO_CIPHER_SHA1_80
};

ORTP_PUBLIC err_status_t ortp_srtp_init(void);
ORTP_PUBLIC err_status_t ortp_srtp_create(srtp_t *session, const srtp_policy_t *policy);
ORTP_PUBLIC err_status_t ortp_srtp_dealloc(srtp_t session);
ORTP_PUBLIC err_status_t ortp_srtp_add_stream(srtp_t session, const srtp_policy_t *policy);
ORTP_PUBLIC err_status_t ortp_crypto_get_random(uint8_t *tmp, int size);
ORTP_PUBLIC bool_t ortp_srtp_supported(void);

ORTP_PUBLIC int srtp_transport_new(srtp_t srtp, RtpTransport **rtpt, RtpTransport **rtcpt );

ORTP_PUBLIC srtp_t ortp_srtp_create_configure_session(enum ortp_srtp_crypto_suite_t suite, uint32_t ssrc, const char* snd_key, const char* rcv_key);

ORTP_PUBLIC void ortp_srtp_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif
