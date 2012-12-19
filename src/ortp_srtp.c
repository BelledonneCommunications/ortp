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

#if defined(_MSC_VER)  && (defined(WIN32) || defined(_WIN32_WCE))
#include "ortp-config-win32.h"
#elif HAVE_CONFIG_H
#include "ortp-config.h"
#endif
#include "ortp/ortp.h"

#undef PACKAGE_NAME 
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME 
#undef PACKAGE_VERSION

#include "ortp/ortp_srtp.h"
#include "rtpsession_priv.h"
#ifdef HAVE_SRTP

#include "ortp/b64.h"

#define SRTP_PAD_BYTES (SRTP_MAX_TRAILER_LEN + 4)

static int  srtp_sendto(RtpTransport *t, mblk_t *m, int flags, const struct sockaddr *to, socklen_t tolen){
	srtp_t srtp=(srtp_t)t->data;
	int slen;
	err_status_t err;
	/* enlarge the buffer for srtp to write its data */
	slen=msgdsize(m);
	msgpullup(m,slen+SRTP_PAD_BYTES);
	err=srtp_protect(srtp,m->b_rptr,&slen);
	if (err==err_status_ok){
		return sendto(t->session->rtp.socket,(void*)m->b_rptr,slen,flags,to,tolen);
	}
	ortp_error("srtp_protect() failed (%d)", err);
	return -1;
}

static int srtp_recvfrom(RtpTransport *t, mblk_t *m, int flags, struct sockaddr *from, socklen_t *fromlen){
	srtp_t srtp=(srtp_t)t->data;
	int err;
	int slen;
	err=rtp_session_rtp_recv_abstract(t->session->rtp.socket,m,flags,from,fromlen);
	if (err>0){
		err_status_t srtp_err;
		/* keep NON-RTP data unencrypted */
		rtp_header_t *rtp;
		if (err>=RTP_FIXED_HEADER_SIZE)
		{
			rtp = (rtp_header_t*)m->b_wptr;
			if (rtp->version!=2)
			{
				return err;
			}
		}

		slen=err;
		srtp_err = srtp_unprotect(srtp,m->b_wptr,&slen);
		if (srtp_err==err_status_ok)
			return slen;
		else {
			ortp_error("srtp_unprotect() failed (%d)", srtp_err);
			return -1;
		}
	}
	return err;
}

static int  srtcp_sendto(RtpTransport *t, mblk_t *m, int flags, const struct sockaddr *to, socklen_t tolen){
	srtp_t srtp=(srtp_t)t->data;
	int slen;
	err_status_t srtp_err;
	slen=msgdsize(m);
	/* enlarge the buffer for srtp to write its data */
	msgpullup(m,slen+SRTP_PAD_BYTES);
	srtp_err=srtp_protect_rtcp(srtp,m->b_rptr,&slen);
	if (srtp_err==err_status_ok){
		return sendto(t->session->rtcp.socket,(void*)m->b_rptr,slen,flags,to,tolen);
	}
	ortp_error("srtp_protect_rtcp() failed (%d)", srtp_err);
	return -1;
}

static int srtcp_recvfrom(RtpTransport *t, mblk_t *m, int flags, struct sockaddr *from, socklen_t *fromlen){
	srtp_t srtp=(srtp_t)t->data;
	int err;
	int slen;
	err=rtp_session_rtp_recv_abstract(t->session->rtcp.socket,m,flags,from,fromlen);
	if (err>0){
		err_status_t srtp_err;
		/* keep NON-RTP data unencrypted */
		rtcp_common_header_t *rtcp;
		if (err>=RTCP_COMMON_HEADER_SIZE)
		{
			rtcp = (rtcp_common_header_t*)m->b_wptr;
			if (rtcp->version!=2)
			{
				return err;
			}
		}

		slen=err;
		srtp_err=srtp_unprotect_rtcp(srtp,m->b_wptr,&slen);
		if (srtp_err==err_status_ok)
			return slen;
		else {
			ortp_error("srtp_unprotect_rtcp() failed (%d)", srtp_err);
			return -1;
		}
	}
	return err;
}

ortp_socket_t 
srtp_getsocket(RtpTransport *t)
{
  return t->session->rtp.socket;
}

ortp_socket_t 
srtcp_getsocket(RtpTransport *t)
{
  return t->session->rtcp.socket;
}

/**
 * Creates a pair of Secure-RTP/Secure-RTCP RtpTransport's.
 * oRTP relies on libsrtp (see http://srtp.sf.net ) for secure RTP encryption.
 * This function creates a RtpTransport object to be used to the RtpSession using
 * rtp_session_set_transport().
 * @srtp: the srtp_t session to be used
 * 
**/
int srtp_transport_new(srtp_t srtp, RtpTransport **rtpt, RtpTransport **rtcpt ){
	if (rtpt) {
		(*rtpt)=ortp_new0(RtpTransport,1);
		(*rtpt)->data=srtp;
		(*rtpt)->t_getsocket=srtp_getsocket;
		(*rtpt)->t_sendto=srtp_sendto;
		(*rtpt)->t_recvfrom=srtp_recvfrom;
	}
	if (rtcpt) {
		(*rtcpt)=ortp_new0(RtpTransport,1);
		(*rtcpt)->data=srtp;
		(*rtcpt)->t_getsocket=srtcp_getsocket;
		(*rtcpt)->t_sendto=srtcp_sendto;
		(*rtcpt)->t_recvfrom=srtcp_recvfrom;
	}
	return 0;
}

static int srtp_init_done=0;

err_status_t ortp_srtp_init(void)
{
	
	err_status_t st=0;
	ortp_message("srtp init");
	if (!srtp_init_done) {
		st=srtp_init();
		if (st==0) {
			srtp_init_done++;
		}else{
			ortp_fatal("Couldn't initialize SRTP library.");
			err_reporting_init("oRTP");
		}
	}else srtp_init_done++;
	return st;
}

void ortp_srtp_shutdown(void){
	srtp_init_done--;
	if (srtp_init_done==0){
#ifdef HAVE_SRTP_SHUTDOWN
		srtp_shutdown();
#endif
	}
}

err_status_t ortp_srtp_create(srtp_t *session, const srtp_policy_t *policy)
{
	int i;
	i = srtp_create(session, policy);
	return i;
}

err_status_t ortp_srtp_dealloc(srtp_t session)
{
	return srtp_dealloc(session);
}

err_status_t ortp_srtp_add_stream(srtp_t session, const srtp_policy_t *policy)
{
	return srtp_add_stream(session, policy);
}

bool_t ortp_srtp_supported(void){
	return TRUE;
}

static bool_t ortp_init_srtp_policy(srtp_t srtp, srtp_policy_t* policy, enum ortp_srtp_crypto_suite_t suite, ssrc_t ssrc, const char* b64_key)
{
	uint8_t* key;
	int key_size;
	err_status_t err;
	unsigned b64_key_length = strlen(b64_key);
		
	switch (suite) {
		case AES_128_SHA1_32:
			crypto_policy_set_aes_cm_128_hmac_sha1_32(&policy->rtp);
			// srtp doc says: not adapted to rtcp...
			crypto_policy_set_aes_cm_128_hmac_sha1_32(&policy->rtcp);
			break;
		case AES_128_NO_AUTH:
			crypto_policy_set_aes_cm_128_null_auth(&policy->rtp);
			// srtp doc says: not adapted to rtcp...
			crypto_policy_set_aes_cm_128_null_auth(&policy->rtcp);
			break;
		case NO_CIPHER_SHA1_80:
			crypto_policy_set_null_cipher_hmac_sha1_80(&policy->rtp);
			crypto_policy_set_null_cipher_hmac_sha1_80(&policy->rtcp);
			break;
		case AES_128_SHA1_80: /*default mode*/
		default:
			crypto_policy_set_rtp_default(&policy->rtp);
			crypto_policy_set_rtcp_default(&policy->rtcp);
	}
	key_size = b64_decode(b64_key, b64_key_length, 0, 0);
	if (key_size != policy->rtp.cipher_key_len) {
		ortp_error("Key size (%d) doesn't match the selected srtp profile (required %d)",
			key_size,
			policy->rtp.cipher_key_len);
			return FALSE;
	}
	key = (uint8_t*) ortp_malloc0(key_size+2); /*srtp uses padding*/
	if (b64_decode(b64_key, b64_key_length, key, key_size) != key_size) {
		ortp_error("Error decoding key");
		ortp_free(key);
		return FALSE;
	}
		
	policy->ssrc = ssrc;
	policy->key = key;
	policy->next = NULL;
		
	err = ortp_srtp_add_stream(srtp, policy);
	if (err != err_status_ok) {
		ortp_error("Failed to add incoming stream to srtp session (%d)", err);
		ortp_free(key);
		return FALSE;
	}
		
	ortp_free(key);
	return TRUE;
}

err_status_t ortp_crypto_get_random(uint8_t *tmp, int size)
{
	return crypto_get_random(tmp, size);
}

srtp_t ortp_srtp_create_configure_session(enum ortp_srtp_crypto_suite_t suite, uint32_t ssrc, const char* snd_key, const char* rcv_key)
{
	err_status_t err;
	srtp_t session;
		
	err = ortp_srtp_create(&session, NULL);
	if (err != err_status_ok) {
		ortp_error("Failed to create srtp session (%d)", err);
		return NULL;
	}

	// incoming stream
	{
		ssrc_t incoming_ssrc;
		srtp_policy_t policy;
		
		memset(&policy, 0, sizeof(srtp_policy_t));
		incoming_ssrc.type = ssrc_any_inbound;
		
		if (!ortp_init_srtp_policy(session, &policy, suite, incoming_ssrc, rcv_key)) {
			ortp_srtp_dealloc(session);
			return NULL;
		}
	}
	// outgoing stream
	{
		ssrc_t outgoing_ssrc;
		srtp_policy_t policy;
		
		memset(&policy, 0, sizeof(srtp_policy_t));
		
		outgoing_ssrc.type = ssrc_specific;
		outgoing_ssrc.value = ssrc;
		
		if (!ortp_init_srtp_policy(session, &policy, suite, outgoing_ssrc, snd_key)) {
			ortp_srtp_dealloc(session);
			return NULL;
		}
	}
	
	return session;
}

#else

err_status_t ortp_srtp_init(void) {
	return -1;
}

err_status_t ortp_crypto_get_random(uint8_t *tmp, int size)
{
	return -1;
}

int srtp_transport_new(void *i, RtpTransport **rtpt, RtpTransport **rtcpt ){
	ortp_error("srtp_transport_new: oRTP has not been compiled with SRTP support.");
	return -1;
}

bool_t ortp_srtp_supported(void){
	return FALSE;
}

err_status_t ortp_srtp_create(srtp_t *i, const srtp_policy_t *policy)
{
	return -1;
}

err_status_t ortp_srtp_dealloc(srtp_t session)
{
	return -1;
}

err_status_t ortp_srtp_add_stream(srtp_t session, const srtp_policy_t *policy)
{
	return -1;
}

srtp_t ortp_srtp_create_configure_session(enum ortp_srtp_crypto_suite_t suite, uint32_t ssrc, const char* snd_key, const char* rcv_key)
{
	return NULL;
}

void ortp_srtp_shutdown(void){
}

#endif

