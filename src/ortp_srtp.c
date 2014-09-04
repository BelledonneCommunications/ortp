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

#ifdef HAVE_CONFIG_H
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

#if defined(ANDROID) || !WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
// Android and Windows phone don't use make install
#include <srtp_priv.h>
#else
#include <srtp/srtp_priv.h>
#endif

#include "ortp/b64.h"

#define SRTP_PAD_BYTES (SRTP_MAX_TRAILER_LEN + 4)

static int _process_on_send(RtpSession* session,srtp_t srtp,mblk_t *m,bool_t is_rtp){
	int slen;
	err_status_t err;
	rtp_header_t *header=is_rtp?(rtp_header_t*)m->b_rptr:NULL;

	slen=msgdsize(m);

	/*only encrypt real RTP packets*/
	if (!is_rtp||(slen>RTP_FIXED_HEADER_SIZE && header->version==2)){
		/* enlarge the buffer for srtp to write its data */
		msgpullup(m,slen+SRTP_PAD_BYTES);
		err=is_rtp?srtp_protect(srtp,m->b_rptr,&slen):srtp_protect_rtcp(srtp,m->b_rptr,&slen);
		if (err==err_status_ok){
			return slen;
		}
		ortp_error("srtp_protect%s() failed (%d)", is_rtp?"":"_rtcp", err);
	}else if (is_rtp){
		return slen;
	}
	return -1;
}

static int srtp_process_on_send(RtpTransportModifier *t, mblk_t *m){
	return _process_on_send(t->session,(srtp_t)t->data, m,TRUE);
}
static int srtcp_process_on_send(RtpTransportModifier *t, mblk_t *m){
	return _process_on_send(t->session,(srtp_t)t->data, m,FALSE);
}
static int _sendto(RtpTransport *t, mblk_t *m, int flags, const struct sockaddr *to, socklen_t tolen, bool_t is_rtp){
	int slen=_process_on_send(t->session,(srtp_t)t->data, m,is_rtp);

	if (slen>=0){
		return sendto(is_rtp?t->session->rtp.gs.socket:t->session->rtcp.gs.socket,(void*)m->b_rptr,slen,flags,to,tolen);
	}
	return slen;
}
static int srtp_sendto(RtpTransport *t, mblk_t *m, int flags, const struct sockaddr *to, socklen_t tolen){
	return _sendto(t,m,flags,to,tolen,TRUE);
}
static int srtcp_sendto(RtpTransport *t, mblk_t *m, int flags, const struct sockaddr *to, socklen_t tolen){
	return _sendto(t,m,flags,to,tolen,FALSE);
}

static srtp_stream_ctx_t * find_other_ssrc(srtp_t srtp, uint32_t ssrc){
	srtp_stream_ctx_t *stream;
	for (stream=srtp->stream_list;stream!=NULL;stream=stream->next){
		if (stream->ssrc!=ssrc) return stream;
	}
	return stream;
}

/*
* The ssrc_any_inbound feature of the libsrtp is not working good.
* It cannot be changed dynamically nor removed.
* As a result we prefer not to use it, but instead the recv stream is configured with a dummy SSRC value.
* When the first packet arrives, or when the SSRC changes, then we change the ssrc value inside the srtp stream context,
* so that the stream that was configured with the dummy SSRC value becomes now fully valid.
*/
static void update_recv_stream(RtpSession *session, srtp_t srtp, uint32_t new_ssrc){
	uint32_t send_ssrc=rtp_session_get_send_ssrc(session);
	srtp_stream_ctx_t *recvstream=find_other_ssrc(srtp,htonl(send_ssrc));
	if (recvstream){
		recvstream->ssrc=new_ssrc;
	}
}

static int _process_on_receive(RtpSession* session,srtp_t srtp,mblk_t *m,bool_t is_rtp, int err){
	int slen;
	uint32_t new_ssrc;
	err_status_t srtp_err;

	/* keep NON-RTP data unencrypted */
	if (is_rtp){
		rtp_header_t *rtp=(rtp_header_t*)m->b_rptr;
		if (err<RTP_FIXED_HEADER_SIZE || rtp->version!=2 )
			return err;
		new_ssrc=rtp->ssrc;
	}else{
		rtcp_common_header_t *rtcp=(rtcp_common_header_t*)m->b_rptr;
		if (err<(sizeof(rtcp_common_header_t)+4) || rtcp->version!=2 )
			return err;
		new_ssrc=*(uint32_t*)(m->b_rptr+sizeof(rtcp_common_header_t));
	}

	slen=err;
	srtp_err = is_rtp?srtp_unprotect(srtp,m->b_rptr,&slen):srtp_unprotect_rtcp(srtp,m->b_rptr,&slen);
	if (srtp_err==err_status_no_ctx) {
		update_recv_stream(session,srtp,new_ssrc);
		slen=err;
		srtp_err = is_rtp?srtp_unprotect(srtp,m->b_rptr,&slen):srtp_unprotect_rtcp(srtp,m->b_rptr,&slen);
	}
	if (srtp_err==err_status_ok) {
		return slen;
	} else {
		ortp_error("srtp_unprotect%s() failed (%d)", is_rtp?"":"_rtcp", srtp_err);
		return -1;
	}
}
static int srtp_process_on_receive(RtpTransportModifier *t, mblk_t *m){
	return _process_on_receive(t->session,(srtp_t)t->data, m,TRUE,msgdsize(m));
}
static int srtcp_process_on_receive(RtpTransportModifier *t, mblk_t *m){
	return _process_on_receive(t->session,(srtp_t)t->data, m,FALSE,msgdsize(m));
}
static int _recvfrom(RtpTransport *t, mblk_t *m, int flags, struct sockaddr *from, socklen_t *fromlen,bool_t is_rtp){
	int err=rtp_session_rtp_recv_abstract(is_rtp?t->session->rtp.gs.socket:t->session->rtcp.gs.socket,m,flags,from,fromlen);
	if (err>0) {
		return _process_on_receive(t->session, (srtp_t)t->data,m, is_rtp, err);
	}
	return err;
}
static int srtp_recvfrom(RtpTransport *t, mblk_t *m, int flags, struct sockaddr *from, socklen_t *fromlen){
	return _recvfrom(t,m,flags,from,fromlen,TRUE);
}
static int srtcp_recvfrom(RtpTransport *t, mblk_t *m, int flags, struct sockaddr *from, socklen_t *fromlen){
	return _recvfrom(t,m,flags,from,fromlen,FALSE);
}


ortp_socket_t srtp_getsocket(RtpTransport *t)
{
	return t->session->rtp.gs.socket;
}

ortp_socket_t srtcp_getsocket(RtpTransport *t)
{
	return t->session->rtcp.gs.socket;
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

void srtp_transport_destroy(RtpTransport *tp){
	ortp_free(tp);
}

int srtp_transport_modifier_new(srtp_t srtp, RtpTransportModifier **rtpt, RtpTransportModifier **rtcpt ){
	if (rtpt) {
		(*rtpt)=ortp_new0(RtpTransportModifier,1);
		(*rtpt)->data=srtp;
		(*rtpt)->t_process_on_send=srtp_process_on_send;
		(*rtpt)->t_process_on_receive=srtp_process_on_receive;
	}
	if (rtcpt) {
		(*rtcpt)=ortp_new0(RtpTransportModifier,1);
		(*rtcpt)->data=srtp;
		(*rtcpt)->t_process_on_send=srtcp_process_on_send;
		(*rtcpt)->t_process_on_receive=srtcp_process_on_receive;
	}
	return 0;
}


void srtp_transport_modifier_destroy(RtpTransportModifier *tp){
	ortp_free(tp);
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

err_status_t ortp_srtp_remove_stream(srtp_t session, uint32_t ssrc){
	return srtp_remove_stream(session,ssrc);
}

bool_t ortp_srtp_supported(void){
	return TRUE;
}

bool_t ortp_init_srtp_policy(srtp_t srtp, srtp_policy_t* policy, enum ortp_srtp_crypto_suite_t suite, ssrc_t ssrc, const char* b64_key)
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
			crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy->rtp);
			crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy->rtcp);
			break;
		case AES_256_SHA1_80:
			crypto_policy_set_aes_cm_256_hmac_sha1_80(&policy->rtp);
			crypto_policy_set_aes_cm_256_hmac_sha1_80(&policy->rtcp);
			break;
		case AES_256_SHA1_32:
			crypto_policy_set_aes_cm_256_hmac_sha1_32(&policy->rtp);
			crypto_policy_set_aes_cm_256_hmac_sha1_32(&policy->rtcp);
			break;
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
		ortp_error("Failed to add stream to srtp session (%d)", err);
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

		policy.allow_repeat_tx=1; /*this is necessary to allow telephone-event to be sent 3 times for end of dtmf packet.*/
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

int srtp_transport_modifier_new(void *i, RtpTransportModifier **rtpt, RtpTransportModifier **rtcpt ){
	ortp_error("srtp_transport_modifier_new: oRTP has not been compiled with SRTP support.");
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

err_status_t ortp_srtp_add_stream(srtp_t session, const srtp_policy_t *policy){
	return -1;
}

err_status_t ortp_srtp_remove_stream(srtp_t session, uint32_t ssrc){
	return -1;
}

srtp_t ortp_srtp_create_configure_session(enum ortp_srtp_crypto_suite_t suite, uint32_t ssrc, const char* snd_key, const char* rcv_key)
{
	return NULL;
}

void ortp_srtp_shutdown(void){
}

void srtp_transport_destroy(RtpTransport *tp){
}

void srtp_transport_modifier_destroy(RtpTransportModifier *tp){
}
#endif
