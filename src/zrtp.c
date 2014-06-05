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
#include "rtpsession_priv.h"

#include "ortp/zrtp.h"

#ifdef WIN32
#include <malloc.h>
#endif

#ifdef HAVE_zrtp
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include <srtp/srtp.h>
#include <bzrtp/bzrtp.h>


#define SRTP_PAD_BYTES (SRTP_MAX_TRAILER_LEN + 4)

struct _OrtpZrtpContext{
	RtpSession *session;
	srtp_t srtpSend;
	srtp_t srtpRecv;
	bzrtpContext_t *zrtpContext; // back link
	RtpTransport rtpt;
	RtpTransport rtcpt;
	char *zidFilename;
	char *peerURI;
};

typedef enum {
	rtp_stream,
	rtcp_stream
} stream_type;




// Helper functions
static ORTP_INLINE uint64_t get_timeval_in_millis() {
	struct timeval t;
	ortp_gettimeofday(&t,NULL);
	uint32_t ret=(1000LL*t.tv_sec)+(t.tv_usec/1000LL);
	return ret;
}

/* ZRTP library Callbacks implementation */

/**
* Send a ZRTP packet via RTP.
*
* ZRTP calls this method to send a ZRTP packet via the RTP session.
*
* @param ctx
*    Pointer to the opaque ZrtpContext structure.
* @param data
*    Points to ZRTP message to send.
* @param length
*    The length in bytes of the data
* @return
*    zero if sending failed, one if packet was sent
*/
static int32_t ozrtp_sendDataZRTP (void *clientData, uint8_t* data, int32_t length ){

	OrtpZrtpContext *userData = (OrtpZrtpContext *)clientData;
	RtpSession *session = userData->session;
	struct sockaddr *destaddr=(struct sockaddr*)&session->rtp.gs.rem_addr;
	socklen_t destlen=session->rtp.gs.rem_addrlen;
	ortp_socket_t sockfd=session->rtp.gs.socket;
	ortp_message("ZRTP Send packet type %.8s", data+16);

	// Send packet
	ssize_t bytesSent = sendto(sockfd, (void*)data, length,0,destaddr,destlen);
	if (bytesSent == -1 || bytesSent < length) {
		ortp_message("ZRTP sending data returned error %s", strerror(errno));
		ortp_error("zrtp_sendDataZRTP: sent only %d bytes out of %d", (int)bytesSent, length);
		return 1;
	} else {
		return 0;
	}
}

/**
 * This function is called by ZRTP engine as soon as SRTP secrets are ready to be used
 * Depending on which role we assume in the ZRTP protocol (Initiator or Responder, randomly selected)
 * both secrets may not be available at the same time, the part argument is either
 * ZRTP_SRTP_SECRETS_FOR_SENDER or ZRTP_SRTP_SECRETS_FOR_RECEIVER
 */
static int32_t ozrtp_srtpSecretsAvailable(void* clientData, bzrtpSrtpSecrets_t* secrets, uint8_t part) {
	err_status_t srtpCreateStatus;
	err_status_t addStreamStatus;
	OrtpZrtpContext *userData = (OrtpZrtpContext *)clientData;


	// Get authentication and cipher algorithms in srtp format
	if ((secrets->authTagAlgo != ZRTP_AUTHTAG_HS32) && ((secrets->authTagAlgo != ZRTP_AUTHTAG_HS80))) {
		ortp_fatal("unsupported authentication algorithm by srtp");
	}

	if ((secrets->cipherAlgo != ZRTP_CIPHER_AES1) && (secrets->cipherAlgo != ZRTP_CIPHER_AES2) && (secrets->cipherAlgo != ZRTP_CIPHER_AES3)) {
		ortp_fatal("unsupported cipher algorithm by srtp");
	}

	ortp_message("ZRTP secrets are ready for %s; auth tag algo is %s", (part==ZRTP_SRTP_SECRETS_FOR_SENDER)?"sender":"receiver", (secrets->authTagAlgo==ZRTP_AUTHTAG_HS32)?"HS32":"HS80");

	/*
	 * Don't use crypto_policy_set_from_profile_for_rtp(), it is totally buggy.
	 */

	if (part==ZRTP_SRTP_SECRETS_FOR_RECEIVER) {
		srtp_policy_t receiverPolicy;
		memset(&receiverPolicy,0,sizeof(receiverPolicy));
		
		if (secrets->authTagAlgo == ZRTP_AUTHTAG_HS32){
			crypto_policy_set_aes_cm_128_hmac_sha1_32(&receiverPolicy.rtp);
			crypto_policy_set_aes_cm_128_hmac_sha1_32(&receiverPolicy.rtcp);
		}else if (secrets->authTagAlgo == ZRTP_AUTHTAG_HS80){
			crypto_policy_set_aes_cm_128_hmac_sha1_80(&receiverPolicy.rtp);
			crypto_policy_set_aes_cm_128_hmac_sha1_80(&receiverPolicy.rtcp);
		}else{
			ortp_fatal("unsupported auth tag");
		}


		/* add the encryption keys to the receiving context */
		srtpCreateStatus = srtp_create(&userData->srtpRecv, NULL);
		receiverPolicy.ssrc.type = ssrc_any_inbound; 
		receiverPolicy.key = ortp_malloc0((secrets->peerSrtpKeyLength+secrets->peerSrtpSaltLength+16)*sizeof(uint8_t)); /* +16 is for padding, why exactly? TODO */
		memcpy(receiverPolicy.key, secrets->peerSrtpKey, secrets->peerSrtpKeyLength);
		memcpy(receiverPolicy.key + secrets->peerSrtpKeyLength, secrets->peerSrtpSalt, secrets->peerSrtpSaltLength);
		addStreamStatus=srtp_add_stream(userData->srtpRecv, &receiverPolicy);
		ortp_free(receiverPolicy.key);
	
		if (srtpCreateStatus != err_status_ok) {
			ortp_error("ZRTP Error %u during creation of SRTP context for receiver",srtpCreateStatus);
			return 1;
		}
		if (addStreamStatus != err_status_ok) {
			ortp_error("ZRTP Error %u during addition of SRTP stream for receiver", addStreamStatus);
			return 1;
		}

	}

	if (part==ZRTP_SRTP_SECRETS_FOR_SENDER) {
		srtp_policy_t senderPolicy;
		memset(&senderPolicy,0,sizeof(senderPolicy));
		
		if (secrets->authTagAlgo == ZRTP_AUTHTAG_HS32){
			crypto_policy_set_aes_cm_128_hmac_sha1_32(&senderPolicy.rtp);
			crypto_policy_set_aes_cm_128_hmac_sha1_32(&senderPolicy.rtcp);
		}else if (secrets->authTagAlgo == ZRTP_AUTHTAG_HS80){
			crypto_policy_set_aes_cm_128_hmac_sha1_80(&senderPolicy.rtp);
			crypto_policy_set_aes_cm_128_hmac_sha1_80(&senderPolicy.rtcp);
		}else{
			ortp_fatal("unsupported auth tag");
		}

		/* add the encryption keys to the sending context */
		srtpCreateStatus = srtp_create(&userData->srtpSend, NULL);
		senderPolicy.ssrc.type = ssrc_specific;
		senderPolicy.ssrc.value = userData->session->snd.ssrc; // us
		senderPolicy.key = ortp_malloc0((secrets->selfSrtpKeyLength+secrets->selfSrtpSaltLength+16)*sizeof(uint8_t)); /* +16 is for padding, why exactly? TODO */
		memcpy(senderPolicy.key, secrets->selfSrtpKey, secrets->selfSrtpKeyLength);
		memcpy(senderPolicy.key + secrets->selfSrtpKeyLength, secrets->selfSrtpSalt, secrets->selfSrtpSaltLength);
		addStreamStatus=srtp_add_stream(userData->srtpSend, &senderPolicy);
		ortp_free(senderPolicy.key);
	
		if (srtpCreateStatus != err_status_ok) {
			ortp_error("ZRTP Error %u during creation of SRTP context for sender",srtpCreateStatus);
		return 1;
		}
		if (addStreamStatus != err_status_ok) {
			ortp_error("ZRTP Error %u during addition of SRTP stream for sender", addStreamStatus);
			return 1;
		}
	}
	return 0;
}




/**
 * Switch off the security for the defined part.
 *
 * @param ctx
 *    Pointer to the opaque ZrtpContext structure.
 * @param part Defines for which part (sender or receiver) to
 *    switch off security
 */
/*
static void ozrtp_srtpSecretsOff (void *clientData) {
	OrtpZrtpContext *userData = (OrtpZrtpContext *)clientData;

	if (userData->srtpRecv != NULL) {
		srtp_dealloc(userData->srtpRecv);
		userData->srtpRecv=NULL;
	}

	if (userData->srtpSend != NULL) {
		srtp_dealloc(userData->srtpSend);
		userData->srtpSend=NULL;
	}

	ortp_message("ZRTP secrets off");
}*/


/**
 * Switch on the security.
 *
 * ZRTP calls this method after it has computed the SAS and check
 * if it is verified or not. In addition ZRTP provides information
 * about the cipher algorithm and key length for the SRTP session.
 *
 * This method must enable SRTP processing if it was not enabled
 * during sertSecretsReady().
 *
 * @param ctx
 *    Pointer to the opaque ZrtpContext structure.
 * @param c The name of the used cipher algorithm and mode, or
 *    NULL
 *
 * @param s The SAS string
 *
 * @param verified if <code>verified</code> is true then SAS was
 *    verified by both parties during a previous call.
 */
static int ozrtp_startSrtpSession(void *clientData, char* sas, int32_t verified ){
	OrtpZrtpContext *userData = (OrtpZrtpContext *)clientData;

	// srtp processing is enabled in SecretsReady fuction when receiver secrets are ready
	// Indeed, the secrets on is called before both parts are given to secretsReady.

	OrtpEventData *eventData;
	OrtpEvent *ev;

	if (sas != NULL) {
		ev=ortp_event_new(ORTP_EVENT_ZRTP_SAS_READY);
		eventData=ortp_event_get_data(ev);
		memcpy(eventData->info.zrtp_sas.sas,sas,4);
		eventData->info.zrtp_sas.sas[4]=0;
		eventData->info.zrtp_sas.verified=(verified != 0) ? TRUE : FALSE;
		rtp_session_dispatch_event(userData->session, ev);
		ortp_message("ZRTP secrets on: SAS is %.4s previously verified %s", sas, verified == 0 ? "no" : "yes");
	}

	ev=ortp_event_new(ORTP_EVENT_ZRTP_ENCRYPTION_CHANGED);
	eventData=ortp_event_get_data(ev);
	eventData->info.zrtp_stream_encrypted=1;
	rtp_session_dispatch_event(userData->session, ev);
	ortp_message("Event dispatched to all: secrets are on");


	return 0;
}

static int ozrtp_loadCache(void *clientData, uint8_t** output, uint32_t *outputSize) {
	/* get filename from ClientData */
	OrtpZrtpContext *userData = (OrtpZrtpContext *)clientData;
	char *filename = userData->zidFilename; 
	FILE *CACHEFD = fopen(filename, "r+");
	if (CACHEFD == NULL) { /* file doesn't seem to exist, try to create it */
		CACHEFD = fopen(filename, "w");
		if (CACHEFD != NULL) { /* file created with success */
			*output = NULL;
			*outputSize = 0;
			fclose(CACHEFD);
			return 0;
		}
		return -1;
	}
	fseek(CACHEFD, 0L, SEEK_END);  /* Position to end of file */
  	*outputSize = ftell(CACHEFD);     /* Get file length */
  	rewind(CACHEFD);               /* Back to start of file */
	*output = (uint8_t *)malloc(*outputSize*sizeof(uint8_t)+1); /* string must be null terminated */
	fread(*output, 1, *outputSize, CACHEFD);
	*(*output+*outputSize) = '\0';
	*outputSize += 1;
	fclose(CACHEFD);
	return *outputSize;
}

static int ozrtp_writeCache(void *clientData, uint8_t* input, uint32_t inputSize) {
	/* get filename from ClientData */
	OrtpZrtpContext *userData = (OrtpZrtpContext *)clientData;
	char *filename = userData->zidFilename; 

	FILE *CACHEFD = fopen(filename, "w+");
	int retval = fwrite(input, 1, inputSize, CACHEFD);
	fclose(CACHEFD);
	return retval;

}

/**
 * @brief This callback is called when context is ready to compute exported keys as in rfc6189 section 4.5.2
 * Computed keys are added to zid cache with sip URI of peer(found in client Data) to be used for IM ciphering
 *
 * @param[in]	clientData		Contains opaque zrtp context but also peer sip URI
 * @param[in]	peerZid			Peer ZID to address correct node in zid cache
 * @param[in]	role			RESPONDER or INITIATOR, needed to compute the pair of keys for IM ciphering
 *
 * @return 	0 on success
 */
static int ozrtp_addExportedKeysInZidCache(void *clientData, uint8_t peerZid[12], uint8_t role) {
	OrtpZrtpContext *userData = (OrtpZrtpContext *)clientData;
	bzrtpContext_t *zrtpContext = userData->zrtpContext;

	if (userData->peerURI) {
		/* Write the peer sip URI in cache */
		bzrtp_addCustomDataInCache(zrtpContext, peerZid, (uint8_t *)"uri", 3, (uint8_t *)(userData->peerURI), strlen(userData->peerURI), 0, BZRTP_CUSTOMCACHE_PLAINDATA, BZRTP_CACHE_LOADFILE|BZRTP_CACHE_DONTWRITEFILE);
	}

	/* Derive the master keys and session Id 32 bytes each */
	bzrtp_addCustomDataInCache(zrtpContext, peerZid, (uint8_t *)"sndKey", 6, (uint8_t *)((role==RESPONDER)?"ResponderKey":"InitiatorKey"), 12, 32, BZRTP_CUSTOMCACHE_USEKDF, BZRTP_CACHE_DONTLOADFILE|BZRTP_CACHE_DONTWRITEFILE);
	bzrtp_addCustomDataInCache(zrtpContext, peerZid, (uint8_t *)"rcvKey", 6, (uint8_t *)((role==RESPONDER)?"InitiatorKey":"ResponderKey"), 12, 32, BZRTP_CUSTOMCACHE_USEKDF, BZRTP_CACHE_DONTLOADFILE|BZRTP_CACHE_DONTWRITEFILE);
	bzrtp_addCustomDataInCache(zrtpContext, peerZid, (uint8_t *)"sndSId", 6, (uint8_t *)((role==RESPONDER)?"ResponderSId":"InitiatorSId"), 12, 32, BZRTP_CUSTOMCACHE_USEKDF, BZRTP_CACHE_DONTLOADFILE|BZRTP_CACHE_DONTWRITEFILE);
	bzrtp_addCustomDataInCache(zrtpContext, peerZid, (uint8_t *)"rcvSId", 6, (uint8_t *)((role==RESPONDER)?"InitiatorSId":"ResponderSId"), 12, 32, BZRTP_CUSTOMCACHE_USEKDF, BZRTP_CACHE_DONTLOADFILE|BZRTP_CACHE_DONTWRITEFILE);

	/* Derive session index, 4 bytes */
	bzrtp_addCustomDataInCache(zrtpContext, peerZid, (uint8_t *)"sndIndex", 6, (uint8_t *)((role==RESPONDER)?"ResponderIndex":"InitiatorIndex"), 14, 4, BZRTP_CUSTOMCACHE_USEKDF, BZRTP_CACHE_DONTLOADFILE|BZRTP_CACHE_DONTWRITEFILE);
	bzrtp_addCustomDataInCache(zrtpContext, peerZid, (uint8_t *)"rcvIndex", 6, (uint8_t *)((role==RESPONDER)?"InitiatorIndex":"ResponderIndex"), 14, 4, BZRTP_CUSTOMCACHE_USEKDF, BZRTP_CACHE_DONTLOADFILE|BZRTP_CACHE_WRITEFILE);

	return 0;
}

/*** end of Callback functions implementations ***/

static int ozrtp_generic_sendto(stream_type stream, RtpTransport *t, mblk_t *m, int flags, const struct sockaddr *to, socklen_t tolen){
	int slen;
	err_status_t err;
	ortp_socket_t socket;

	OrtpZrtpContext *userData = (OrtpZrtpContext*) t->data;
	bzrtpContext_t *zrtpContext = userData->zrtpContext;
	RtpSession *session = userData->session;



	if (stream == rtp_stream) {
		socket= t->session->rtp.gs.socket;
	} else {
		socket= t->session->rtcp.gs.socket;
	}

	if (userData->srtpSend == NULL || !bzrtp_isSecure(zrtpContext, session->snd.ssrc)) {
		int size;
		msgpullup(m,-1);
		size=msgdsize(m);
		return sendto(socket,(void*)m->b_rptr,size,flags,to,tolen);
	}
	slen=msgdsize(m);
	// Protect with srtp
	/* enlarge the buffer for srtp to write its data */
	msgpullup(m,msgdsize(m)+SRTP_PAD_BYTES);
	if (stream == rtp_stream) {
		err=srtp_protect(userData->srtpSend,m->b_rptr,&slen);
	} else {
		err=srtp_protect_rtcp(userData->srtpSend,m->b_rptr,&slen);
	}
	if (err==err_status_ok){
		return sendto(socket,(void*)m->b_rptr,slen,flags,to,tolen);
	} else {
		ortp_error("srtp_protect() failed with status %d", err);
	}
	return -1;
}

static int ozrtp_rtcp_sendto(RtpTransport *t, mblk_t *m, int flags, const struct sockaddr *to, socklen_t tolen){
	return ozrtp_generic_sendto(rtcp_stream,t,m,flags,to,tolen);
}

static int ozrtp_rtp_sendto(RtpTransport *t, mblk_t *m, int flags, const struct sockaddr *to, socklen_t tolen){
	return ozrtp_generic_sendto(rtp_stream,t,m,flags,to,tolen);
}


static int ozrtp_rtp_recvfrom(RtpTransport *t, mblk_t *m, int flags, struct sockaddr *from, socklen_t *fromlen){
	int rlen;

	OrtpZrtpContext *userData = (OrtpZrtpContext*) t->data;
	bzrtpContext_t *zrtpContext = userData->zrtpContext;
	RtpSession *session = userData->session;


	// send a timer tick to the zrtp engine
	bzrtp_iterate(zrtpContext, session->snd.ssrc, get_timeval_in_millis());

	// Check if something to receive
	rlen=rtp_session_rtp_recv_abstract(t->session->rtp.gs.socket,m,flags,from,fromlen);
	if (rlen<=0) {
		// nothing was received or error: pass the information to caller
		return rlen;
	}

	uint8_t* rtp = m->b_rptr;
	int rtpVersion = ((rtp_header_t*)rtp)->version;

	// If plain or secured RTP
	if (rtpVersion == 2) {
		if (userData->srtpRecv != NULL && bzrtp_isSecure(zrtpContext, session->snd.ssrc)) {
			// probably srtp packet, unprotect
			err_status_t err = srtp_unprotect(userData->srtpRecv,m->b_wptr,&rlen);
			if (err != err_status_ok) {
				ortp_warning("srtp_unprotect failed; packet may be plain RTP");
				return -1;
			}
		}
		// in both cases (RTP plain and deciphered srtp)
		return rlen;
	}

	// if ZRTP packet, send to engine
	uint32_t *magicField=(uint32_t *)(rtp + 4);
	if (rtpVersion==0 && ntohl(*magicField) == ZRTP_MAGIC_COOKIE) {
		ortp_message("ZRTP Receive packet type %.8s", rtp+16);
		bzrtp_processMessage(zrtpContext, session->snd.ssrc, rtp, rlen);
		return 0;
		}
	else {
		// Not a ZRTP packet, accept it
		return rlen;
	}
}

static int ozrtp_rtcp_recvfrom(RtpTransport *t, mblk_t *m, int flags, struct sockaddr *from, socklen_t *fromlen){
	OrtpZrtpContext *userData = (OrtpZrtpContext*) t->data;
	bzrtpContext_t *zrtpContext = userData->zrtpContext;
	RtpSession *session = userData->session;


	int rlen = rtp_session_rtp_recv_abstract(t->session->rtcp.gs.socket,m,flags,from,fromlen);
	if (rlen<=0) {
		// nothing was received or error: pass the information to caller
		return rlen;
	}

	uint8_t *rtcp = m->b_wptr;
	int version = ((rtcp_common_header_t *)rtcp)->version;
	if (version == 2 && userData->srtpRecv != NULL && bzrtp_isSecure(zrtpContext, session->snd.ssrc)) {
		err_status_t err = srtp_unprotect_rtcp(userData->srtpRecv,m->b_wptr,&rlen);
		if (err != err_status_ok) {
			ortp_error("srtp_unprotect failed %d ; packet discarded (may be plain RTCP)", err);
			return 0;
		}
	}

	return rlen;
}


static ortp_socket_t ozrtp_rtp_getsocket(RtpTransport *t){
  return t->session->rtp.gs.socket;
}

static ortp_socket_t ozrtp_rtcp_getsocket(RtpTransport *t){
  return t->session->rtcp.gs.socket;
}

static OrtpZrtpContext* createUserData(bzrtpContext_t *context, OrtpZrtpParams *params) {
	OrtpZrtpContext *userData=ortp_new0(OrtpZrtpContext,1);
	userData->zrtpContext=context;
	userData->srtpRecv=NULL;
	userData->srtpSend=NULL;
	/* get the zidFilename (if any)*/
	if (params->zid_file != NULL) {
		userData->zidFilename = (char *)malloc(strlen(params->zid_file)+1);
		memcpy(userData->zidFilename, params->zid_file, strlen(params->zid_file));
		userData->zidFilename[strlen(params->zid_file)] = '\0';
	} else {
		userData->zidFilename = NULL;
	}


	return userData;
}

static OrtpZrtpContext* ortp_zrtp_configure_context(OrtpZrtpContext *userData, RtpSession *s) {
	bzrtpContext_t *context=userData->zrtpContext;


	if (s->rtp.gs.tr || s->rtcp.gs.tr)
		ortp_warning("Overwriting rtp or rtcp transport with ZRTP one");

	userData->rtpt.data=userData; /* back link to get access to the other fields of the OrtoZrtpContext from the RtpTransport structure */
	userData->rtpt.t_getsocket=ozrtp_rtp_getsocket;
	userData->rtpt.t_sendto=ozrtp_rtp_sendto;
	userData->rtpt.t_recvfrom=ozrtp_rtp_recvfrom;

	userData->rtcpt.data=userData; /* back link to get access to the other fields of the OrtoZrtpContext from the RtpTransport structure */
	userData->rtcpt.t_getsocket=ozrtp_rtcp_getsocket;
	userData->rtcpt.t_sendto=ozrtp_rtcp_sendto;
	userData->rtcpt.t_recvfrom=ozrtp_rtcp_recvfrom;

	rtp_session_set_transports(s, &userData->rtpt, &userData->rtcpt);

	ortp_message("Starting ZRTP engine on session [%p]",s);
	bzrtp_startChannelEngine(context, s->snd.ssrc);
	return userData;
}

OrtpZrtpContext* ortp_zrtp_context_new(RtpSession *s, OrtpZrtpParams *params){
	ortp_message("Creating ZRTP engine on session [%p]",s);
	bzrtpContext_t *context = bzrtp_createBzrtpContext(s->snd.ssrc); /* create the zrtp context, provide the SSRC of first channel */
	/* set callback functions */
	bzrtp_setCallback(context, (int (*)())ozrtp_sendDataZRTP, ZRTP_CALLBACK_SENDDATA);
	bzrtp_setCallback(context, (int (*)())ozrtp_srtpSecretsAvailable, ZRTP_CALLBACK_SRTPSECRETSAVAILABLE);
	bzrtp_setCallback(context, (int (*)())ozrtp_startSrtpSession, ZRTP_CALLBACK_STARTSRTPSESSION);
	if (params->zid_file) {
		/*enabling cache*/
		bzrtp_setCallback(context, (int (*)())ozrtp_loadCache, ZRTP_CALLBACK_LOADCACHE);
		bzrtp_setCallback(context, (int (*)())ozrtp_writeCache, ZRTP_CALLBACK_WRITECACHE);
		/* enable exportedKeys computation only if we have an uri to associate them */
		if (params->uri && strlen(params->uri)>0) {
			bzrtp_setCallback(context, (int (*)())ozrtp_addExportedKeysInZidCache, ZRTP_CALLBACK_CONTEXTREADYFOREXPORTEDKEYS);
		}
	}
	/* create and link user data */
	OrtpZrtpContext *userData=createUserData(context, params);
	userData->session=s;

	/* get the sip URI of peer and store it into the context to set it in the cache. Done only for the first channel as it is useless for the other ones which doesn't update the cache */
	if (params->uri && strlen(params->uri)>0) {
		userData->peerURI = strdup(params->uri);
	} else {
		userData->peerURI = NULL;
	}

	bzrtp_setClientData(context, s->snd.ssrc, (void *)userData);
	
	bzrtp_initBzrtpContext(context); /* init is performed only when creating the first channel context */
	return ortp_zrtp_configure_context(userData,s);
}

OrtpZrtpContext* ortp_zrtp_multistream_new(OrtpZrtpContext* activeContext, RtpSession *s, OrtpZrtpParams *params) {
	int retval;
	if ((retval = bzrtp_addChannel(activeContext->zrtpContext, s->snd.ssrc)) != 0) {
		ortp_warning("could't add stream: multistream not supported by peer %x", retval);
	}

	ortp_message("Initializing ZRTP context");
	OrtpZrtpContext *userData=createUserData(activeContext->zrtpContext, params);
	userData->session=s;
	bzrtp_setClientData(activeContext->zrtpContext, s->snd.ssrc, (void *)userData);

	return ortp_zrtp_configure_context(userData,s);
}

bool_t ortp_zrtp_available(){return TRUE;}


void ortp_zrtp_sas_verified(OrtpZrtpContext* ctx){
	bzrtp_SASVerified(ctx->zrtpContext); 
}

void ortp_zrtp_sas_reset_verified(OrtpZrtpContext* ctx){
	bzrtp_resetSASVerified(ctx->zrtpContext);
}

void ortp_zrtp_context_destroy(OrtpZrtpContext *ctx) {
	ortp_message("Stopping ZRTP context");
	bzrtp_destroyBzrtpContext(ctx->zrtpContext, ctx->session->snd.ssrc);

	ortp_message("Destroying SRTP contexts");
	if (ctx->srtpSend != NULL) srtp_dealloc(ctx->srtpSend);
	if (ctx->srtpRecv != NULL) srtp_dealloc(ctx->srtpRecv);

	if (ctx->zidFilename) free(ctx->zidFilename);
	if (ctx->peerURI) free(ctx->peerURI);
	free(ctx);
	ortp_message("ORTP-ZRTP context destroyed");
}

void ortp_zrtp_reset_transmition_timer(OrtpZrtpContext* ctx, RtpSession *s) {
	bzrtp_resetRetransmissionTimer(ctx->zrtpContext,s->snd.ssrc);
}

#else


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
void ortp_zrtp_reset_transmition_timer(OrtpZrtpContext* ctx, RtpSession *s) {};
#endif


