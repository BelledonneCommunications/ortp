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


// Minimum packet length is 3 + 3 (HelloAck) + 1 = 7 uint_32t
#define ZRTP_MIN_MSG_LENGTH 28

// ZRTP message is prefixed by RTP header
#define ZRTP_MESSAGE_OFFSET 12

#define SRTP_PAD_BYTES (SRTP_MAX_TRAILER_LEN + 4)
//                                  1234567890123456
static const char userAgentStr[] = "LINPHONE-ZRTPCPP"; // 16 chars max.

struct _OrtpZrtpContext{
	ortp_mutex_t mutex;
	RtpSession *session;
	uint32_t timerWillTriggerAt;
	uint16_t last_recv_zrtp_seq_number;
	uint16_t last_sent_zrtp_seq_number;
	srtp_t srtpSend;
	srtp_t srtpRecv;
	zrtp_Callbacks zrtp_cb;
	ZrtpContext *zrtpContext; // back link
	RtpTransport rtpt;
	RtpTransport rtcpt;
};

typedef enum {
	rtp_stream,
	rtcp_stream
} stream_type;



// Helper functions
static inline OrtpZrtpContext* user_data(ZrtpContext *c) {
	return (OrtpZrtpContext*) c->userData;
}

static inline uint64_t convert_timeval_to_millis(struct timeval *t) {
	uint32_t ret=(1000LL*t->tv_sec)+(t->tv_usec/1000LL);
	return ret;
}

static void check_timer(ZrtpContext *zrtpContext, OrtpZrtpContext *c) {
	if (c->timerWillTriggerAt != 0) {
		struct timeval t;
		gettimeofday(&t,NULL);
		uint64_t now=convert_timeval_to_millis(&t);
		if (now > c->timerWillTriggerAt) {
			c->timerWillTriggerAt=0;
			zrtp_processTimeout(zrtpContext);
		}
	}
}

static void parseZrtpMessageType(char *messageType, const uint8_t* data) {
	memcpy(messageType, data+4,8);
	messageType[8]=0;
}

/* Structure of ZRTP packet (taken from the RFC)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 0 0 1|Not Used (set to zero) |         Sequence Number       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Magic Cookie 'ZRTP' (0x5a525450)              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Source Identifier                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |           ZRTP Message (length depends on Message Type)       |
   |                            . . .                              |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          CRC (1 word)                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                       Figure 2: ZRTP Packet Format
*/

/* Structure of ZRTP Message (taken from RFC)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 1 0 1 0 0 0 0 0 1 0 1 1 0 1 0|             length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Message Type Block="the type" (2 words)            |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static inline uint16_t get_rtp_seqnumber(const uint8_t *rtp) {
	return ntohs(*(uint16_t*)(rtp+2));
}

static inline uint16_t get_zrtp_message_length(const uint8_t *zrtp_message){
	return ntohs(*(uint16_t*)(zrtp_message+2));
}

static inline uint32_t get_zrtp_packet_crc(const uint32_t *zrtp_packet, uint16_t zrtp_message_length) {
	return ntohl(*(zrtp_packet + ZRTP_MESSAGE_OFFSET/4 + zrtp_message_length));
}

static const char *zrtpErrorType="Error   ";
static void print_zrtp_packet(const char *info, const uint8_t *rtp) {
	const uint8_t *zmessage=rtp+ZRTP_MESSAGE_OFFSET;
	uint16_t zmessage_seq=get_rtp_seqnumber(rtp);

	char msgType[9];
	parseZrtpMessageType(msgType, zmessage);

/*	uint16_t zmessage_length = get_zrtp_message_length(zmessage);
	uint32_t crc = get_zrtp_packet_crc((uint32_t*) rtp, zmessage_length);

	ortp_message("%s ZRTP seq=%u type=%s CRC=%u, ln=%u",
			info, zmessage_seq, msgType, crc, zmessage_length);
*/

    if (strcmp(zrtpErrorType, msgType) == 0) {
        uint32_t *msg32=(uint32_t*)zmessage;
        uint32_t errcode=ntohl(msg32[3]);
        ortp_error("%s ZRTP %s 0x%x %u", info, msgType, errcode, zmessage_seq);
    } else {
        ortp_message("%s ZRTP %s %u", info, msgType, zmessage_seq);
    }

/*	uint32_t *msg32=(uint32_t*)zmessage;
	int i=0;
	for (; i<zmessage_length; i++) {
		ortp_message("%u", ntohl(msg32[i]));
	}*/
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
static int32_t ozrtp_sendDataZRTP (ZrtpContext* ctx, const uint8_t* data, const int32_t length ){
	OrtpZrtpContext *userData = user_data(ctx);
	RtpSession *session = userData->session;
	struct sockaddr *destaddr=(struct sockaddr*)&session->rtp.rem_addr;
	socklen_t destlen=session->rtp.rem_addrlen;
	ortp_socket_t sockfd=session->rtp.socket;

	// Create ZRTP packet

	int32_t newlength = length + 3*4; // strangely, given length includes CRC size !!!!
	uint32_t* buffer32 = alloca(newlength);
	uint8_t *buffer8=(uint8_t*)buffer32;
	uint16_t *buffer16=(uint16_t*)buffer32;

	uint16_t seqNumber=userData->last_sent_zrtp_seq_number++;

	*buffer8 = 0x10;
	buffer8[1]=0;
	buffer16[1] = htons(seqNumber);
	buffer32[1] = htonl(ZRTP_MAGIC);
	buffer32[2] = htonl(session->snd.ssrc);
	memcpy(buffer32+3, data, length);
	uint32_t cks=zrtp_EndCksum(zrtp_GenerateCksum(buffer8, newlength-CRC_SIZE));
	buffer32[newlength/4-1] = htonl(cks);

	print_zrtp_packet("sent", buffer8);

	// Send packet
	ssize_t bytesSent = sendto(sockfd, (void*)buffer8, newlength,0,destaddr,destlen);
	if (bytesSent == -1 || bytesSent < length) {
		ortp_error("zrtp_sendDataZRTP: sent only %d bytes out of %d", (int)bytesSent, length);
		return 0;
	} else {
		return 1;
	}
}


/**
* Activate timer.
*
* @param ctx
*    Pointer to the opaque ZrtpContext structure.
* @param time
*    The time in ms for the timer
* @return
*    zero if activation failed, one if timer was activated
*/
static int32_t ozrtp_activateTimer (ZrtpContext* ctx, int32_t time ) {
	if (user_data(ctx)->timerWillTriggerAt != 0) {
		ortp_error("zrtp_activateTimer while another timer already active");
		return 0;
	}
	struct timeval t;
	gettimeofday(&t,NULL);
	user_data(ctx)->timerWillTriggerAt=time+convert_timeval_to_millis(&t);
	return 1;
}

/**
* Cancel the active timer.
*
* @param ctx
*    Pointer to the opaque ZrtpContext structure.
* @return
*    zero if cancel action failed, one if timer was canceled
*/
static int32_t ozrtp_cancelTimer(ZrtpContext* ctx) {
	user_data(ctx)->timerWillTriggerAt=0;
	return 1;
}

/**
* Send information messages to the hosting environment.
*
* The ZRTP implementation uses this method to send information
* messages to the host. Along with the message ZRTP provides a
* severity indicator that defines: Info, Warning, Error,
* Alert. Refer to the <code>MessageSeverity</code> enum above.
*
* @param ctx
*    Pointer to the opaque ZrtpContext structure.
* @param severity
*     This defines the message's severity
* @param subCode
*     The subcode identifying the reason.
* @see ZrtpCodes#MessageSeverity
*/
static void ozrtp_sendInfo (ZrtpContext* ctx, int32_t severity, int32_t subCode ) {
	const char* submsg;
	switch (subCode) {
		case zrtp_InfoHelloReceived:
			/*!< Hello received, preparing a Commit */
			submsg="zrtp_InfoHelloReceived";
			break;
		case zrtp_InfoCommitDHGenerated:
			/*!< Commit: Generated a public DH key */
			submsg="zrtp_InfoCommitDHGenerated";
			break;
		case zrtp_InfoRespCommitReceived:
			 /*!< Responder: Commit received, preparing DHPart1 */
			submsg="zrtp_InfoRespCommitReceived";
			break;
		case zrtp_InfoDH1DHGenerated:
			/*!< DH1Part: Generated a public DH key */
			submsg="zrtp_InfoDH1DHGenerated";
			break;
		case zrtp_InfoInitDH1Received:
           /*!< Initiator: DHPart1 received, preparing DHPart2 */
			submsg="zrtp_InfoInitDH1Received";
			break;
		case zrtp_InfoRespDH2Received:
			/*!< Responder: DHPart2 received, preparing Confirm1 */
			submsg="zrtp_InfoRespDH2Received";
			break;
		case zrtp_InfoInitConf1Received:
			/*!< Initiator: Confirm1 received, preparing Confirm2 */
			submsg="zrtp_InfoInitConf1Received";
			break;
		case zrtp_InfoRespConf2Received:
			/*!< Responder: Confirm2 received, preparing Conf2Ack */
			submsg="zrtp_InfoRespConf2Received";
			break;
		case zrtp_InfoRSMatchFound:
			/*!< At least one retained secrets matches - security OK */
			submsg="zrtp_InfoRSMatchFound";
			break;
		case zrtp_InfoSecureStateOn:
			/*!< Entered secure state */
			submsg="zrtp_InfoSecureStateOn";
			break;
		case zrtp_InfoSecureStateOff:
			/*!< No more security for this session */
			submsg="zrtp_InfoSecureStateOff";
			break;
		default:
			submsg="unkwown";
			break;
	}

	switch (severity) {
		case zrtp_Info:
			ortp_message("ZRTP INFO %s",submsg);
			break;
		case zrtp_Warning: /*!< A Warning message - security can be established */
			ortp_warning("ZRTP %s",submsg);
			break;
		case zrtp_Severe:/*!< Severe error, security will not be established */
			ortp_error("ZRTP SEVERE %s",submsg);
			break;
		case zrtp_ZrtpError:
			ortp_error("ZRTP ERROR %s",submsg);
			break;
		default:
			ortp_error("ZRTP UNKNOWN ERROR %s",submsg);
			break;
	}


	if (subCode == zrtp_InfoSecureStateOn || subCode == zrtp_InfoSecureStateOff) {
		OrtpEventData *eventData;
		OrtpEvent *ev;
		ev=ortp_event_new(ORTP_EVENT_ZRTP_ENCRYPTION_CHANGED);
		eventData=ortp_event_get_data(ev);
		eventData->info.zrtp_stream_encrypted=(subCode == zrtp_InfoSecureStateOn);
		rtp_session_dispatch_event(user_data(ctx)->session, ev);
	}
}


/** returned key need to be fred.*/
static uint8_t *key_with_salt(C_SrtpSecret_t* s, int32_t role) {
	uint8_t *saltedKey;
	const int pad=128;
	if (role == Initiator) {
		saltedKey=ortp_malloc0((s->initKeyLen + s->initSaltLen + pad)/8);
		memcpy(saltedKey, s->keyInitiator, s->initKeyLen/8);
		memcpy(saltedKey + s->initKeyLen/8, s->saltInitiator, s->initSaltLen/8);
	} else {
		saltedKey=ortp_malloc0((s->respKeyLen + s->respSaltLen + pad)/8);
		memcpy(saltedKey, s->keyResponder, s->respKeyLen/8);
		memcpy(saltedKey + s->respKeyLen/8, s->saltResponder, s->respSaltLen/8);
	}
	return saltedKey;
}


/**
 * SRTP crypto data ready for the sender or receiver.
 *
 * The ZRTP implementation calls this method right after all SRTP
 * secrets are computed and ready to be used. The parameter points
 * to a structure that contains pointers to the SRTP secrets and a
 * <code>enum Role</code>. The called method (the implementation
 * of this abstract method) must either copy the pointers to the SRTP
 * data or the SRTP data itself to a save place. The SrtpSecret_t
 * structure is destroyed after the callback method returns to the
 * ZRTP implementation.
 *
 * The SRTP data themselves are obtained in the ZRtp object and are
 * valid as long as the ZRtp object is active. TheZRtp's
 * destructor clears the secrets. Thus the called method needs to
 * save the pointers only, ZRtp takes care of the data.
 *
 * The implementing class may enable SRTP processing in this
 * method or delay it to srtpSecertsOn().
 *
 * @param ctx
 *    Pointer to the opaque ZrtpContext structure.
 * @param secrets A pointer to a SrtpSecret_t structure that
 *     contains all necessary data.
 *
 * @param part for which part (Sender or Receiver) this data is
 *     valid.
 *
 * @return Returns false if something went wrong during
 *    initialization of SRTP context, for example memory shortage.
 */
static int32_t ozrtp_srtpSecretsReady (ZrtpContext* ctx, C_SrtpSecret_t* secrets, int32_t part ) {
	srtp_policy_t policy;
	err_status_t srtpCreateStatus;
	err_status_t addStreamStatus;
	OrtpZrtpContext *userData = user_data(ctx);

	ortp_message("ZRTP secrets for %s are ready; auth tag len is %i",
	             (part == ForSender) ? "sender" : "receiver",secrets->srtpAuthTagLen);

	// Get authentication and cipher algorithms in srtp format
	if (secrets->authAlgorithm != zrtp_Sha1) {
		ortp_fatal("unsupported authentication algorithm by srtp");
	}

	if (secrets->symEncAlgorithm != zrtp_Aes) {
		ortp_fatal("unsupported cipher algorithm by srtp");
	}

	/*
	 * Don't use crypto_policy_set_from_profile_for_rtp(), it is totally buggy.
	 */
	memset(&policy,0,sizeof(policy));

	if (secrets->srtpAuthTagLen == 32){
		crypto_policy_set_aes_cm_128_hmac_sha1_32(&policy.rtp);
		crypto_policy_set_aes_cm_128_hmac_sha1_32(&policy.rtcp);
	}else if (secrets->srtpAuthTagLen == 80){
		crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtp);
		crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtcp);
	}else{
		ortp_fatal("unsupported auth tag len");
	}

	if (part == ForSender) {
		srtpCreateStatus=srtp_create(&userData->srtpSend, NULL);
		policy.ssrc.type=ssrc_specific;
		policy.ssrc.value=userData->session->snd.ssrc; // us
		policy.key=key_with_salt(secrets, secrets->role);
		addStreamStatus=srtp_add_stream(userData->srtpSend, &policy);
	} else { //if (part == ForReceiver)
		srtpCreateStatus=srtp_create(&userData->srtpRecv, NULL);
		policy.ssrc.type = ssrc_any_inbound; /*we don't know the incoming ssrc will be */
		int32_t peerRole=secrets->role == Initiator ? Responder : Initiator;
		policy.key=key_with_salt(secrets,peerRole);
		addStreamStatus=srtp_add_stream(userData->srtpRecv, &policy);
	}

	ortp_free(policy.key);

	if (srtpCreateStatus != err_status_ok) {
		ortp_error("ZRTP Error %u during creation of SRTP context for %s",
			srtpCreateStatus, (part == ForSender) ? "sender" : "receiver");
		return 0;
	}
	if (addStreamStatus != err_status_ok) {
		ortp_error("ZRTP Error %u during addition of SRTP stream for %s",
			addStreamStatus, (part == ForSender) ? "sender" : "receiver");
		return 0;
	}
	return 1;
}




/**
 * Switch off the security for the defined part.
 *
 * @param ctx
 *    Pointer to the opaque ZrtpContext structure.
 * @param part Defines for which part (sender or receiver) to
 *    switch off security
 */
static void ozrtp_srtpSecretsOff (ZrtpContext* ctx, int32_t part ) {
	OrtpZrtpContext *userData = user_data(ctx);

	if (userData->srtpRecv != NULL) {
		srtp_dealloc(userData->srtpRecv);
		userData->srtpRecv=NULL;
	}

	if (userData->srtpSend != NULL) {
		srtp_dealloc(userData->srtpSend);
		userData->srtpSend=NULL;
	}

	ortp_message("ZRTP secrets off");
}

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
static void ozrtp_rtpSecretsOn (ZrtpContext* ctx, char* c, char* s, int32_t verified ){
//	OrtpZrtpContext *userData = user_data(ctx);

	// srtp processing is enabled in SecretsReady fuction when receiver secrets are ready
	// Indeed, the secrets on is called before both parts are given to secretsReady.

	OrtpEventData *eventData;
	OrtpEvent *ev;
	ev=ortp_event_new(ORTP_EVENT_ZRTP_SAS_READY);
	eventData=ortp_event_get_data(ev);
	memcpy(eventData->info.zrtp_sas.sas,s,4);
	eventData->info.zrtp_sas.sas[4]=0;
	eventData->info.zrtp_sas.verified=(verified != 0) ? TRUE : FALSE;
	rtp_session_dispatch_event(user_data(ctx)->session, ev);
	ortp_message("ZRTP secrets on: SAS is %s previously verified %s - algo %s", s, verified == 0 ? "no" : "yes", c);
}


/**
 *
 * According to the ZRTP specification the user must be informed about
 * a GoClear request because the ZRTP implementation switches off security
 * if it could authenticate the GoClear packet.
 *
 * <b>Note:</b> GoClear is not yet implemented in GNU ZRTP.
 *
 * @param ctx
 *    Pointer to the opaque ZrtpContext structure.
 */
static void ozrtp_handleGoClear(ZrtpContext* ctx) {
	ortp_fatal("not implemented");
}

/**
 * Handle ZRTP negotiation failed.
 *
 * ZRTP calls this method in case ZRTP negotiation failed. The
 * parameters show the severity as well as the reason.
 *
 * @param ctx
 *    Pointer to the opaque ZrtpContext structure.
 * @param severity
 *     This defines the message's severity
 * @param subCode
 *     The subcode identifying the reason.
 * @see ZrtpCodes#MessageSeverity
 */
static void ozrtp_zrtpNegotiationFailed (ZrtpContext* ctx, int32_t severity, int32_t subCode ){
	ozrtp_sendInfo(ctx, severity, subCode);
	// FIXME: necessary?
}

/**
 * ZRTP calls this method if the other side does not support ZRTP.
 *
 * @param ctx
 *    Pointer to the opaque ZrtpContext structure.
 * If the other side does not answer the ZRTP <em>Hello</em> packets then
 * ZRTP calls this method,
 *
 */
static void ozrtp_zrtpNotSuppOther(ZrtpContext* ctx) {
	// FIXME: do nothing
}

/**
 * Enter synchronization mutex.
 *
 * GNU ZRTP requires one mutex to synchronize its
 * processing. Because mutex implementations depend on the
 * underlying infrastructure, for example operating system or
 * thread implementation, GNU ZRTP delegates mutex handling to the
 * specific part of its implementation.
 *
 * @param ctx
 *    Pointer to the opaque ZrtpContext structure.
 */
static void ozrtp_synchEnter(ZrtpContext* ctx){
	ortp_mutex_lock(&user_data(ctx)->mutex);
}

/**
 * Leave synchronization mutex.
 *
 * @param ctx
 *    Pointer to the opaque ZrtpContext structure.
 */
static void ozrtp_synchLeave(ZrtpContext* ctx){
	ortp_mutex_unlock(&user_data(ctx)->mutex);
}


static inline uint32_t get_rtcp_ssrc(uint8_t *rtp) {
	return ntohl(*(uint32_t*)(rtp+4));

}
static int ozrtp_generic_sendto(stream_type stream, RtpTransport *t, mblk_t *m, int flags, const struct sockaddr *to, socklen_t tolen){
	int slen;
	err_status_t err;
	ortp_socket_t socket;

	ZrtpContext *zrtpContext = (ZrtpContext*) t->data;
	OrtpZrtpContext *userData = (OrtpZrtpContext*) zrtpContext->userData;


	if (stream == rtp_stream) {
		socket= t->session->rtp.socket;
	} else {
		socket= t->session->rtcp.socket;
	}

	if (userData->srtpSend == NULL || !zrtp_inState(zrtpContext, SecureState)) {
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

	ZrtpContext *zrtpContext = (ZrtpContext*) t->data;
	OrtpZrtpContext *userData = (OrtpZrtpContext*) zrtpContext->userData;


	// Do extra stuff first
	check_timer(zrtpContext, userData);


	// Check if something to receive
	rlen=rtp_session_rtp_recv_abstract(t->session->rtp.socket,m,flags,from,fromlen);
	if (rlen<=0) {
		// nothing was received or error: pass the information to caller
		return rlen;
	}

	uint8_t* rtp = m->b_rptr;
	int rtpVersion = ((rtp_header_t*)rtp)->version;

	// If plain or secured RTP
	if (rtpVersion == 2) {
		if (userData->srtpRecv != NULL && zrtp_inState(zrtpContext, SecureState)) {
			// probably srtp packet, unprotect
			err_status_t err = srtp_unprotect(userData->srtpRecv,m->b_wptr,&rlen);
			if (err != err_status_ok) {
				ortp_warning("srtp_unprotect failed; packet may be plain RTP");
			}
		}
		// in both cases (RTP plain and deciphered srtp)
		return rlen;
	}


	// if ZRTP packet, send to engine
	uint32_t *magicField=(uint32_t *)(rtp + 4);
	if (rlen >= ZRTP_MIN_MSG_LENGTH && rtpVersion==0 && ntohl(*magicField) == ZRTP_MAGIC) {
		print_zrtp_packet("received", rtp);
		uint8_t *ext_header = rtp+ZRTP_MESSAGE_OFFSET;
		uint16_t ext_length = get_zrtp_message_length(ext_header);
		char messageType[9];
		parseZrtpMessageType(messageType, ext_header);

		// Check max length
		if (rlen < 12 + ext_length + 4) {
			ortp_warning("Received malformed ZRTP-like packet: size %d (expected %d)", rlen, 12 + ext_length + 4);
			return 0;
		}

		// Check sequence number
		uint16_t seq_number = get_rtp_seqnumber(rtp);
		if (userData->last_recv_zrtp_seq_number != 0 && seq_number <= userData->last_recv_zrtp_seq_number) {
			// Discard out of order ZRTP packet
			ortp_message("Discarding received out of order zrtp packet: %d (expected >%d)",
					seq_number, userData->last_recv_zrtp_seq_number);
			return 0;
		}


		// Check packet checksum
		uint32_t rcv_crc = get_zrtp_packet_crc((uint32_t*)rtp, ext_length);
		uint32_t zrtp_total_packet_length = ZRTP_MESSAGE_OFFSET + 4*ext_length + 4;
		if (!zrtp_CheckCksum(rtp, zrtp_total_packet_length-CRC_SIZE, rcv_crc)) {
			ortp_warning("Bad ZRTP packet checksum %u total %u", rcv_crc, zrtp_total_packet_length);
			return 0;
		}

		uint32_t peerssrc = ntohl(*(uint32_t*)(rtp+8));
		zrtp_processZrtpMessage(zrtpContext, ext_header, peerssrc);
		userData->last_recv_zrtp_seq_number=seq_number;
		return 0;
		}
	else {
		// Not a ZRTP packet, accept it
		return rlen;
	}
}



static int ozrtp_rtcp_recvfrom(RtpTransport *t, mblk_t *m, int flags, struct sockaddr *from, socklen_t *fromlen){
	ZrtpContext *zrtpContext = (ZrtpContext*) t->data;
	OrtpZrtpContext *userData = (OrtpZrtpContext*) zrtpContext->userData;

	int rlen = rtp_session_rtp_recv_abstract(t->session->rtcp.socket,m,flags,from,fromlen);
	if (rlen<=0) {
		// nothing was received or error: pass the information to caller
		return rlen;
	}

	uint8_t *rtcp = m->b_wptr;
	int version = ((rtcp_common_header_t *)rtcp)->version;
	if (version == 2 && userData->srtpRecv != NULL && zrtp_inState(zrtpContext, SecureState)) {
		err_status_t err = srtp_unprotect_rtcp(userData->srtpRecv,m->b_wptr,&rlen);
		if (err != err_status_ok) {
			ortp_error("srtp_unprotect failed %d ; packet discarded (may be plain RTCP)", err);
			return 0;
		}
	}

	return rlen;
}


static ortp_socket_t ozrtp_rtp_getsocket(RtpTransport *t){
  return t->session->rtp.socket;
}

static ortp_socket_t ozrtp_rtcp_getsocket(RtpTransport *t){
  return t->session->rtcp.socket;
}

static OrtpZrtpContext* createUserData(ZrtpContext *context) {
	OrtpZrtpContext *userData=ortp_new0(OrtpZrtpContext,1);
	userData->zrtpContext=context;
	userData->timerWillTriggerAt=0;
	userData->last_recv_zrtp_seq_number=0;
	userData->last_sent_zrtp_seq_number=rand()+1; // INT_MAX+1 (signed)

	userData->srtpRecv=NULL;
	userData->srtpSend=NULL;
	ortp_mutex_init(&userData->mutex,NULL);

	memset(&userData->zrtp_cb,0,sizeof(userData->zrtp_cb));
	userData->zrtp_cb.zrtp_activateTimer=&ozrtp_activateTimer;
	userData->zrtp_cb.zrtp_cancelTimer=&ozrtp_cancelTimer;
	userData->zrtp_cb.zrtp_handleGoClear=&ozrtp_handleGoClear;
	userData->zrtp_cb.zrtp_rtpSecretsOn=&ozrtp_rtpSecretsOn;
	userData->zrtp_cb.zrtp_sendDataZRTP=&ozrtp_sendDataZRTP;
	userData->zrtp_cb.zrtp_sendInfo=&ozrtp_sendInfo;
	userData->zrtp_cb.zrtp_srtpSecretsOff=&ozrtp_srtpSecretsOff;
	userData->zrtp_cb.zrtp_srtpSecretsReady=&ozrtp_srtpSecretsReady;
	userData->zrtp_cb.zrtp_synchEnter=&ozrtp_synchEnter;
	userData->zrtp_cb.zrtp_synchLeave=&ozrtp_synchLeave;
	userData->zrtp_cb.zrtp_zrtpNegotiationFailed=&ozrtp_zrtpNegotiationFailed;
	userData->zrtp_cb.zrtp_zrtpNotSuppOther=&ozrtp_zrtpNotSuppOther;

	return userData;
}

//static void initContext() {
	// Configure algorithms
	//zrtp_confClear(context);
	/* FIXMe use default ones as these methods require some unknown char*
	zrtp_addAlgo(context,zrtp_CipherAlgorithm,zrtp_Aes);
	zrtp_addAlgo(context,zrtp_HashAlgorithm,zrtp_Sha1);*/
	// CF zrtp_InitializeConfig
//}

static void ortp_zrtp_configure(ZrtpContext *context){
	zrtp_InitializeConfig(context);
	zrtp_setMandatoryOnly(context);
	zrtp_setTrustedMitM(context,FALSE);//because it is uninitialized in zrtpcpp.
	zrtp_setSasSignature(context,FALSE);//because it is uninitialized in zrtpcpp.
}

static OrtpZrtpContext* ortp_zrtp_configure_context(OrtpZrtpContext *userData, RtpSession *s, OrtpZrtpParams *params) {
	ZrtpContext *context=userData->zrtpContext;


	if (s->rtp.tr || s->rtcp.tr)
		ortp_warning("Overwriting rtp or rtcp transport with ZRTP one");

	userData->rtpt.data=context;
	userData->rtpt.t_getsocket=ozrtp_rtp_getsocket;
	userData->rtpt.t_sendto=ozrtp_rtp_sendto;
	userData->rtpt.t_recvfrom=ozrtp_rtp_recvfrom;

	userData->rtcpt.data=context;
	userData->rtcpt.t_getsocket=ozrtp_rtcp_getsocket;
	userData->rtcpt.t_sendto=ozrtp_rtcp_sendto;
	userData->rtcpt.t_recvfrom=ozrtp_rtcp_recvfrom;

	rtp_session_set_transports(s, &userData->rtpt, &userData->rtcpt);

	ortp_message("Starting ZRTP engine");
	zrtp_setEnrollmentMode(context,FALSE);//because it is uninitialized in zrtpcpp.
	
	zrtp_startZrtpEngine(context);

	return userData;
}

OrtpZrtpContext* ortp_zrtp_context_new(RtpSession *s, OrtpZrtpParams *params){
	ZrtpContext *context = zrtp_CreateWrapper();
	OrtpZrtpContext *userData=createUserData(context);
	userData->session=s;
	ortp_zrtp_configure(context);
	ortp_message("Initialized ZRTP context");
	zrtp_initializeZrtpEngine(context, &userData->zrtp_cb, userAgentStr, params->zid_file, userData, 0);
	return ortp_zrtp_configure_context(userData,s,params);
}

OrtpZrtpContext* ortp_zrtp_multistream_new(OrtpZrtpContext* activeContext, RtpSession *s, OrtpZrtpParams *params) {
	int32_t length;
	char *multiparams=NULL;
	int i=0;
	
	if (!zrtp_isMultiStreamAvailable(activeContext->zrtpContext)) {
		ortp_warning("could't add stream: mutlistream not supported by peer");
	}

	if (zrtp_isMultiStream(activeContext->zrtpContext)) {
		ortp_fatal("Error: should derive multistream from DH or preshared modes only");
	}

	multiparams=zrtp_getMultiStrParams(activeContext->zrtpContext, &length);
	
	ortp_message("ZRTP multiparams length is %d", length);
	for (;i<length;i++) {
		ortp_message("%d", multiparams[i]);
	}

	ortp_message("Initializing ZRTP context");
	ZrtpContext *context = zrtp_CreateWrapper();
	OrtpZrtpContext *userData=createUserData(context);
	userData->session=s;
	ortp_zrtp_configure(context);
	
	zrtp_initializeZrtpEngine(context, &userData->zrtp_cb, userAgentStr, params->zid_file, userData, 0);

	ortp_message("setting zrtp_setMultiStrParams");
	zrtp_setMultiStrParams(context,multiparams,length);

	return ortp_zrtp_configure_context(userData,s,params);
}

bool_t ortp_zrtp_available(){return TRUE;}



void ortp_zrtp_sas_verified(OrtpZrtpContext* ctx){
	zrtp_SASVerified(ctx->zrtpContext);
}

void ortp_zrtp_sas_reset_verified(OrtpZrtpContext* ctx){
	zrtp_resetSASVerified(ctx->zrtpContext);
}

void ortp_zrtp_context_destroy(OrtpZrtpContext *ctx) {
	ortp_message("Stopping ZRTP context");
	zrtp_stopZrtpEngine(ctx->zrtpContext);

	ortp_message("Destroying ZRTP wrapper");
	zrtp_DestroyWrapper(ctx->zrtpContext);

	ortp_message("Destroying ORTP-ZRTP mutex");
	ortp_mutex_destroy(&ctx->mutex);

	ortp_message("Destroying SRTP contexts");
	if (ctx->srtpSend != NULL) srtp_dealloc(ctx->srtpSend);
	if (ctx->srtpRecv != NULL) srtp_dealloc(ctx->srtpRecv);

	ortp_message("ORTP-ZRTP context destroyed");
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

#endif


