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

/***************************************************************************
 *            rtcp.c
 *
 *  Wed Dec  1 11:45:30 2004
 *  Copyright  2004  Simon Morlat
 *  Email simon dot morlat at linphone dot org
 ****************************************************************************/

#include <math.h>

#include "ortp/ortp.h"
#include "ortp/rtpsession.h"
#include "ortp/rtcp.h"
#include "utils.h"
#include "rtpsession_priv.h"
#include "jitterctl.h"

#define rtcp_bye_set_ssrc(b,pos,ssrc)	(b)->ssrc[pos]=htonl(ssrc)
#define rtcp_bye_get_ssrc(b,pos)		ntohl((b)->ssrc[pos])


void rtcp_common_header_init(rtcp_common_header_t *ch, RtpSession *s,int type, int rc, int bytes_len){
	rtcp_common_header_set_version(ch,2);
	rtcp_common_header_set_padbit(ch,0);
	rtcp_common_header_set_packet_type(ch,type);
	rtcp_common_header_set_rc(ch,rc);	/* as we don't yet support multi source receiving */
	rtcp_common_header_set_length(ch,(bytes_len/4)-1);
}

static mblk_t *sdes_chunk_new(uint32_t ssrc){
	mblk_t *m=allocb(RTCP_SDES_CHUNK_DEFAULT_SIZE,0);
	sdes_chunk_t *sc=(sdes_chunk_t*)m->b_rptr;
	sc->csrc=htonl(ssrc);
	m->b_wptr+=sizeof(sc->csrc);
	return m;
}


static mblk_t * sdes_chunk_append_item(mblk_t *m, rtcp_sdes_type_t sdes_type, const char *content)
{
	if ( content )
	{
		sdes_item_t si;
		si.item_type=sdes_type;
		si.len=(uint8_t) MIN(strlen(content),RTCP_SDES_MAX_STRING_SIZE);
		m=appendb(m,(char*)&si,RTCP_SDES_ITEM_HEADER_SIZE,FALSE);
		m=appendb(m,content,si.len,FALSE);
	}
	return m;
}

static void sdes_chunk_set_ssrc(mblk_t *m, uint32_t ssrc){
	sdes_chunk_t *sc=(sdes_chunk_t*)m->b_rptr;
	sc->csrc=htonl(ssrc);
}

#define sdes_chunk_get_ssrc(m) ntohl(((sdes_chunk_t*)((m)->b_rptr))->csrc)

static mblk_t * sdes_chunk_pad(mblk_t *m){
	return appendb(m,"",1,TRUE);
}

static mblk_t * sdes_chunk_set_minimal_items(mblk_t *m, const char *cname) {
	if (cname == NULL) {
		cname = "Unknown";
	}
	return sdes_chunk_append_item(m, RTCP_SDES_CNAME, cname);
}

static mblk_t * sdes_chunk_set_full_items(mblk_t *m, const char *cname,
	const char *name, const char *email, const char *phone, const char *loc,
	const char *tool, const char *note) {
	m = sdes_chunk_set_minimal_items(m, cname);
	m = sdes_chunk_append_item(m, RTCP_SDES_NAME, name);
	m = sdes_chunk_append_item(m, RTCP_SDES_EMAIL, email);
	m = sdes_chunk_append_item(m, RTCP_SDES_PHONE, phone);
	m = sdes_chunk_append_item(m, RTCP_SDES_LOC, loc);
	m = sdes_chunk_append_item(m, RTCP_SDES_TOOL, tool);
	m = sdes_chunk_append_item(m, RTCP_SDES_NOTE, note);
	m = sdes_chunk_pad(m);
	return m;
}

/**
 * Set session's SDES item for automatic sending of RTCP compound packets.
 * If some items are not specified, use NULL.
**/
void rtp_session_set_source_description(RtpSession *session, const char *cname,
	const char *name, const char *email, const char *phone, const char *loc,
	const char *tool, const char *note) {
	mblk_t *m;
	mblk_t *chunk = sdes_chunk_new(session->snd.ssrc);
	sdes_chunk_set_full_items(chunk, cname, name, email, phone, loc, tool, note);
	if (session->full_sdes != NULL)
		freemsg(session->full_sdes);
	session->full_sdes = chunk;
	chunk = sdes_chunk_new(session->snd.ssrc);
	m = sdes_chunk_set_minimal_items(chunk, cname);
	m = sdes_chunk_pad(m);
	session->minimal_sdes = chunk;
}

void
rtp_session_add_contributing_source(RtpSession *session, uint32_t csrc,
	const char *cname, const char *name, const char *email, const char *phone,
	const char *loc, const char *tool, const char *note) {
	mblk_t *chunk = sdes_chunk_new(csrc);
	sdes_chunk_set_full_items(chunk, cname, name, email, phone, loc, tool, note);
	putq(&session->contributing_sources, chunk);
}


mblk_t* rtp_session_create_rtcp_sdes_packet(RtpSession *session)
{
    mblk_t *mp=allocb(sizeof(rtcp_common_header_t),0);
	rtcp_common_header_t *rtcp;
    mblk_t *tmp,*m=mp;
	queue_t *q;
	int rc=0;
    rtcp = (rtcp_common_header_t*)mp->b_wptr;
	mp->b_wptr+=sizeof(rtcp_common_header_t);

	/* concatenate all sdes chunks */
	sdes_chunk_set_ssrc(session->full_sdes,session->snd.ssrc);
	m=concatb(m,dupmsg(session->full_sdes));
	rc++;

	q=&session->contributing_sources;
    for (tmp=qbegin(q); !qend(q,tmp); tmp=qnext(q,mp)){
		m=concatb(m,dupmsg(tmp));
		rc++;
	}
	rtcp_common_header_init(rtcp,session,RTCP_SDES,rc,msgdsize(mp));
    return mp;
}


mblk_t *rtcp_create_simple_bye_packet(uint32_t ssrc, const char *reason)
{
	int packet_size;
	int strsize = 0;
	int strpadding = 0;
	mblk_t *mp;
	rtcp_bye_t *rtcp;

	packet_size	= RTCP_BYE_HEADER_SIZE;
	if (reason!=NULL) {
		strsize=(int)MIN(strlen(reason),RTCP_BYE_REASON_MAX_STRING_SIZE);
		if (strsize > 0) {
			strpadding = 3 - (strsize % 4);
			packet_size += 1 + strsize + strpadding;
		}
    	}
	mp	= allocb(packet_size, 0);

	rtcp = (rtcp_bye_t*)mp->b_rptr;
	rtcp_common_header_init(&rtcp->ch,NULL,RTCP_BYE,1,packet_size);
	rtcp->ssrc[0] = htonl(ssrc);
	mp->b_wptr += RTCP_BYE_HEADER_SIZE;
	/* append the reason if any*/
	if (reason!=NULL) {
		const char pad[] = {0, 0, 0};
		unsigned char strsize_octet = (unsigned char)strsize;

		appendb(mp, (const char*)&strsize_octet, 1, FALSE);
		appendb(mp, reason,strsize, FALSE);
		appendb(mp, pad,strpadding, FALSE);
	}
	return mp;
}

void rtp_session_remove_contributing_sources(RtpSession *session, uint32_t ssrc)
{
	queue_t *q=&session->contributing_sources;
	mblk_t *tmp;
	for (tmp=qbegin(q); !qend(q,tmp); tmp=qnext(q,tmp)){
		uint32_t csrc=sdes_chunk_get_ssrc(tmp);
		if (csrc==ssrc) {
			remq(q,tmp);
			break;
		}
	}
	tmp=rtcp_create_simple_bye_packet(ssrc, NULL);
	rtp_session_rtcp_send(session,tmp);
}


static void sender_info_init(sender_info_t *info, RtpSession *session){
	struct timeval tv;
	uint64_t ntp;
	ortp_gettimeofday(&tv,NULL);
	ntp=ortp_timeval_to_ntp(&tv);
	info->ntp_timestamp_msw=htonl(ntp >>32);
	info->ntp_timestamp_lsw=htonl(ntp & 0xFFFFFFFF);
	info->rtp_timestamp=htonl(session->rtp.snd_last_ts);
	info->senders_packet_count=(uint32_t) htonl((u_long) session->rtp.stats.packet_sent);
	info->senders_octet_count=(uint32_t) htonl((u_long) session->rtp.sent_payload_bytes);
	session->rtp.last_rtcp_packet_count=session->rtp.stats.packet_sent;
}



static void report_block_init(report_block_t *b, RtpSession *session){
	int packet_loss=0;
	int loss_fraction=0;
	RtpStream *stream=&session->rtp;
	uint32_t delay_snc_last_sr=0;
	uint32_t fl_cnpl;

	/* compute the statistics */
	if (stream->hwrcv_since_last_SR!=0){
		int expected_packets=stream->hwrcv_extseq - stream->hwrcv_seq_at_last_SR;

		if ( session->flags & RTCP_OVERRIDE_LOST_PACKETS ) {
			/* If the test mode is enabled, replace the lost packet field with
			the test vector value set by rtp_session_rtcp_set_lost_packet_value() */
			packet_loss = session->lost_packets_test_vector;
			/* The test value is the definite cumulative one, no need to increment
			it each time a packet is sent */
			stream->stats.cum_packet_loss = packet_loss;
		}else {
			/* Normal mode */
			packet_loss = expected_packets - stream->hwrcv_since_last_SR;
			stream->stats.cum_packet_loss += packet_loss;
		}
		if (expected_packets>0){/*prevent division by zero and negative loss fraction*/
			loss_fraction=(int)( 256 * packet_loss) / expected_packets;
			/*make sure this fits into 8 bit unsigned*/
			if (loss_fraction>255) loss_fraction=255;
			else if (loss_fraction<0) loss_fraction=0;
		}else{
			loss_fraction=0;
		}
	}
	/* reset them */
	stream->hwrcv_since_last_SR=0;
	stream->hwrcv_seq_at_last_SR=stream->hwrcv_extseq;

	if (stream->last_rcv_SR_time.tv_sec!=0){
		struct timeval now;
		double delay;
		ortp_gettimeofday(&now,NULL);
		delay= (now.tv_sec-stream->last_rcv_SR_time.tv_sec)+ ((now.tv_usec-stream->last_rcv_SR_time.tv_usec)*1e-6);
		delay= (delay*65536);
		delay_snc_last_sr=(uint32_t) delay;
	}

	b->ssrc=htonl(session->rcv.ssrc);
	fl_cnpl=((loss_fraction&0xFF)<<24) | (stream->stats.cum_packet_loss & 0xFFFFFF);
	b->fl_cnpl=htonl(fl_cnpl);
	if ( session->flags & RTCP_OVERRIDE_JITTER ) {
		/* If the test mode is enabled, replace the interarrival jitter field with the test vector value set by rtp_session_rtcp_set_jitter_value() */
		b->interarrival_jitter = htonl( session->interarrival_jitter_test_vector );
	}
	else {
		/* Normal mode */
		b->interarrival_jitter = htonl( (uint32_t) stream->jittctl.inter_jitter );
	}
	b->ext_high_seq_num_rec=htonl(stream->hwrcv_extseq);
	b->delay_snc_last_sr=htonl(delay_snc_last_sr);
	if ( session->flags & RTCP_OVERRIDE_DELAY ) {
		/* If the test mode is enabled, modifies the returned ts (LSR) so it matches the value of the delay test value */
		/* refer to the rtp_session_rtcp_set_delay_value() documentation for further explanations */
		double new_ts = ( (double)stream->last_rcv_SR_time.tv_sec + (double)stream->last_rcv_SR_time.tv_usec * 1e-6 ) - ( (double)session->delay_test_vector / 1000.0 );
		uint32_t new_ts2;

		/* Converting the time format in RFC3550 (par. 4) format */
		new_ts += 2208988800.0; /* 2208988800 is the number of seconds from 1900 to 1970 (January 1, Oh TU) */
		new_ts = 65536.0 * new_ts;
		/* This non-elegant way of coding fits with the gcc and the icc compilers */
		new_ts2 = (uint32_t)( (uint64_t)new_ts & 0xffffffff );
		b->lsr = htonl( new_ts2 );
	}
	else {
		/* Normal mode */
		b->lsr = htonl( stream->last_rcv_SR_ts );
	}
}

static void extended_statistics( RtpSession *session, report_block_t * rb ) {
	/* the jitter raw value is kept in stream clock units */
	uint32_t jitter = session->rtp.jittctl.inter_jitter;
	session->rtp.stats.sent_rtcp_packets ++;
	session->rtp.jitter_stats.sum_jitter += jitter;
	session->rtp.jitter_stats.jitter=jitter;
	/* stores the biggest jitter for that session and its date (in millisecond) since Epoch */
	if ( jitter > session->rtp.jitter_stats.max_jitter ) {
		struct timeval now;

		session->rtp.jitter_stats.max_jitter = jitter ;

		ortp_gettimeofday( &now, NULL );
		session->rtp.jitter_stats.max_jitter_ts = ( now.tv_sec * 1000LL ) + ( now.tv_usec / 1000LL );
	}
	/* compute mean jitter buffer size */
	session->rtp.jitter_stats.jitter_buffer_size_ms=jitter_control_compute_mean_size(&session->rtp.jittctl);
}


static int rtcp_sr_init(RtpSession *session, uint8_t *buf, int size){
	rtcp_sr_t *sr=(rtcp_sr_t*)buf;
	int rr=(session->rtp.stats.packet_recv>0);
	int sr_size=sizeof(rtcp_sr_t)-sizeof(report_block_t)+(rr*sizeof(report_block_t));
	if (size<sr_size) return 0;
	rtcp_common_header_init(&sr->ch,session,RTCP_SR,rr,sr_size);
	sr->ssrc=htonl(session->snd.ssrc);
	sender_info_init(&sr->si,session);
	/*only include a report block if packets were received*/
	if (rr) {
		report_block_init( &sr->rb[0], session );
		extended_statistics( session, &sr->rb[0] );
	}
	return sr_size;
}

static int rtcp_rr_init(RtpSession *session, uint8_t *buf, int size){
	rtcp_rr_t *rr=(rtcp_rr_t*)buf;
	if (size<sizeof(rtcp_rr_t)) return 0;
	rtcp_common_header_init(&rr->ch,session,RTCP_RR,1,sizeof(rtcp_rr_t));
	rr->ssrc=htonl(session->snd.ssrc);
	report_block_init(&rr->rb[0],session);
	extended_statistics( session, &rr->rb[0] );
	return sizeof(rtcp_rr_t);
}

static int rtcp_app_init(RtpSession *session, uint8_t *buf, uint8_t subtype, const char *name, int size){
	rtcp_app_t *app=(rtcp_app_t*)buf;
	if (size<sizeof(rtcp_app_t)) return 0;
	rtcp_common_header_init(&app->ch,session,RTCP_APP,subtype,size);
	app->ssrc=htonl(session->snd.ssrc);
	memset(app->name,0,4);
	strncpy(app->name,name,4);
	return sizeof(rtcp_app_t);
}

static mblk_t * make_rr(RtpSession *session){
	mblk_t *cm=NULL;
	mblk_t *sdes=NULL;

	cm=allocb(sizeof(rtcp_sr_t),0);
	cm->b_wptr+=rtcp_rr_init(session,cm->b_wptr,sizeof(rtcp_rr_t));
	/* make a SDES packet */
	if (session->full_sdes!=NULL)
		sdes=rtp_session_create_rtcp_sdes_packet(session);
	/* link them */
	cm->b_cont=sdes;
	return cm;
}

static mblk_t * make_sr(RtpSession *session){
	mblk_t *cm=NULL;
	mblk_t *sdes=NULL;

	cm=allocb(sizeof(rtcp_sr_t),0);
	cm->b_wptr+=rtcp_sr_init(session,cm->b_wptr,sizeof(rtcp_sr_t));
	/* make a SDES packet */
	if (session->full_sdes!=NULL)
		sdes=rtp_session_create_rtcp_sdes_packet(session);
	/* link them */
	cm->b_cont=sdes;
	return cm;
}

static void notify_sent_rtcp(RtpSession *session, mblk_t *rtcp){
	if (session->eventqs!=NULL){
		OrtpEvent *ev;
		OrtpEventData *evd;
		ev=ortp_event_new(ORTP_EVENT_RTCP_PACKET_EMITTED);
		evd=ortp_event_get_data(ev);
		evd->packet=dupmsg(rtcp);
		msgpullup(evd->packet,-1);
		rtp_session_dispatch_event(session,ev);
	}
}

static void rtp_session_rtcp_xr_process_send(RtpSession *session) {
	RtpStream *st = &session->rtp;
	RtcpStream *rtcp_st = &session->rtcp;

	if ((rtcp_st->xr_conf.rcvr_rtt_mode != OrtpRtcpXrRcvrRttNone)
		&& ((st->snd_last_ts - rtcp_st->last_rtcp_xr_rcvr_rtt_s) > rtcp_st->rtcp_xr_rcvr_rtt_interval)) {
		rtcp_st->last_rtcp_xr_rcvr_rtt_s = st->snd_last_ts;
		rtp_session_send_rtcp_xr_rcvr_rtt(session);
	}
	if ((rtcp_st->xr_conf.stat_summary_enabled == TRUE)
		&& ((st->snd_last_ts - rtcp_st->last_rtcp_xr_stat_summary_s) > rtcp_st->rtcp_xr_stat_summary_interval)) {
		rtcp_st->last_rtcp_xr_stat_summary_s = st->snd_last_ts;
		rtp_session_send_rtcp_xr_stat_summary(session);
	}
	if ((rtcp_st->xr_conf.voip_metrics_enabled == TRUE)
		&& ((st->snd_last_ts - rtcp_st->last_rtcp_xr_voip_metrics_s) > rtcp_st->rtcp_xr_voip_metrics_interval)) {
		rtcp_st->last_rtcp_xr_voip_metrics_s = st->snd_last_ts;
		rtp_session_send_rtcp_xr_voip_metrics(session);
	}
}

void rtp_session_rtcp_process_send(RtpSession *session){
	RtpStream *st=&session->rtp;
	RtcpStream *rtcp_st=&session->rtcp;
	mblk_t *m;
	if (st->rcv_last_app_ts - rtcp_st->last_rtcp_report_snt_r > rtcp_st->rtcp_report_snt_interval_r
		|| st->snd_last_ts - rtcp_st->last_rtcp_report_snt_s > rtcp_st->rtcp_report_snt_interval_s){
		rtcp_st->last_rtcp_report_snt_r=st->rcv_last_app_ts;
		rtcp_st->last_rtcp_report_snt_s=st->snd_last_ts;
		m=make_sr(session);
		/* send the compound packet */
		notify_sent_rtcp(session,m);
		ortp_message("Sending RTCP SR compound message on session [%p].",session);
		rtp_session_rtcp_send(session,m);
	}
	if (session->rtcp.xr_conf.enabled == TRUE) {
		rtp_session_rtcp_xr_process_send(session);
	}
}

void rtp_session_rtcp_process_recv(RtpSession *session){
	RtpStream *st=&session->rtp;
	RtcpStream *rtcp_st=&session->rtcp;
	mblk_t *m=NULL;
	bool_t is_sr=FALSE;
	if (st->rcv_last_app_ts - rtcp_st->last_rtcp_report_snt_r > rtcp_st->rtcp_report_snt_interval_r
		|| st->snd_last_ts - rtcp_st->last_rtcp_report_snt_s > rtcp_st->rtcp_report_snt_interval_s){
		rtcp_st->last_rtcp_report_snt_r=st->rcv_last_app_ts;
		rtcp_st->last_rtcp_report_snt_s=st->snd_last_ts;

		if (session->rtp.last_rtcp_packet_count<session->rtp.stats.packet_sent){
			m=make_sr(session);
			session->rtp.last_rtcp_packet_count=session->rtp.stats.packet_sent;
			is_sr=TRUE;
		}else if (session->rtp.stats.packet_recv>0){
			/*don't send RR when no packet are received yet*/
			m=make_rr(session);
			is_sr=FALSE;
		}
		if (m!=NULL){
			/* send the compound packet */
			notify_sent_rtcp(session,m);
			ortp_message("Sending RTCP %s compound message on session [%p].",(is_sr?"SR":"RR"),session);
			rtp_session_rtcp_send(session,m);
		}
	}
}

void rtp_session_send_rtcp_APP(RtpSession *session, uint8_t subtype, const char *name, const uint8_t *data, int datalen){
	mblk_t *h=allocb(sizeof(rtcp_app_t),0);
	mblk_t *d;
	h->b_wptr+=rtcp_app_init(session,h->b_wptr,subtype,name,datalen+sizeof(rtcp_app_t));
	d=esballoc((uint8_t*)data,datalen,0,NULL);
	d->b_wptr+=datalen;
	h->b_cont=d;
	rtp_session_rtcp_send(session,h);
}

/**
 * Sends a RTCP bye packet.
 *@param session RtpSession
 *@param reason the reason phrase.
**/
int
rtp_session_bye(RtpSession *session, const char *reason)
{
    mblk_t *cm;
    mblk_t *sdes = NULL;
    mblk_t *bye = NULL;
    int ret;

    /* Make a BYE packet (will be on the end of the compund packet). */
    bye = rtcp_create_simple_bye_packet(session->snd.ssrc, reason);

    /* SR or RR is determined by the fact whether stream was sent*/
    if (session->rtp.stats.packet_sent>0)
    {
        cm = allocb(sizeof(rtcp_sr_t), 0);
        cm->b_wptr += rtcp_sr_init(session,cm->b_wptr, sizeof(rtcp_sr_t));
        /* make a SDES packet */
        sdes = rtp_session_create_rtcp_sdes_packet(session);
        /* link them */
        concatb(concatb(cm, sdes), bye);
    } else if (session->rtp.stats.packet_recv>0){
        /* make a RR packet */
        cm = allocb(sizeof(rtcp_rr_t), 0);
        cm->b_wptr += rtcp_rr_init(session, cm->b_wptr, sizeof(rtcp_rr_t));
        /* link them */
        cm->b_cont = bye;
    }else cm=bye;

    /* Send compound packet. */
    ret = rtp_session_rtcp_send(session, cm);

    return ret;
}


static int rtcp_xr_header_init(uint8_t *buf, RtpSession *session, int bytes_len) {
	rtcp_xr_header_t *header = (rtcp_xr_header_t *)buf;
	rtcp_common_header_init(&header->ch, session, RTCP_XR, 0, bytes_len);
	header->ssrc = htonl(session->snd.ssrc);
	return sizeof(rtcp_xr_header_t);
}

static int rtcp_xr_rcvr_rtt_init(uint8_t *buf, RtpSession *session) {
	struct timeval tv;
	uint64_t ntp;
	rtcp_xr_rcvr_rtt_report_block_t *block = (rtcp_xr_rcvr_rtt_report_block_t *)buf;

	block->bh.bt = RTCP_XR_RCVR_RTT;
	block->bh.flags = 0; // Reserved bits
	block->bh.length = htons(2);
	ortp_gettimeofday(&tv, NULL);
	ntp = ortp_timeval_to_ntp(&tv);
	block->ntp_timestamp_msw = htonl(ntp >> 32);
	block->ntp_timestamp_lsw = htonl(ntp & 0xFFFFFFFF);
	return sizeof(rtcp_xr_rcvr_rtt_report_block_t);
}

static int rtcp_xr_dlrr_init(uint8_t *buf, RtpSession *session) {
	uint32_t dlrr = 0;
	rtcp_xr_dlrr_report_block_t *block = (rtcp_xr_dlrr_report_block_t *)buf;

	block->bh.bt = RTCP_XR_DLRR;
	block->bh.flags = 0; // Reserved bits
	block->bh.length = htons(3);
	block->content[0].ssrc = htonl(rtp_session_get_recv_ssrc(session));
	block->content[0].lrr = htonl(session->rtcp_xr_stats.last_rcvr_rtt_ts);
	if (session->rtcp_xr_stats.last_rcvr_rtt_time.tv_sec != 0) {
		struct timeval now;
		double delay;
		ortp_gettimeofday(&now, NULL);
		delay = ((now.tv_sec - session->rtcp_xr_stats.last_rcvr_rtt_time.tv_sec)
			+ ((now.tv_usec - session->rtcp_xr_stats.last_rcvr_rtt_time.tv_usec) * 1e-6)) * 65536;
		dlrr = (uint32_t) delay;
	}
	block->content[0].dlrr = htonl(dlrr);
	return sizeof(rtcp_xr_dlrr_report_block_t);
}

static int rtcp_xr_stat_summary_init(uint8_t *buf, RtpSession *session) {
	rtcp_xr_stat_summary_report_block_t *block = (rtcp_xr_stat_summary_report_block_t *)buf;
	uint16_t last_rcv_seq = session->rtp.hwrcv_extseq & 0xFFFF;
	uint8_t flags = session->rtcp.xr_conf.stat_summary_flags;
	uint32_t expected_packets;
	uint32_t lost_packets = 0;
	uint32_t dup_packets = session->rtcp_xr_stats.dup_since_last_stat_summary;

	/* Compute lost and duplicate packets statistics */
	if (flags & OrtpRtcpXrStatSummaryLoss) {
		uint32_t no_duplicate_received = session->rtcp_xr_stats.rcv_since_last_stat_summary - dup_packets;
		expected_packets = last_rcv_seq - session->rtcp_xr_stats.rcv_seq_at_last_stat_summary;
		lost_packets = (expected_packets > session->rtcp_xr_stats.rcv_since_last_stat_summary)
			? (expected_packets - no_duplicate_received) : 0;
	}

	block->bh.bt = RTCP_XR_STAT_SUMMARY;
	block->bh.flags = flags;
	block->bh.length = htons(9);
	block->ssrc = htonl(rtp_session_get_recv_ssrc(session));
	block->begin_seq = htons(session->rtcp_xr_stats.rcv_seq_at_last_stat_summary + 1);
	block->end_seq = htons(last_rcv_seq + 1);
	block->lost_packets = htonl(lost_packets);
	block->dup_packets = htonl(dup_packets);
	if ((flags & OrtpRtcpXrStatSummaryJitt)
		&& (session->rtcp_xr_stats.rcv_since_last_stat_summary > 0)) {
		block->min_jitter = htonl(session->rtcp_xr_stats.min_jitter_since_last_stat_summary);
		block->max_jitter = htonl(session->rtcp_xr_stats.max_jitter_since_last_stat_summary);
		block->mean_jitter = htonl((session->rtcp_xr_stats.rcv_since_last_stat_summary > 1)
			? (uint32_t)session->rtcp_xr_stats.newm_jitter_since_last_stat_summary : 0);
		block->dev_jitter = htonl((session->rtcp_xr_stats.rcv_since_last_stat_summary > 2)
			? (uint32_t)sqrt(session->rtcp_xr_stats.news_jitter_since_last_stat_summary / (session->rtcp_xr_stats.rcv_since_last_stat_summary - 2)) : 0);
	} else {
		block->min_jitter = htonl(0);
		block->max_jitter = htonl(0);
		block->mean_jitter = htonl(0);
		block->dev_jitter = htonl(0);
	}
	if ((flags & (OrtpRtcpXrStatSummaryTTL | OrtpRtcpXrStatSummaryHL))
		&& (session->rtcp_xr_stats.rcv_since_last_stat_summary > 0)) {
		block->min_ttl_or_hl = session->rtcp_xr_stats.min_ttl_or_hl_since_last_stat_summary;
		block->max_ttl_or_hl = session->rtcp_xr_stats.max_ttl_or_hl_since_last_stat_summary;
		block->mean_ttl_or_hl = (session->rtcp_xr_stats.rcv_since_last_stat_summary > 0)
			? (uint8_t)session->rtcp_xr_stats.newm_ttl_or_hl_since_last_stat_summary : 0;
		block->dev_ttl_or_hl = (session->rtcp_xr_stats.rcv_since_last_stat_summary > 1)
			? (uint8_t)sqrt(session->rtcp_xr_stats.news_ttl_or_hl_since_last_stat_summary / (session->rtcp_xr_stats.rcv_since_last_stat_summary - 1)) : 0;
	} else {
		block->min_ttl_or_hl = 0;
		block->max_ttl_or_hl = 0;
		block->mean_ttl_or_hl = 0;
		block->dev_ttl_or_hl = 0;
	}

	session->rtcp_xr_stats.rcv_seq_at_last_stat_summary = last_rcv_seq;
	session->rtcp_xr_stats.rcv_since_last_stat_summary = 0;
	session->rtcp_xr_stats.dup_since_last_stat_summary = 0;

	return sizeof(rtcp_xr_stat_summary_report_block_t);
}

static uint8_t calc_rate(double d1, double d2) {
	double rate = (d1 / d2) * 256;
	uint32_t int_rate = (uint32_t)rate;
	if (int_rate > 255) int_rate = 255;
	return (uint8_t)int_rate;
}

static int rtcp_xr_voip_metrics_init(uint8_t *buf, RtpSession *session) {
	JBParameters jbparams;
	uint32_t expected_packets;
	uint32_t lost_packets;
	rtcp_xr_voip_metrics_report_block_t *block = (rtcp_xr_voip_metrics_report_block_t *)buf;
	float rtt = rtp_session_get_round_trip_propagation(session);
	uint16_t int_rtt = (rtt >= 0) ? (rtt * 1000) : 0;
	float qi = -1;
	float lq_qi = -1;

	rtp_session_get_jitter_buffer_params(session, &jbparams);
	if (session->rtcp.xr_media_callbacks.average_qi != NULL) {
		qi = session->rtcp.xr_media_callbacks.average_qi(session->rtcp.xr_media_callbacks.userdata);
	}
	if (session->rtcp.xr_media_callbacks.average_lq_qi != NULL) {
		lq_qi = session->rtcp.xr_media_callbacks.average_lq_qi(session->rtcp.xr_media_callbacks.userdata);
	}

	block->bh.bt = RTCP_XR_VOIP_METRICS;
	block->bh.flags = 0; // Reserved bits
	block->bh.length = htons(8);
	block->ssrc = htonl(rtp_session_get_recv_ssrc(session));
	block->gmin = RTCP_XR_GMIN;

	// Fill RX config
	block->rx_config = 0;
	if (jbparams.adaptive) {
		block->rx_config |= RTCP_XR_VOIP_METRICS_CONFIG_JBA_ADA;
	} else {
		block->rx_config |= RTCP_XR_VOIP_METRICS_CONFIG_JBA_NON;
	}
	if (session->rtcp.xr_media_callbacks.plc != NULL) {
		switch (session->rtcp.xr_media_callbacks.plc(session->rtcp.xr_media_callbacks.userdata)) {
			default:
			case OrtpRtcpXrNoPlc:
				block->rx_config |= RTCP_XR_VOIP_METRICS_CONFIG_PLC_UNS;
				break;
			case OrtpRtcpXrSilencePlc:
				block->rx_config |= RTCP_XR_VOIP_METRICS_CONFIG_PLC_DIS;
				break;
			case OrtpRtcpXrEnhancedPlc:
				block->rx_config |= RTCP_XR_VOIP_METRICS_CONFIG_PLC_ENH;
				break;
		}
	} else {
		block->rx_config |= RTCP_XR_VOIP_METRICS_CONFIG_PLC_UNS;
	}

	// Fill JB fields
	block->jb_nominal = htons((uint16_t)jbparams.nom_size);
	if (jbparams.adaptive) {
		block->jb_maximum = htons((session->rtp.jittctl.adapt_jitt_comp_ts * 1000) / session->rtp.jittctl.clock_rate);
	} else {
		block->jb_maximum = block->jb_nominal;
	}
	block->jb_abs_max = htons(65535);

	if (session->rtcp_xr_stats.rcv_count > 0) {
		expected_packets = session->rtcp_xr_stats.last_rcv_seq - session->rtcp_xr_stats.first_rcv_seq + 1;
		lost_packets = expected_packets - session->rtcp_xr_stats.rcv_count;
		block->loss_rate = calc_rate((double)lost_packets, (double)expected_packets);
		block->discard_rate = calc_rate((double)session->rtcp_xr_stats.discarded_count, (double)expected_packets);
		// TODO: fill burst_density, gap_density, burst_duration, gap_duration
		block->burst_density = 0;
		block->gap_density = 0;
		block->burst_duration = htons(0);
		block->gap_duration = htons(0);
		block->round_trip_delay = htons(int_rtt);
		// TODO: fill end_system_delay
		block->end_system_delay = htons(0);
		if (session->rtcp.xr_media_callbacks.signal_level != NULL) {
			block->signal_level = session->rtcp.xr_media_callbacks.signal_level(session->rtcp.xr_media_callbacks.userdata);
		} else {
			block->signal_level = ORTP_RTCP_XR_UNAVAILABLE_PARAMETER;
		}
		if (session->rtcp.xr_media_callbacks.noise_level != NULL) {
			block->noise_level = session->rtcp.xr_media_callbacks.noise_level(session->rtcp.xr_media_callbacks.userdata);
		} else {
			block->noise_level = ORTP_RTCP_XR_UNAVAILABLE_PARAMETER;
		}
		block->rerl = ORTP_RTCP_XR_UNAVAILABLE_PARAMETER;
		if (qi < 0) {
			block->r_factor = ORTP_RTCP_XR_UNAVAILABLE_PARAMETER;
		} else {
			block->r_factor = (uint8_t)(qi * 20);
		}
		block->ext_r_factor = ORTP_RTCP_XR_UNAVAILABLE_PARAMETER;
		if (lq_qi < 0) {
			block->mos_lq = ORTP_RTCP_XR_UNAVAILABLE_PARAMETER;
		} else {
			block->mos_lq = (uint8_t)(qi * 10);
			if (block->mos_lq < 10) block->mos_lq = 10;
		}
		if (qi < 0) {
			block->mos_cq = ORTP_RTCP_XR_UNAVAILABLE_PARAMETER;
		} else {
			block->mos_cq = (uint8_t)(qi * 10);
			if (block->mos_cq < 10) block->mos_cq = 10;
		}
	} else {
		block->loss_rate = 0;
		block->discard_rate = 0;
		block->burst_density = 0;
		block->gap_density = 0;
		block->burst_duration = htons(0);
		block->gap_duration = htons(0);
		block->round_trip_delay = htons(0);
		block->end_system_delay = htons(0);
		block->signal_level = ORTP_RTCP_XR_UNAVAILABLE_PARAMETER;
		block->noise_level = ORTP_RTCP_XR_UNAVAILABLE_PARAMETER;
		block->rerl = ORTP_RTCP_XR_UNAVAILABLE_PARAMETER;
		block->r_factor = ORTP_RTCP_XR_UNAVAILABLE_PARAMETER;
		block->ext_r_factor = ORTP_RTCP_XR_UNAVAILABLE_PARAMETER;
		block->mos_lq = ORTP_RTCP_XR_UNAVAILABLE_PARAMETER;
		block->mos_cq = ORTP_RTCP_XR_UNAVAILABLE_PARAMETER;
	}
	return sizeof(rtcp_xr_voip_metrics_report_block_t);
}

void rtp_session_send_rtcp_xr_rcvr_rtt(RtpSession *session) {
	int size = sizeof(rtcp_xr_header_t) + sizeof(rtcp_xr_rcvr_rtt_report_block_t);
	mblk_t *h = allocb(size, 0);
	h->b_wptr += rtcp_xr_header_init(h->b_wptr, session, size);
	h->b_wptr += rtcp_xr_rcvr_rtt_init(h->b_wptr, session);
	notify_sent_rtcp(session, h);
	rtp_session_rtcp_send(session, h);
}

void rtp_session_send_rtcp_xr_dlrr(RtpSession *session) {
	int size = sizeof(rtcp_xr_header_t) + sizeof(rtcp_xr_dlrr_report_block_t);
	mblk_t *h = allocb(size, 0);
	h->b_wptr += rtcp_xr_header_init(h->b_wptr, session, size);
	h->b_wptr += rtcp_xr_dlrr_init(h->b_wptr, session);
	notify_sent_rtcp(session, h);
	rtp_session_rtcp_send(session, h);
}

void rtp_session_send_rtcp_xr_stat_summary(RtpSession *session) {
	int size = sizeof(rtcp_xr_header_t) + sizeof(rtcp_xr_stat_summary_report_block_t);
	mblk_t *h = allocb(size, 0);
	h->b_wptr += rtcp_xr_header_init(h->b_wptr, session, size);
	h->b_wptr += rtcp_xr_stat_summary_init(h->b_wptr, session);
	notify_sent_rtcp(session, h);
	rtp_session_rtcp_send(session, h);
}

void rtp_session_send_rtcp_xr_voip_metrics(RtpSession *session) {
	int size = sizeof(rtcp_xr_header_t) + sizeof(rtcp_xr_voip_metrics_report_block_t);
	mblk_t *h = allocb(size, 0);
	h->b_wptr += rtcp_xr_header_init(h->b_wptr, session, size);
	h->b_wptr += rtcp_xr_voip_metrics_init(h->b_wptr, session);
	notify_sent_rtcp(session, h);
	rtp_session_rtcp_send(session, h);
}


static mblk_t * rtp_session_create_rtcp_fb_pli(RtpSession *session) {
	int size = sizeof(rtcp_common_header_t) + sizeof(rtcp_fb_header_t);
	mblk_t *h= allocb(size, 0);
	rtcp_common_header_t *ch;
	rtcp_fb_header_t *fbh;

	/* Fill PLI */
	ch = (rtcp_common_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_common_header_t);
	fbh = (rtcp_fb_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_header_t);
	fbh->packet_sender_ssrc = htonl(rtp_session_get_send_ssrc(session));
	fbh->media_source_ssrc = htonl(rtp_session_get_recv_ssrc(session));

	/* Fill common header */
	rtcp_common_header_init(ch, session, RTCP_PSFB, RTCP_PSFB_PLI, msgdsize(h));

	return h;
}

static mblk_t * rtp_session_create_rtcp_fb_fir(RtpSession *session) {
	int size = sizeof(rtcp_common_header_t) + sizeof(rtcp_fb_header_t) + sizeof(rtcp_fb_fir_fci_t);
	mblk_t *h = allocb(size, 0);
	rtcp_common_header_t *ch;
	rtcp_fb_header_t *fbh;
	rtcp_fb_fir_fci_t *fci;

	/* Fill FIR */
	ch = (rtcp_common_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_common_header_t);
	fbh = (rtcp_fb_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_header_t);
	fci = (rtcp_fb_fir_fci_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_fir_fci_t);
	fbh->packet_sender_ssrc = htonl(0);
	fbh->media_source_ssrc = htonl(rtp_session_get_recv_ssrc(session));
	fci->ssrc = htonl(rtp_session_get_send_ssrc(session));
	fci->seq_nr = session->rtcp.rtcp_fb_fir_seq_nr++;
	fci->pad1 = 0;
	fci->pad2 = 0;

	/* Fill common header */
	rtcp_common_header_init(ch, session, RTCP_PSFB, RTCP_PSFB_FIR, msgdsize(h));

	return h;
}

static mblk_t * rtp_session_create_rtcp_fb_sli(RtpSession *session, uint16_t first, uint16_t number, uint8_t picture_id) {
	int size = sizeof(rtcp_common_header_t) + sizeof(rtcp_fb_header_t) + sizeof(rtcp_fb_sli_fci_t);
	mblk_t *h = allocb(size, 0);
	rtcp_common_header_t *ch;
	rtcp_fb_header_t *fbh;
	rtcp_fb_sli_fci_t *fci;

	/* Fill SLI */
	ch = (rtcp_common_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_common_header_t);
	fbh = (rtcp_fb_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_header_t);
	fci = (rtcp_fb_sli_fci_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_sli_fci_t);
	fbh->packet_sender_ssrc = htonl(rtp_session_get_send_ssrc(session));
	fbh->media_source_ssrc = htonl(rtp_session_get_recv_ssrc(session));
	rtcp_fb_sli_fci_set_first(fci, first);
	rtcp_fb_sli_fci_set_number(fci, number);
	rtcp_fb_sli_fci_set_picture_id(fci, picture_id);

	/* Fill common header */
	rtcp_common_header_init(ch, session, RTCP_PSFB, RTCP_PSFB_SLI, msgdsize(h));

	return h;
}

static mblk_t * rtp_session_create_rtcp_fb_rpsi(RtpSession *session, uint8_t *bit_string, uint16_t bit_string_len) {
	uint16_t bit_string_len_in_bytes;
	int additional_bytes;
	int size;
	mblk_t *h;
	rtcp_common_header_t *ch;
	rtcp_fb_header_t *fbh;
	rtcp_fb_rpsi_fci_t *fci;
	int i;

	/* Calculate packet size and allocate memory. */
	bit_string_len_in_bytes = (bit_string_len / 8) + (((bit_string_len % 8) == 0) ? 0 : 1);
	additional_bytes = bit_string_len_in_bytes - 2;
	if (additional_bytes < 0) additional_bytes = 0;
	size = sizeof(rtcp_common_header_t) + sizeof(rtcp_fb_header_t) + sizeof(rtcp_fb_rpsi_fci_t) + additional_bytes;
	h = allocb(size, 0);

	/* Fill RPSI */
	ch = (rtcp_common_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_common_header_t);
	fbh = (rtcp_fb_header_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_header_t);
	fci = (rtcp_fb_rpsi_fci_t *)h->b_wptr;
	h->b_wptr += sizeof(rtcp_fb_rpsi_fci_t);
	fbh->packet_sender_ssrc = htonl(rtp_session_get_send_ssrc(session));
	fbh->media_source_ssrc = htonl(rtp_session_get_recv_ssrc(session));
	if (bit_string_len <= 16) {
		fci->pb = 16 - bit_string_len;
		memset(&fci->bit_string, 0, 2);
	} else {
		fci->pb = (bit_string_len - 16) % 32;
		memset(&fci->bit_string, 0, bit_string_len_in_bytes);
	}
	fci->payload_type = rtp_session_get_recv_payload_type(session) & 0x7F;
	memcpy(&fci->bit_string, bit_string, bit_string_len / 8);
	for (i = 0; i < (bit_string_len % 8); i++) {
		fci->bit_string[bit_string_len_in_bytes - 1] |= (bit_string[bit_string_len_in_bytes - 1] & (1 << (7 - i)));
	}

	/* Fill common header */
	rtcp_common_header_init(ch, session, RTCP_PSFB, RTCP_PSFB_RPSI, msgdsize(h));

	return h;
}

void rtp_session_send_rtcp_fb_pli(RtpSession *session) {
	mblk_t *m;
	mblk_t *m_pli;
	RtpStream *st = &session->rtp;
	RtcpStream *rtcp_st = &session->rtcp;
	PayloadType *pt = rtp_profile_get_payload(session->snd.profile, session->snd.pt);

	if ((payload_type_get_flags(pt) & PAYLOAD_TYPE_RTCP_FEEDBACK_ENABLED)
		&& ((st->snd_last_ts - rtcp_st->last_rtcp_fb_pli_snt) > 1000)) {
		rtcp_st->last_rtcp_report_snt_r = st->rcv_last_app_ts;
		rtcp_st->last_rtcp_report_snt_s = st->snd_last_ts;
		rtcp_st->last_rtcp_fb_pli_snt = st->snd_last_ts;
		m = make_sr(session);
		m_pli = rtp_session_create_rtcp_fb_pli(session);
		concatb(m, m_pli);

		/* send the compound packet */
		notify_sent_rtcp(session, m);
		ortp_message("Sending RTCP SR compound message with PLI on session [%p]", session);
		rtp_session_rtcp_send(session, m);
	}
}

void rtp_session_send_rtcp_fb_fir(RtpSession *session) {
	mblk_t *m;
	mblk_t *m_fir;
	RtpStream *st = &session->rtp;
	RtcpStream *rtcp_st = &session->rtcp;
	PayloadType *pt = rtp_profile_get_payload(session->snd.profile, session->snd.pt);

	if (payload_type_get_flags(pt) & PAYLOAD_TYPE_RTCP_FEEDBACK_ENABLED) {
		rtcp_st->last_rtcp_report_snt_r = st->rcv_last_app_ts;
		rtcp_st->last_rtcp_report_snt_s = st->snd_last_ts;
		m = make_sr(session);
		m_fir = rtp_session_create_rtcp_fb_fir(session);
		concatb(m, m_fir);

		/* send the compound packet */
		notify_sent_rtcp(session, m);
		ortp_message("Sending RTCP SR compound message with FIR on session [%p]", session);
		rtp_session_rtcp_send(session, m);
	}
}

void rtp_session_send_rtcp_fb_sli(RtpSession *session, uint16_t first, uint16_t number, uint8_t picture_id) {
	mblk_t *m;
	mblk_t *m_sli;
	RtpStream *st = &session->rtp;
	RtcpStream *rtcp_st = &session->rtcp;
	PayloadType *pt = rtp_profile_get_payload(session->snd.profile, session->snd.pt);

	if (payload_type_get_flags(pt) & PAYLOAD_TYPE_RTCP_FEEDBACK_ENABLED) {
		rtcp_st->last_rtcp_report_snt_r = st->rcv_last_app_ts;
		rtcp_st->last_rtcp_report_snt_s = st->snd_last_ts;
		m = make_sr(session);
		m_sli = rtp_session_create_rtcp_fb_sli(session, first, number, picture_id);
		concatb(m, m_sli);

		/* send the compound packet */
		notify_sent_rtcp(session, m);
		ortp_message("Sending RTCP SR compound message with SLI on session [%p]", session);
		rtp_session_rtcp_send(session, m);
	}
}

void rtp_session_send_rtcp_fb_rpsi(RtpSession *session, uint8_t *bit_string, uint16_t bit_string_len) {
	mblk_t *m;
	mblk_t *m_rpsi;
	RtpStream *st = &session->rtp;
	RtcpStream *rtcp_st = &session->rtcp;
	PayloadType *pt = rtp_profile_get_payload(session->snd.profile, session->snd.pt);

	if (payload_type_get_flags(pt) & PAYLOAD_TYPE_RTCP_FEEDBACK_ENABLED) {
		rtcp_st->last_rtcp_report_snt_r = st->rcv_last_app_ts;
		rtcp_st->last_rtcp_report_snt_s = st->snd_last_ts;
		m = make_sr(session);
		m_rpsi = rtp_session_create_rtcp_fb_rpsi(session, bit_string, bit_string_len);
		concatb(m, m_rpsi);

		/* send the compound packet */
		notify_sent_rtcp(session, m);
		ortp_message("Sending RTCP SR compound message with RPSI on session [%p]", session);
		rtp_session_rtcp_send(session, m);
	}
}
