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

/**
 * Set session's SDES item for automatic sending of RTCP compound packets.
 * If some items are not specified, use NULL.
**/
void rtp_session_set_source_description(RtpSession *session, 
    const char *cname, const char *name, const char *email, const char *phone, 
    const char *loc, const char *tool, const char *note){
	mblk_t *chunk = sdes_chunk_new(session->snd.ssrc);
	mblk_t *m=chunk;
	const char *_cname=cname;
	if (_cname==NULL)
	{
		_cname="Unknown";
	}
	chunk=sdes_chunk_append_item(chunk, RTCP_SDES_CNAME, _cname);
	chunk=sdes_chunk_append_item(chunk, RTCP_SDES_NAME, name);
	chunk=sdes_chunk_append_item(chunk, RTCP_SDES_EMAIL, email);
	chunk=sdes_chunk_append_item(chunk, RTCP_SDES_PHONE, phone);
	chunk=sdes_chunk_append_item(chunk, RTCP_SDES_LOC, loc);
	chunk=sdes_chunk_append_item(chunk, RTCP_SDES_TOOL, tool);
	chunk=sdes_chunk_append_item(chunk, RTCP_SDES_NOTE, note);
	chunk=sdes_chunk_pad(chunk);
	if (session->sd!=NULL) freemsg(session->sd);
	session->sd=m;
}

void
rtp_session_add_contributing_source(RtpSession *session, uint32_t csrc, 
    const char *cname, const char *name, const char *email, const char *phone, 
    const char *loc, const char *tool, const char *note)
{
	mblk_t *chunk = sdes_chunk_new(csrc);
	mblk_t *m=chunk;
	char *_cname=(char*)cname;
	if (_cname==NULL)
	{
		_cname="toto";
	}
	chunk=sdes_chunk_append_item(chunk, RTCP_SDES_CNAME, cname);
	chunk=sdes_chunk_append_item(chunk, RTCP_SDES_NAME, name);
	chunk=sdes_chunk_append_item(chunk, RTCP_SDES_EMAIL, email);
	chunk=sdes_chunk_append_item(chunk, RTCP_SDES_PHONE, phone);
	chunk=sdes_chunk_append_item(chunk, RTCP_SDES_LOC, loc);
	chunk=sdes_chunk_append_item(chunk, RTCP_SDES_TOOL, tool);
	chunk=sdes_chunk_append_item(chunk, RTCP_SDES_NOTE, note);
	chunk=sdes_chunk_pad(chunk);
	putq(&session->contributing_sources,m);
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
	sdes_chunk_set_ssrc(session->sd,session->snd.ssrc);
	m=concatb(m,dupmsg(session->sd));
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

uint64_t ortp_timeval_to_ntp(const struct timeval *tv){
	uint64_t msw;
	uint64_t lsw;
	msw=tv->tv_sec + 0x83AA7E80; /* 0x83AA7E80 is the number of seconds from 1900 to 1970 */
	lsw=(uint32_t)((double)tv->tv_usec*(double)(((uint64_t)1)<<32)*1.0e-6);
	return msw<<32 | lsw; 
}

static void sender_info_init(sender_info_t *info, RtpSession *session){
	struct timeval tv;
	uint64_t ntp;
	gettimeofday(&tv,NULL);
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
		if ( session->flags & RTCP_OVERRIDE_LOST_PACKETS ) {
			/* If the test mode is enabled, replace the lost packet field with the test vector value set by rtp_session_rtcp_set_lost_packet_value() */
			packet_loss = session->lost_packets_test_vector;
			if ( packet_loss < 0 )
				packet_loss = 0;
			/* The test value is the definite cumulative one, no need to increment it each time a packet is sent */
			stream->stats.cum_packet_loss = packet_loss;
		}else {
			/* Normal mode */
			packet_loss = ( stream->hwrcv_extseq - stream->hwrcv_seq_at_last_SR ) - stream->hwrcv_since_last_SR;
			if ( packet_loss < 0 )
				packet_loss = 0;
			stream->stats.cum_packet_loss += packet_loss;
		}
		loss_fraction=(int)( 256 * packet_loss) / stream->hwrcv_since_last_SR ;
	}
	/* reset them */
	stream->hwrcv_since_last_SR=0;
	stream->hwrcv_seq_at_last_SR=stream->hwrcv_extseq;
	
	if (stream->last_rcv_SR_time.tv_sec!=0){
		struct timeval now;
		double delay;
		gettimeofday(&now,NULL);
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

		gettimeofday( &now, NULL );
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
	if (session->sd!=NULL)
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
	if (session->sd!=NULL)
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
		rtp_session_dispatch_event(session,ev);
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
		rtp_session_rtcp_send(session,m);
		ortp_debug("Rtcp compound message sent.");
	}
}

void rtp_session_rtcp_process_recv(RtpSession *session){
	RtpStream *st=&session->rtp;
	RtcpStream *rtcp_st=&session->rtcp;
	mblk_t *m=NULL;
	if (st->rcv_last_app_ts - rtcp_st->last_rtcp_report_snt_r > rtcp_st->rtcp_report_snt_interval_r 
		|| st->snd_last_ts - rtcp_st->last_rtcp_report_snt_s > rtcp_st->rtcp_report_snt_interval_s){
		rtcp_st->last_rtcp_report_snt_r=st->rcv_last_app_ts;
		rtcp_st->last_rtcp_report_snt_s=st->snd_last_ts;

		if (session->rtp.last_rtcp_packet_count<session->rtp.stats.packet_sent){
			m=make_sr(session);
			session->rtp.last_rtcp_packet_count=session->rtp.stats.packet_sent;
		}else if (session->rtp.stats.packet_recv>0){
			/*don't send RR when no packet are received yet*/
			m=make_rr(session);
		}
		if (m!=NULL){
			/* send the compound packet */
			notify_sent_rtcp(session,m);
			rtp_session_rtcp_send(session,m);
			ortp_debug("Rtcp compound message sent.");
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

