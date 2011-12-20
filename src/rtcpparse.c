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


#include "ortp/ortp.h"
#include "utils.h"

static int rtcp_get_size(const mblk_t *m){
	const rtcp_common_header_t *ch=rtcp_get_common_header(m);
	if (ch==NULL) return -1;
	return (1+rtcp_common_header_get_length(ch))*4;
}

/*in case of coumpound packet, set read pointer of m to the beginning of the next RTCP
packet */
bool_t rtcp_next_packet(mblk_t *m){
	int nextlen=rtcp_get_size(m);
	if (nextlen>=0){
		if (m->b_rptr+nextlen<m->b_wptr){
			m->b_rptr+=nextlen;
			return TRUE;
		}
	}
	return FALSE;
}

void rtcp_rewind(mblk_t *m){
	m->b_rptr=m->b_datap->db_base;
}

/* get common header; this function will also check the sanity of the packet*/
const rtcp_common_header_t * rtcp_get_common_header(const mblk_t *m){
	int size=msgdsize(m);
	rtcp_common_header_t *ch;
	if (m->b_cont!=NULL){
		ortp_fatal("RTCP parser does not work on fragmented mblk_t. Use msgpullup() before to re-assemble the packet.");
		return NULL;
	}
	if (size<sizeof(rtcp_common_header_t)){
		ortp_warning("Bad RTCP packet, too short.");
		return NULL;
	}
	ch=(rtcp_common_header_t*)m->b_rptr;
	return ch;
}

bool_t rtcp_is_SR(const mblk_t *m){
	const rtcp_common_header_t *ch=rtcp_get_common_header(m);
	if (ch!=NULL && rtcp_common_header_get_packet_type(ch)==RTCP_SR){
		if (msgdsize(m)<(sizeof(rtcp_sr_t)-sizeof(report_block_t))){
			ortp_warning("Too short RTCP SR packet.");
			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

/*Sender Report accessors */
uint32_t rtcp_SR_get_ssrc(const mblk_t *m){
	rtcp_sr_t *sr=(rtcp_sr_t*)m->b_rptr;
	return ntohl(sr->ssrc);
}

const sender_info_t * rtcp_SR_get_sender_info(const mblk_t *m){
	rtcp_sr_t *sr=(rtcp_sr_t*)m->b_rptr;
	return &sr->si;
}

const report_block_t * rtcp_SR_get_report_block(const mblk_t *m, int idx){
	rtcp_sr_t *sr=(rtcp_sr_t*)m->b_rptr;
	report_block_t *rb=&sr->rb[idx];
	int size=rtcp_get_size(m);
	if ( ( (uint8_t*)rb)+sizeof(report_block_t) <= m->b_rptr + size ) {
		return rb;
	}else{
		if (idx<rtcp_common_header_get_rc(&sr->ch)){
			ortp_warning("RTCP packet should include a report_block_t at pos %i but has no space for it.",idx);
		}
	}
	return NULL;
}

/*Receiver report accessors*/
bool_t rtcp_is_RR(const mblk_t *m){
	const rtcp_common_header_t *ch=rtcp_get_common_header(m);
	if (ch!=NULL && rtcp_common_header_get_packet_type(ch)==RTCP_RR){
		if (msgdsize(m)<sizeof(rtcp_rr_t)){
			ortp_warning("Too short RTCP RR packet.");
			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

uint32_t rtcp_RR_get_ssrc(const mblk_t *m){
	rtcp_rr_t *rr=(rtcp_rr_t*)m->b_rptr;
	return ntohl(rr->ssrc);
}

const report_block_t * rtcp_RR_get_report_block(const mblk_t *m,int idx){
	rtcp_rr_t *rr=(rtcp_rr_t*)m->b_rptr;
	report_block_t *rb=&rr->rb[idx];
	int size=rtcp_get_size(m);
	if ( ( (uint8_t*)rb)+sizeof(report_block_t) <= (m->b_rptr + size ) ){
		return rb;
	}else{
		if (idx<rtcp_common_header_get_rc(&rr->ch)){
			ortp_warning("RTCP packet should include a report_block_t at pos %i but has no space for it.",idx);
		}
	}
	return NULL;
}

/*SDES accessors */
bool_t rtcp_is_SDES(const mblk_t *m){
	const rtcp_common_header_t *ch=rtcp_get_common_header(m);
	if (ch && rtcp_common_header_get_packet_type(ch)==RTCP_SDES){
		if (msgdsize(m)<rtcp_get_size(m)){
			ortp_warning("Too short RTCP SDES packet.");
			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

void rtcp_sdes_parse(const mblk_t *m, SdesItemFoundCallback cb, void *user_data){
	uint8_t *rptr=(uint8_t*)m->b_rptr+sizeof(rtcp_common_header_t);
	const rtcp_common_header_t *ch=(rtcp_common_header_t*)m->b_rptr;
	uint8_t *end=rptr+(4*(rtcp_common_header_get_length(ch)+1));
	uint32_t ssrc=0;
	int nchunk=0;
	bool_t chunk_start=TRUE;

	if (end>(uint8_t*)m->b_wptr) end=(uint8_t*)m->b_wptr;

	while(rptr<end){
		if (chunk_start){
			if (rptr+4<=end){
				ssrc=ntohl(*(uint32_t*)rptr);
				rptr+=4;
			}else{
				ortp_warning("incorrect chunk start in RTCP SDES");
				break;
			}
			chunk_start=FALSE;
		}else{
			if (rptr+2<=end){
				uint8_t type=rptr[0];
				uint8_t len=rptr[1];

				if (type==RTCP_SDES_END){
					/* pad to next 32bit boundary*/
					rptr=(uint8_t*)(((unsigned long)rptr+4) & ~0x3);
					nchunk++;
					if (nchunk<rtcp_common_header_get_rc(ch)){
						chunk_start=TRUE;
						continue;
					}else break;
				}
				rptr+=2;
				if (rptr+len<=end){
					cb(user_data,ssrc,type,(char*)rptr,len);
					rptr+=len;
				}else{
					ortp_warning("bad item length in RTCP SDES");
					break;
				}
			}else{
				/*end of packet */
				break;
			}
		}
	}
}

/*BYE accessors */
bool_t rtcp_is_BYE(const mblk_t *m){
	const rtcp_common_header_t *ch=rtcp_get_common_header(m);
	if (ch && rtcp_common_header_get_packet_type(ch)==RTCP_BYE){
		if (msgdsize(m)<rtcp_get_size(m)){
			ortp_warning("Too short RTCP BYE packet.");
			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

bool_t rtcp_BYE_get_ssrc(const mblk_t *m, int idx, uint32_t *ssrc){
	rtcp_bye_t *bye=(rtcp_bye_t*)m->b_rptr;
	int rc=rtcp_common_header_get_rc(&bye->ch);
	int len=rtcp_common_header_get_length(&bye->ch);
	if (idx<rc){
		if ((uint8_t*)&bye->ssrc[idx]<=(m->b_rptr
				+sizeof(rtcp_common_header_t)+len-4)) {
			*ssrc=ntohl(bye->ssrc[idx]);
			return TRUE;
		}else{
			ortp_warning("RTCP BYE should contain %i ssrc, but there is not enough room for it.",rc);
		}
	}
	return FALSE;
}

bool_t rtcp_BYE_get_reason(const mblk_t *m, const char **reason, int *reason_len){
	rtcp_bye_t *bye=(rtcp_bye_t*)m->b_rptr;
	int rc=rtcp_common_header_get_rc(&bye->ch);
	uint8_t *rptr=(uint8_t*)m->b_rptr+sizeof(rtcp_common_header_t)+rc*4;
	uint8_t *end=(uint8_t*)(m->b_rptr+rtcp_get_size(m));
	if (rptr<end){
		uint8_t content_len=rptr[0];
		if (rptr+1+content_len<=end){
			*reason=(char*)rptr+1;
			*reason_len=content_len;
			return TRUE;
		}else{
			ortp_warning("RTCP BYE has not enough space for reason phrase.");
			return FALSE;
		}
	}
	return FALSE;
}

/*APP accessors */
bool_t rtcp_is_APP(const mblk_t *m){
	const rtcp_common_header_t *ch=rtcp_get_common_header(m);
	int size=rtcp_get_size(m);
	if (ch!=NULL && rtcp_common_header_get_packet_type(ch)==RTCP_APP){
		if (msgdsize(m)<size){
			ortp_warning("Too short RTCP APP packet.");
			return FALSE;
		}
		if (size < sizeof(rtcp_app_t)){
			ortp_warning("Bad RTCP APP packet.");
			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

int rtcp_APP_get_subtype(const mblk_t *m){
	rtcp_app_t *app=(rtcp_app_t*)m->b_rptr;
	return rtcp_common_header_get_rc(&app->ch);
}

uint32_t rtcp_APP_get_ssrc(const mblk_t *m){
	rtcp_app_t *app=(rtcp_app_t*)m->b_rptr;
	return ntohl(app->ssrc);
}
/* name argument is supposed to be at least 4 characters (note: no '\0' written)*/
void rtcp_APP_get_name(const mblk_t *m, char *name){
	rtcp_app_t *app=(rtcp_app_t*)m->b_rptr;
	memcpy(name,app->name,4);
}
/* retrieve the data. when returning, data points directly into the mblk_t */
void rtcp_APP_get_data(const mblk_t *m, uint8_t **data, int *len){
	int datalen=rtcp_get_size(m)-sizeof(rtcp_app_t);
	if (datalen>0){
		*data=(uint8_t*)m->b_rptr+sizeof(rtcp_app_t);
		*len=datalen;
	}else{
		*len=0;
		*data=NULL;
	}
}
