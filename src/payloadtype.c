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

#include "ortp/logging.h"
#include "ortp/payloadtype.h"
#include "ortp/str_utils.h"


char *payload_type_get_rtpmap(PayloadType *pt)
{
	int len=(int)strlen(pt->mime_type)+15;
	char *rtpmap=(char *) ortp_malloc(len);
	if (pt->channels>0)
		snprintf(rtpmap,len,"%s/%i/%i",pt->mime_type,pt->clock_rate,pt->channels);
	else
		snprintf(rtpmap,len,"%s/%i",pt->mime_type,pt->clock_rate);
	return rtpmap;
}

PayloadType *payload_type_new()
{
	PayloadType *newpayload=(PayloadType *)ortp_new0(PayloadType,1);
	newpayload->flags|=PAYLOAD_TYPE_ALLOCATED;
	return newpayload;
}


PayloadType *payload_type_clone(PayloadType *payload)
{
	PayloadType *newpayload=(PayloadType *)ortp_new0(PayloadType,1);
	memcpy(newpayload,payload,sizeof(PayloadType));
	newpayload->mime_type=ortp_strdup(payload->mime_type);
	if (payload->recv_fmtp!=NULL) {
		newpayload->recv_fmtp=ortp_strdup(payload->recv_fmtp);
	}
	if (payload->send_fmtp!=NULL){
		newpayload->send_fmtp=ortp_strdup(payload->send_fmtp);
	}
	newpayload->flags|=PAYLOAD_TYPE_ALLOCATED;
	return newpayload;
}

static bool_t canWrite(PayloadType *pt){
	if (!(pt->flags & PAYLOAD_TYPE_ALLOCATED)) {
		ortp_error("Cannot change parameters of statically defined payload types: make your"
			" own copy using payload_type_clone() first.");
		return FALSE;
	}
	return TRUE;
}

/**
 * Sets a recv parameters (fmtp) for the PayloadType.
 * This method is provided for applications using RTP with SDP, but
 * actually the ftmp information is not used for RTP processing.
**/
void payload_type_set_recv_fmtp(PayloadType *pt, const char *fmtp){
	if (canWrite(pt)){
		if (pt->recv_fmtp!=NULL) ortp_free(pt->recv_fmtp);
		if (fmtp!=NULL) pt->recv_fmtp=ortp_strdup(fmtp);
		else pt->recv_fmtp=NULL;
	}
}

/**
 * Sets a send parameters (fmtp) for the PayloadType.
 * This method is provided for applications using RTP with SDP, but
 * actually the ftmp information is not used for RTP processing.
**/
void payload_type_set_send_fmtp(PayloadType *pt, const char *fmtp){
	if (canWrite(pt)){
		if (pt->send_fmtp!=NULL) ortp_free(pt->send_fmtp);
		if (fmtp!=NULL) pt->send_fmtp=ortp_strdup(fmtp);
		else pt->send_fmtp=NULL;
	}
}



void payload_type_append_recv_fmtp(PayloadType *pt, const char *fmtp){
	if (canWrite(pt)){
		if (pt->recv_fmtp==NULL)
			pt->recv_fmtp=ortp_strdup(fmtp);
		else{
			char *tmp=ortp_strdup_printf("%s;%s",pt->recv_fmtp,fmtp);
			ortp_free(pt->recv_fmtp);
			pt->recv_fmtp=tmp;
		}
	}
}

void payload_type_append_send_fmtp(PayloadType *pt, const char *fmtp){
	if (canWrite(pt)){
		if (pt->send_fmtp==NULL)
			pt->send_fmtp=ortp_strdup(fmtp);
		else{
			char *tmp=ortp_strdup_printf("%s;%s",pt->send_fmtp,fmtp);
			ortp_free(pt->send_fmtp);
			pt->send_fmtp=tmp;
		}
	}
}


/**
 * Frees a PayloadType.
**/
void payload_type_destroy(PayloadType *pt)
{
	if (pt->mime_type) ortp_free(pt->mime_type);
	if (pt->recv_fmtp) ortp_free(pt->recv_fmtp);
	if (pt->send_fmtp) ortp_free(pt->send_fmtp);
	ortp_free(pt);
}

/**
 * Parses a fmtp string such as "profile=0;level=10", finds the value matching
 * parameter param_name, and writes it into result. 
 * Despite fmtp strings are not used anywhere within oRTP, this function can
 * be useful for people using RTP streams described from SDP.
 * @param fmtp the fmtp line (format parameters)
 * @param param_name the parameter to search for
 * @param result the value given for the parameter (if found)
 * @param result_len the size allocated to hold the result string
 * @return TRUE if the parameter was found, else FALSE.
**/ 
bool_t fmtp_get_value(const char *fmtp, const char *param_name, char *result, size_t result_len){
	const char *pos=strstr(fmtp,param_name);
	memset(result, '\0', result_len);
	if (pos){
		const char *equal=strchr(pos,'=');
		if (equal){
			int copied;
			const char *end=strchr(equal+1,';');
			if (end==NULL) end=fmtp+strlen(fmtp); /*assuming this is the last param */
			copied=MIN(result_len-1,end-(equal+1));
			strncpy(result,equal+1,copied);
			result[copied]='\0';
			return TRUE;
		}
	}
	return FALSE;
}
