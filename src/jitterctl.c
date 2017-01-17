/*
 * The oRTP library is an RTP (Realtime Transport Protocol - rfc3550) implementation with additional features.
 * Copyright (C) 2017 Belledonne Communications SARL
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
/***************************************************************************
 *            jitterctl.c
 *
 *  Mon Nov  8 11:53:21 2004
 *  Copyright  2004  Simon MORLAT
 *  Email simon.morlat@linphone.org
 ****************************************************************************/

#include "ortp/rtpsession.h"
#include "ortp/payloadtype.h"
#include "ortp/ortp.h"
#include "utils.h"
#include "rtpsession_priv.h"
#include <math.h>

#define JC_BETA .01
#define JC_GAMMA (JC_BETA)

#include "jitterctl.h"

void jitter_control_init(JitterControl *ctl, PayloadType *payload){
	ctl->count=0;
	ctl->clock_offset_ts=0;
	ctl->prev_clock_offset_ts=0;
	ctl->jitter=0;
	ctl->inter_jitter=0;
	ctl->cum_jitter_buffer_count=0;
	ctl->cum_jitter_buffer_size=0;
	ctl->corrective_slide=0;

	ctl->clock_rate=8000;
	ctl->adapt_refresh_prev_ts=0;

	if (payload!=NULL){
		jitter_control_set_payload(ctl,payload);
	}
}


void jitter_control_enable_adaptive(JitterControl *ctl, bool_t val){
	ctl->params.adaptive=val;
}

void jitter_control_set_payload(JitterControl *ctl, PayloadType *pt){
	ctl->jitt_comp_ts =
			(int) (((double) ctl->params.nom_size / 1000.0) * (pt->clock_rate));
	/*make correction by not less than 10ms */
	ctl->corrective_step=(int) (0.01 * (float)pt->clock_rate);
	ctl->adapt_jitt_comp_ts=ctl->jitt_comp_ts;
	ctl->clock_rate=pt->clock_rate;
}


void jitter_control_dump_stats(JitterControl *ctl){
	ortp_message("JitterControl:\n\tslide=%g,jitter=%g,adapt_jitt_comp_ts=%i,corrective_slide=%i, count=%i",
			(double)ctl->clock_offset_ts,ctl->jitter, ctl->adapt_jitt_comp_ts, ctl->corrective_slide,ctl->count);
}

/*the goal of this method is to compute "corrective_slide": a timestamp unit'd value to be added
 to recv timestamp to make them reflect the instant they are delivered by the jitter buffer. */
void jitter_control_update_corrective_slide(JitterControl *ctl){
	int tmp;
	tmp=(int)(ctl->clock_offset_ts-ctl->prev_clock_offset_ts);
	if (tmp>ctl->corrective_step) {
		ctl->corrective_slide+=ctl->corrective_step;
		ctl->prev_clock_offset_ts=ctl->clock_offset_ts+ctl->corrective_step;
	}
	else if (tmp<-ctl->corrective_step) {
		ctl->corrective_slide-=ctl->corrective_step;
		ctl->prev_clock_offset_ts=ctl->clock_offset_ts-ctl->corrective_step;
	}
}

void jitter_control_update_size(JitterControl *ctl, queue_t *q){
	mblk_t *newest=qlast(q);
	mblk_t *oldest=qbegin(q);
	uint32_t newest_ts,oldest_ts;
	if (newest==NULL) return;
	newest_ts=rtp_get_timestamp(newest);
	oldest_ts=rtp_get_timestamp(oldest);
	ctl->cum_jitter_buffer_count++;
	ctl->cum_jitter_buffer_size+=(uint32_t)(newest_ts-oldest_ts);
}

float jitter_control_compute_mean_size(JitterControl *ctl){
	if (ctl->cum_jitter_buffer_count!=0){
		double tmp=((double)ctl->cum_jitter_buffer_size)/(double)ctl->cum_jitter_buffer_count;
		ctl->cum_jitter_buffer_size=0;
		ctl->cum_jitter_buffer_count=0;
		ctl->jitter_buffer_mean_size = 1000.0f*(float)tmp/(float)ctl->clock_rate;
		return ctl->jitter_buffer_mean_size;
	}
	return 0;
}

void rtp_session_init_jitter_buffer(RtpSession *session){
	PayloadType *payload=NULL;
	
	if (session->rcv.pt!=-1) {
		payload = rtp_profile_get_payload (session->rcv.profile,session->rcv.pt);
	}/*else not set yet */
	jitter_control_init(&session->rtp.jittctl,payload);
}

/**
 *@param session: a RtpSession
 *@param milisec: the time interval in milisec to be jitter compensed.
 *
 * Sets the time interval for which packet are buffered instead of being delivered to the
 * application.
 **/
void
rtp_session_set_jitter_compensation (RtpSession * session, int milisec)
{
	session->rtp.jittctl.params.min_size = session->rtp.jittctl.params.nom_size = milisec;
	rtp_session_init_jitter_buffer(session);
}

void rtp_session_enable_adaptive_jitter_compensation(RtpSession *session, bool_t val){
	jitter_control_enable_adaptive(&session->rtp.jittctl,val);
}

bool_t rtp_session_adaptive_jitter_compensation_enabled(RtpSession *session){
	return session->rtp.jittctl.params.adaptive;
}

void rtp_session_enable_jitter_buffer(RtpSession *session, bool_t enabled){
	session->rtp.jittctl.params.enabled = enabled;
	session->flags|=RTP_SESSION_RECV_SYNC;
}

bool_t rtp_session_jitter_buffer_enabled(const RtpSession *session){
	return session->rtp.jittctl.params.enabled;
}

void rtp_session_set_jitter_buffer_params(RtpSession *session, const JBParameters *par){
	if (par == &session->rtp.jittctl.params) return;
	memcpy(&session->rtp.jittctl.params, par, sizeof (JBParameters));
	rtp_session_init_jitter_buffer(session);
}

void rtp_session_get_jitter_buffer_params(RtpSession *session, JBParameters *par){
	memcpy(par, &session->rtp.jittctl.params, sizeof(JBParameters));
}


/*
 The algorithm computes two values:
	slide: an average of difference between the expected and the socket-received timestamp
	jitter: an average of the absolute value of the difference between socket-received timestamp and slide.
	slide is used to make clock-slide detection and correction.
	jitter is added to the initial jitt_comp_time value. It compensates bursty packets arrival (packets
	not arriving at regular interval ).
*/
void jitter_control_new_packet(JitterControl *ctl, uint32_t packet_ts, uint32_t cur_str_ts){
	switch (ctl->params.buffer_algorithm){
		case OrtpJitterBufferBasic:
			jitter_control_new_packet_basic (ctl, packet_ts, cur_str_ts);
		break;
		case OrtpJitterBufferRecursiveLeastSquare:
			jitter_control_new_packet_rls (ctl, packet_ts, cur_str_ts);
		break;
		default:
			ortp_fatal("No such new packet strategy: %d", ctl->params.buffer_algorithm);
		break;
	}
	ctl->count++;
}

static void jitter_control_update_interarrival_jitter(JitterControl *ctl, int64_t diff){
	/*compute interarrival jitter*/
	int delta;
	delta= (int)(diff-ctl->olddiff);
	ctl->inter_jitter=(float) (ctl->inter_jitter+ (( (float)abs(delta) - ctl->inter_jitter)*(1/16.0)));
	ctl->olddiff=diff;
}

void jitter_control_new_packet_basic(JitterControl *ctl, uint32_t packet_ts, uint32_t cur_str_ts){
	int64_t diff=(int64_t)packet_ts - (int64_t)cur_str_ts;
	double gap,slide;

	if (ctl->count==0){
		ctl->clock_offset_ts=ctl->prev_clock_offset_ts=diff;
		slide=(double)diff;
		ctl->olddiff=diff;
		ctl->jitter=0;
	}else{
		slide=((double)ctl->clock_offset_ts*(1-JC_BETA)) + ((double)diff*JC_BETA);
	}
	gap=(double)diff - slide;
	gap=gap<0 ? -gap : 0; /*compute only for late packets*/
	ctl->jitter=(float) ((ctl->jitter*(1-JC_GAMMA)) + (gap*JC_GAMMA));
	jitter_control_update_interarrival_jitter(ctl, diff);
	
	if (ctl->params.adaptive){
		if (ctl->count%50==0) {
			ctl->adapt_jitt_comp_ts=(int) MAX(ctl->jitt_comp_ts,2*ctl->jitter);
			//jitter_control_dump_stats(ctl);
		}
		ctl->clock_offset_ts=(int64_t)slide;
	}else {
		/*ctl->slide and jitter size are not updated*/
	}
}

static bool_t time_for_log(JitterControl *ctl, uint32_t cur_str_ts){
	int32_t elapsed = (int32_t)(cur_str_ts - ctl->last_log_ts);
	if (elapsed >= 5*ctl->clock_rate){
		ctl->last_log_ts = cur_str_ts;
		return TRUE;
	}
	return FALSE;
}

static uint32_t jitter_control_local_ts_to_remote_ts_rls(JitterControl *ctl, uint32_t local_ts){
	return (uint32_t)( (int64_t)(ctl->capped_clock_ratio*(double)local_ts) + ctl->clock_offset_ts);
}

/**************************** RLS *********************************/
void jitter_control_new_packet_rls(JitterControl *ctl, uint32_t packet_ts, uint32_t cur_str_ts){
	int64_t diff=(int64_t)packet_ts - (int64_t)cur_str_ts;
	int deviation;
	bool_t jb_size_updated = FALSE;

	if (ctl->count==0){
		ctl->clock_offset_ts=ctl->prev_clock_offset_ts=diff;
		ctl->olddiff=diff;
		ctl->jitter=0;

		ortp_extremum_init(&ctl->max_ts_deviation, (int)(ctl->params.refresh_ms / 1000.f * ctl->clock_rate));
		ortp_extremum_record_max(&ctl->max_ts_deviation, cur_str_ts, (float)ctl->jitt_comp_ts);

		// clocks rate should be the same
		ortp_kalman_rls_init(&ctl->kalman_rls, 1, (double)diff);
		ctl->capped_clock_ratio = ctl->kalman_rls.m;
	}
	
	/*offset estimation tends to be smaller than reality when
	jitter appears since it compensates the jitter */
	ortp_kalman_rls_record(&ctl->kalman_rls, cur_str_ts, packet_ts);

	ctl->capped_clock_ratio=MAX(.5, MIN(ctl->kalman_rls.m, 2));
	ctl->clock_offset_ts = (!(.5f<ctl->kalman_rls.m && ctl->kalman_rls.m<2.f))? diff : (int64_t)ctl->kalman_rls.b;
	deviation=abs((int32_t)(packet_ts - jitter_control_local_ts_to_remote_ts_rls(ctl, cur_str_ts)));
	
	/*ortp_message("deviation=%g ms", 1000.0*deviation/(double)ctl->clock_rate);*/
	
	jitter_control_update_interarrival_jitter(ctl, diff);

	if (ctl->params.adaptive){
		bool_t max_updated = ortp_extremum_record_max(&ctl->max_ts_deviation, cur_str_ts, (float)deviation);
		float max_deviation = MAX(ortp_extremum_get_previous(&ctl->max_ts_deviation), ortp_extremum_get_current(&ctl->max_ts_deviation));
		if (max_updated && max_deviation > ctl->adapt_jitt_comp_ts){
			ctl->adapt_jitt_comp_ts=(int)max_deviation;
			jb_size_updated = TRUE;
		}else if (max_deviation < ctl->params.ramp_threshold/100.f*ctl->adapt_jitt_comp_ts){
			/*Jitter is decreasing. Make a smooth descent to avoid dropping lot of packets*/
			if ( (int32_t)(cur_str_ts - ctl->adapt_refresh_prev_ts) > ((ctl->params.ramp_refresh_ms*ctl->clock_rate)/1000)) {
				ctl->adapt_jitt_comp_ts -= (ctl->params.ramp_step_ms * ctl->clock_rate) / 1000;
				jb_size_updated = TRUE;
			}
		}
		if (jb_size_updated){
			int min_size_ts = (ctl->params.min_size * ctl->clock_rate) / 1000;
			int max_size_ts = (ctl->params.max_size * ctl->clock_rate) / 1000;
			if (ctl->adapt_jitt_comp_ts < min_size_ts){
				ctl->adapt_jitt_comp_ts = min_size_ts;
			}else if (ctl->adapt_jitt_comp_ts > max_size_ts){
				ctl->adapt_jitt_comp_ts = max_size_ts;
			}
			ctl->adapt_refresh_prev_ts = cur_str_ts;
			jb_size_updated = TRUE;
		}
	}
	if (time_for_log(ctl, cur_str_ts)){
		ortp_message("jitter buffer %s: target-size: %f ms, effective-size: %f (min: %i nom: %i, max: %i)",jb_size_updated ? "updated" : "stable",
			((float)ctl->adapt_jitt_comp_ts/(float)ctl->clock_rate)*1000.0,
			ctl->jitter_buffer_mean_size,
			ctl->params.min_size, ctl->params.nom_size, ctl->params.max_size);
		ortp_message("jitter buffer rls stats: count=%d"
			", offset=%g clock_ratio=%g"
			", capped_offset=%i capped_clock_ratio=%f"
			", max_ts_deviation=%f prev_max_ts_deviation=%f"
			", deviation=%i"
			", RLS VARIABLES: P[0][0]=%f, P[1][0]=%f, P[0][1]=%f, P[1][1]=%f"
			, ctl->count
			, ctl->kalman_rls.b, ctl->kalman_rls.m
			, (int) ctl->clock_offset_ts, (float)ctl->capped_clock_ratio
			, ortp_extremum_get_current(&ctl->max_ts_deviation), ortp_extremum_get_previous(&ctl->max_ts_deviation)
			, deviation
			, ctl->kalman_rls.P[0][0], ctl->kalman_rls.P[1][0], ctl->kalman_rls.P[0][1], ctl->kalman_rls.P[1][1]);
	}
}

uint32_t jitter_control_get_compensated_timestamp(JitterControl *obj , uint32_t user_ts){
	uint32_t ret = 0;
	switch (obj->params.buffer_algorithm){
		case OrtpJitterBufferBasic:
			ret = (uint32_t)( (int64_t)user_ts+obj->clock_offset_ts-(int64_t)obj->adapt_jitt_comp_ts);
		break;
		case OrtpJitterBufferRecursiveLeastSquare:
			ret = jitter_control_local_ts_to_remote_ts_rls(obj, user_ts) - obj->adapt_jitt_comp_ts;
		break;
		default:
			ortp_fatal("No such new packet strategy: %d", obj->params.buffer_algorithm);
		break;
	}
	return ret;
}

