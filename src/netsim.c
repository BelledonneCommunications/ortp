/*
  The oRTP library is an RTP (Realtime Transport Protocol - rfc3550) stack.
  Copyright (C) 2011 Belledonne Communications SARL
  Author: Simon MORLAT simon.morlat@linphone.org

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
#include "ortp/rtpsession.h"
#include "rtpsession_priv.h"

static OrtpNetworkSimulatorCtx* simulator_ctx_new(void){
	OrtpNetworkSimulatorCtx *ctx=(OrtpNetworkSimulatorCtx*)ortp_malloc0(sizeof(OrtpNetworkSimulatorCtx));
	qinit(&ctx->q);
	return ctx;
}

void ortp_network_simulator_destroy(OrtpNetworkSimulatorCtx *sim){
	flushq(&sim->q,0);
	ortp_free(sim);
}

void rtp_session_enable_network_simulation(RtpSession *session, const OrtpNetworkSimulatorParams *params){
	OrtpNetworkSimulatorCtx *sim=session->net_sim_ctx;
	if (params->enabled){
		if (sim==NULL) sim=simulator_ctx_new();
		sim->params=*params;
		session->net_sim_ctx=sim;
	}else{
		if (sim!=NULL) ortp_network_simulator_destroy(sim);
		session->net_sim_ctx=NULL;
	}
}

static int64_t elapsed_us(struct timeval *tv1, struct timeval *tv2){
	return ((tv2->tv_sec-tv1->tv_sec)*1000000LL)+((tv2->tv_usec-tv1->tv_usec));
}

#define IP_UDP_OVERHEAD (20+8)
#define IP6_UDP_OVERHEAD (40+8)

static mblk_t *simulate_bandwidth_limit(RtpSession *session, mblk_t *input){
	OrtpNetworkSimulatorCtx *sim=session->net_sim_ctx;
	struct timeval current;
	int64_t elapsed;
	int bits;
	mblk_t *output=NULL;
#ifdef ORTP_INET6
	int overhead=(session->rtp.sockfamily==AF_INET6) ? IP6_UDP_OVERHEAD : IP_UDP_OVERHEAD;
#else
	int overhead=IP_UDP_OVERHEAD;
#endif
	gettimeofday(&current,NULL);
	
	if (sim->last_check.tv_sec==0){
		sim->last_check=current;
		sim->bit_budget=0;
	}
	/*update the budget */
	elapsed=elapsed_us(&sim->last_check,&current);
	sim->bit_budget+=(elapsed*(int64_t)sim->params.max_bandwidth)/1000000LL;
	sim->last_check=current;
	/* queue the packet for sending*/
	if (input){
		putq(&sim->q,input);
		bits=(msgdsize(input)+overhead)*8;
		sim->qsize+=bits;
	}
	/*flow control*/
	while (sim->qsize>=sim->params.max_bandwidth){
		ortp_message("rtp_session_network_simulate(): discarding packets.");
		output=getq(&sim->q);
		if (output){
			bits=(msgdsize(output)+overhead)*8;
			sim->qsize-=bits;
			freemsg(output);
		}
	}
	
	output=NULL;
	
	/*see if we can output a packet*/
	if (sim->bit_budget>=0){
		output=getq(&sim->q);
		if (output){
			bits=(msgdsize(output)+overhead)*8;
			sim->bit_budget-=bits;
			sim->qsize-=bits;
		}
	}
	if (output==NULL && input==NULL && sim->bit_budget>=0){
		/* unused budget is lost...*/
		sim->last_check.tv_sec=0;
	}
	return output;
}

static mblk_t *simulate_loss_rate(RtpSession *session, mblk_t *input, int rate){
	if((rand() % 101) >= rate) {
		return input;
	}
	freemsg(input);
	return NULL;
}

mblk_t * rtp_session_network_simulate(RtpSession *session, mblk_t *input){
	OrtpNetworkSimulatorCtx *sim=session->net_sim_ctx;
	mblk_t *om=NULL;
	
	om=input;
	if (sim->params.max_bandwidth>0){
		om=simulate_bandwidth_limit(session,input);
	}
	if (sim->params.loss_rate>0 && om){
		om=simulate_loss_rate(session,om, sim->params.loss_rate);
	}
	return om;
}

