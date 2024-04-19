/*
 * Copyright (c) 2010-2022 Belledonne Communications SARL.
 *
 * This file is part of oRTP
 * (see https://gitlab.linphone.org/BC/public/ortp).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifdef HAVE_CONFIG_H
#include "ortp-config.h"
#endif
#ifndef _WIN32
#include <sys/resource.h>
#endif
#include "ortp/ortp.h"
#include "ortp/rtpsession.h"
#include "rtpsession_priv.h"
#include "utils.h"
#include <bctoolbox/port.h>

static void rtp_session_schedule_outbound_network_simulator(RtpSession *session, ortpTimeSpec *sleep_until);

static OrtpNetworkSimulatorCtx *simulator_ctx_new(void) {
	OrtpNetworkSimulatorCtx *ctx = (OrtpNetworkSimulatorCtx *)ortp_malloc0(sizeof(OrtpNetworkSimulatorCtx));
	qinit(&ctx->latency_q);
	qinit(&ctx->q);
	qinit(&ctx->send_q);
	return ctx;
}

static void ortp_network_simulator_dump_stats(OrtpNetworkSimulatorCtx *sim) {
	int drop_by_flush = sim->latency_q.q_mcount + sim->q.q_mcount;
	if (sim->total_count > 0) {
		ortp_message("Network simulation: dump stats. Statistics are:"
		             "%d/%d(%.1f%%, param=%.1f) packets dropped by loss, "
		             "%d/%d(%.1f%%) packets dropped by congestion, "
		             "%d/%d(%.1f%%) packets flushed.",
		             sim->drop_by_loss, sim->total_count, sim->drop_by_loss * 100.f / sim->total_count,
		             sim->params.loss_rate, sim->drop_by_congestion, sim->total_count,
		             sim->drop_by_congestion * 100.f / sim->total_count, drop_by_flush, sim->total_count,
		             drop_by_flush * 100.f / sim->total_count);
	}
}

void ortp_network_simulator_stop_thread(OrtpNetworkSimulatorCtx *sim) {
	if (sim->thread_started) {
		sim->thread_started = FALSE;
		ortp_thread_join(sim->thread, NULL);
	}
}

void ortp_network_simulator_destroy(OrtpNetworkSimulatorCtx *sim) {
	ortp_network_simulator_dump_stats(sim);
	if (sim->thread_started) {
		ortp_network_simulator_stop_thread(sim);
	}
	flushq(&sim->latency_q, 0);
	flushq(&sim->q, 0);
	flushq(&sim->send_q, 0);
	ortp_free(sim);
}

#ifndef _WIN32
static const char *sched_policy_to_string(int policy) {
	switch (policy) {
		case SCHED_OTHER:
			return "SCHED_OTHER";
		case SCHED_RR:
			return "SCHED_RR";
		case SCHED_FIFO:
			return "SCHED_FIFO";
	}
	return "SCHED_INVALID";
}
#endif

static void set_high_prio(void) {
#ifndef _WIN32
	const char *sched_pref = getenv("ORTP_SIMULATOR_SCHED_POLICY");
	int policy = SCHED_OTHER;
	struct sched_param param;
	int result = 0;
	char *env_prio_c = NULL;
	int min_prio, max_prio, env_prio;

	if (sched_pref && strcasecmp(sched_pref, "SCHED_RR") == 0) {
		policy = SCHED_RR;
	} else if (sched_pref && strcasecmp(sched_pref, "SCHED_FIFO") == 0) {
		policy = SCHED_FIFO;
	}

	memset(&param, 0, sizeof(param));

	min_prio = sched_get_priority_min(policy);
	max_prio = sched_get_priority_max(policy);
	env_prio_c = getenv("ORTP_SIMULATOR_SCHED_PRIO");

	env_prio = (env_prio_c == NULL) ? max_prio : atoi(env_prio_c);

	env_prio = MAX(MIN(env_prio, max_prio), min_prio);

	param.sched_priority = env_prio;
	if ((result = pthread_setschedparam(pthread_self(), policy, &param))) {
		ortp_warning("Ortp simulator: set pthread_setschedparam failed: %s", strerror(result));
	} else {
		ortp_message("ortp network simulator: sched policy set to %s and priority value (%i)",
		             sched_policy_to_string(policy), param.sched_priority);
	}
	/* The linux kernel has sched_get_priority_max(SCHED_OTHER)=sched_get_priority_max(SCHED_OTHER)=0. As long as we
	 * can't use SCHED_RR or SCHED_FIFO, the only way to increase priority of a calling thread is to use
	 * setpriority().*/
	if (setpriority(PRIO_PROCESS, 0, -20) == -1) {
		ortp_message("Ortp network simulator setpriority() failed: %s, nevermind.", strerror(errno));
	} else {
		ortp_message("Ortp network simulator priority increased to maximum.");
	}
#endif
}

static void *outboud_simulator_thread(void *ctx) {
	RtpSession *session = (RtpSession *)ctx;
	OrtpNetworkSimulatorCtx *sim = session->net_sim_ctx;
	ortpTimeSpec sleep_until;
	set_high_prio();

	while (sim->thread_started) {
		sleep_until.tv_sec = 0;
		sleep_until.tv_nsec = 0;
		rtp_session_schedule_outbound_network_simulator(session, &sleep_until);
		if (sleep_until.tv_sec != 0) ortp_sleep_until(&sleep_until);
		else bctbx_sleep_ms(1);
	}
	return NULL;
}

const char *ortp_network_simulator_mode_to_string(OrtpNetworkSimulatorMode mode) {
	switch (mode) {
		case OrtpNetworkSimulatorInbound:
			return "Inbound";
		case OrtpNetworkSimulatorOutbound:
			return "Outbound";
		case OrtpNetworkSimulatorOutboundControlled:
			return "OutboundControlled";
		case OrtpNetworkSimulatorInvalid:
			return "Invalid";
	}
	return "invalid";
}

OrtpNetworkSimulatorMode ortp_network_simulator_mode_from_string(const char *str) {
	if (strcasecmp(str, "Inbound") == 0) return OrtpNetworkSimulatorInbound;
	if (strcasecmp(str, "Outbound") == 0) return OrtpNetworkSimulatorOutbound;
	if (strcasecmp(str, "OutboundControlled") == 0) return OrtpNetworkSimulatorOutboundControlled;
	return OrtpNetworkSimulatorInvalid;
}

void rtp_session_enable_network_simulation(RtpSession *session, const OrtpNetworkSimulatorParams *params) {
	set_high_prio();
	OrtpNetworkSimulatorCtx *sim = session->net_sim_ctx;
	if (params->enabled) {
		if (sim == NULL) {
			sim = simulator_ctx_new();
		} else {
			ortp_network_simulator_dump_stats(sim);
		}
		sim->drop_by_congestion = sim->drop_by_loss = sim->total_count = 0;
		sim->params = *params;
		if (sim->params.jitter_burst_density > 0 && sim->params.jitter_strength > 0 && sim->params.max_bandwidth == 0) {
			sim->params.max_bandwidth = 1024000;
			ortp_message(
			    "Network simulation: jitter requested but max_bandwidth is not set. Using default value of %f bits/s.",
			    sim->params.max_bandwidth);
		}
		if (sim->params.max_bandwidth && sim->params.max_buffer_size == 0) {
			sim->params.max_buffer_size = (int)sim->params.max_bandwidth;
			ortp_message("Network simulation: Max buffer size not set for RTP session [%p], using [%i]", session,
			             sim->params.max_buffer_size);
		}
		session->net_sim_ctx = sim;
		if ((params->mode == OrtpNetworkSimulatorOutbound || params->mode == OrtpNetworkSimulatorOutboundControlled) &&
		    !sim->thread_started) {
			sim->thread_started = TRUE;
			ortp_thread_create(&sim->thread, NULL, outboud_simulator_thread, session);
		}

		ortp_message("Network simulation: enabled with the following parameters:\n"
		             "\tlatency=%d\n"
		             "\tloss_rate=%.1f\n"
		             "\tconsecutive_loss_probability=%.1f\n"
		             "\tmax_bandwidth=%.1f\n"
		             "\tmax_buffer_size=%d\n"
		             "\tjitter_density=%.1f\n"
		             "\tjitter_strength=%.1f\n"
		             "\tmode=%s",
		             params->latency, params->loss_rate, params->consecutive_loss_probability, params->max_bandwidth,
		             params->max_buffer_size, params->jitter_burst_density, params->jitter_strength,
		             ortp_network_simulator_mode_to_string(params->mode));
	} else {
		if (sim) {
			/* stop thread first: it is using the main_mutex internally and we don't want a deadlock with
			 * pthread_join(). */
			ortp_network_simulator_stop_thread(sim);
		}
		ortp_mutex_lock(&session->main_mutex);
		session->net_sim_ctx = NULL; /* RtpSession can no longer use it from now on */
		ortp_mutex_unlock(&session->main_mutex);
		ortp_message("rtp_session_enable_network_simulation:DISABLING NETWORK SIMULATION");
		if (sim != NULL) ortp_network_simulator_destroy(sim);
	}
}

static int64_t elapsed_us(struct timeval *tv1, struct timeval *tv2) {
	return ((tv2->tv_sec - tv1->tv_sec) * 1000000LL) + ((tv2->tv_usec - tv1->tv_usec));
}

static mblk_t *simulate_latency(RtpSession *session, mblk_t *input) {
	OrtpNetworkSimulatorCtx *sim = session->net_sim_ctx;
	struct timeval current;
	mblk_t *output = NULL;
	uint32_t current_ts;
	bctbx_gettimeofday(&current, NULL);
	/*since we must store expiration date in reserved2(32bits) only(reserved1
	already used), we need to reduce time stamp to milliseconds only*/
	current_ts = 1000 * current.tv_sec + current.tv_usec / 1000;

	/*queue the packet - store expiration timestamps in reserved fields*/
	if (input) {
		input->reserved2 = current_ts + sim->params.latency;
		putq(&sim->latency_q, input);
	}

	if ((output = peekq(&sim->latency_q)) != NULL) {
		if (TIME_IS_NEWER_THAN(current_ts, output->reserved2)) {
			output->reserved2 = 0;
			getq(&sim->latency_q);
			/*return the first dequeued packet*/
			return output;
		}
	}

	return NULL;
}

static int simulate_jitter_by_bit_budget_reduction(OrtpNetworkSimulatorCtx *sim, int budget_increase) {
	unsigned int r = bctbx_random() % 1000;
	float threshold, score;
	int budget_adjust = 0;
	uint64_t now = bctbx_get_cur_time_ms();

	if (sim->last_jitter_event == 0) {
		sim->last_jitter_event = bctbx_get_cur_time_ms();
	}

	if (sim->in_jitter_event) {
		threshold = 100;
		score = (float)r;
	} else {
		score = 1000.0f * (float)r * (now - sim->last_jitter_event) * sim->params.jitter_burst_density * 1e-6f;
		threshold = 500;
	}
	if (score > (int)threshold) {
		int64_t strength_rand = (int64_t)(sim->params.jitter_strength * (float)(bctbx_random() % 1000));
		sim->in_jitter_event = TRUE;
		budget_adjust = (int)-((int64_t)budget_increase * strength_rand / 1000LL);
		/*ortp_message("jitter in progress... bit_budget_adjustement=%i,
		 * bit_budget=%i",budget_adjust,sim->bit_budget);*/
	} else if (sim->in_jitter_event) {
		/*ortp_message("jitter ended.");*/
		sim->in_jitter_event = FALSE;
		sim->last_jitter_event = bctbx_get_cur_time_ms();
	}
	return budget_adjust;
}

static int get_packet_overhead(RtpSession *session, mblk_t *packet) {
	bool_t is_rtp_packet = packet->reserved1;
	bool_t is_ipv6 = is_rtp_packet ? ortp_stream_is_ipv6(&session->rtp.gs) : ortp_stream_is_ipv6(&session->rtcp.gs);
	return is_ipv6 ? IP6_UDP_OVERHEAD : IP_UDP_OVERHEAD;
}

static mblk_t *simulate_bandwidth_limit_and_jitter(RtpSession *session, mblk_t *input) {
	OrtpNetworkSimulatorCtx *sim = session->net_sim_ctx;
	struct timeval current;
	int64_t elapsed;
	int bits;
	int budget_increase;
	mblk_t *output = NULL;

	bctbx_gettimeofday(&current, NULL);

	if (sim->last_check.tv_sec == 0) {
		sim->last_check = current;
		sim->bit_budget = 0;
	}
	/*update the budget */
	elapsed = elapsed_us(&sim->last_check, &current);
	budget_increase = (int)((elapsed * (int64_t)sim->params.max_bandwidth) / 1000000LL);
	sim->bit_budget += budget_increase;
	sim->bit_budget += simulate_jitter_by_bit_budget_reduction(sim, budget_increase);
	sim->last_check = current;
	/* queue the packet for sending*/
	if (input) {
		putq(&sim->q, input);
		bits = ((int)msgdsize(input) + get_packet_overhead(session, input)) * 8;
		sim->qsize += bits;
	}
	/*flow control*/
	while (sim->qsize >= sim->params.max_buffer_size) {
		// ortp_message("rtp_session_network_simulate(): discarding packets.");
		output = getq(&sim->q);
		if (output) {
			bits = ((int)msgdsize(output) + get_packet_overhead(session, output)) * 8;
			sim->qsize -= bits;
			sim->drop_by_congestion++;
			freemsg(output);
		}
	}

	output = peekq(&sim->q);

	if (output) {
		bits = ((int)msgdsize(output) + get_packet_overhead(session, output)) * 8;
		/*see if we can output a packet*/
		if (sim->bit_budget >= bits) {
			sim->bit_budget -= bits;
			sim->qsize -= bits;
			output = getq(&sim->q);
		} else output = NULL;
	}
	if (qempty(&sim->q) && sim->bit_budget >= 0) {
		/* unused budget is lost...*/
		sim->last_check.tv_sec = 0;
	}
	return output;
}

static mblk_t *simulate_loss_rate(OrtpNetworkSimulatorCtx *net_sim_ctx, mblk_t *input) {
	int rrate;
	float loss_rate = net_sim_ctx->params.loss_rate * 10.0f;

	/*in order to simulate bursts of dropped packets, take into account a different probability after a loss occurred*/
	if (net_sim_ctx->consecutive_drops > 0) {
		loss_rate = net_sim_ctx->params.consecutive_loss_probability * 1000.0f;
	}

	rrate = bctbx_random() % 1000;

	if (rrate >= loss_rate) {
		if (net_sim_ctx->consecutive_drops) {
			/*after a burst of lost packets*/
			net_sim_ctx->drops_to_ignore =
			    net_sim_ctx->consecutive_drops -
			    (int)(((float)net_sim_ctx->consecutive_drops * net_sim_ctx->params.loss_rate) / 100.0f);
			net_sim_ctx->consecutive_drops = 0;
		}
		return input;
	}
	if (net_sim_ctx->drops_to_ignore > 0) {
		net_sim_ctx->drops_to_ignore--;
		return input;
	}
	if (net_sim_ctx->params.consecutive_loss_probability > 0) {
		net_sim_ctx->consecutive_drops++;
	}
	net_sim_ctx->drop_by_loss++;
	freemsg(input);
	return NULL;
}

mblk_t *rtp_session_network_simulate(RtpSession *session, mblk_t *input, bool_t *is_rtp_packet) {
	OrtpNetworkSimulatorCtx *sim = session->net_sim_ctx;
	mblk_t *om = NULL;

	om = input;

	/*while packet is stored in network simulator queue, keep its type in reserved1 space*/
	if (om != NULL) {
		sim->total_count++;
		om->reserved1 = *is_rtp_packet;
	}

	if (sim->params.latency > 0) {
		om = simulate_latency(session, om);
	}

	if ((sim->params.loss_rate > 0) && (om != NULL)) {
		if (sim->params.rtp_only == TRUE) {
			if (*is_rtp_packet == TRUE) {
				om = simulate_loss_rate(sim, om);
			}
		} else {
			om = simulate_loss_rate(sim, om);
		}
	}

	if (sim->params.max_bandwidth > 0) {
		om = simulate_bandwidth_limit_and_jitter(session, om);
	}

	/*finally when releasing the packet from the simulator, reset the reserved1 space to default,
	since it will be used by mediastreamer later*/
	if (om != NULL) {
		*is_rtp_packet = om->reserved1;
		om->reserved1 = 0;
	}
	return om;
}

static mblk_t *rtp_session_netsim_find_next_packet_to_send(RtpSession *session) {
	mblk_t *om;
	ortpTimeSpec min_packet_time = {0, 0};
	ortpTimeSpec packet_time;
	mblk_t *next_packet = NULL;

	for (om = qbegin(&session->net_sim_ctx->send_q); !qend(&session->net_sim_ctx->send_q, om);
	     om = qnext(&session->net_sim_ctx->send_q, om)) {
		packet_time.tv_sec = om->timestamp.tv_sec;
		packet_time.tv_nsec = om->timestamp.tv_usec * 1000LL;
		if (packet_time.tv_sec == 0 && packet_time.tv_nsec == 0) {
			/*this is a packet to drop*/
			return om;
		}
		if (min_packet_time.tv_sec == 0 || ortp_timespec_compare(&packet_time, &min_packet_time) < 0) {
			min_packet_time = packet_time;
			next_packet = om;
		}
	}
	return next_packet;
}

static void rtp_session_schedule_outbound_network_simulator(RtpSession *session, ortpTimeSpec *sleep_until) {
	mblk_t *om;
	int count = 0;
	bool_t is_rtp_packet;

	if (!session->net_sim_ctx) return;

	if (!session->net_sim_ctx->params.enabled) return;

	if (session->net_sim_ctx->params.mode == OrtpNetworkSimulatorOutbound) {
		sleep_until->tv_sec = 0;
		sleep_until->tv_nsec = 0;
		ortp_mutex_lock(&session->main_mutex);
		while ((om = getq(&session->net_sim_ctx->send_q)) != NULL) {
			count++;
			ortp_mutex_unlock(&session->main_mutex);
			is_rtp_packet = om->reserved1; /*it was set by rtp_session_sendto()*/
			om = rtp_session_network_simulate(session, om, &is_rtp_packet);
			if (om) {
				_ortp_sendto(rtp_session_get_socket(session, is_rtp_packet), om, 0, (struct sockaddr *)&om->net_addr,
				             om->net_addrlen);
				freemsg(om);
			}
			ortp_mutex_lock(&session->main_mutex);
		}
		ortp_mutex_unlock(&session->main_mutex);
		if (count == 0) {
			/*even if no packets were queued, we have to schedule the simulator*/
			is_rtp_packet = TRUE;
			om = rtp_session_network_simulate(session, NULL, &is_rtp_packet);
			if (om) {
				_ortp_sendto(rtp_session_get_socket(session, is_rtp_packet), om, 0, (struct sockaddr *)&om->net_addr,
				             om->net_addrlen);
				freemsg(om);
			}
		}
	} else if (session->net_sim_ctx->params.mode == OrtpNetworkSimulatorOutboundControlled) {
		ortpTimeSpec current = {0};
		ortpTimeSpec packet_time;
		mblk_t *todrop = NULL;

		ortp_mutex_lock(&session->main_mutex);
		while ((om = rtp_session_netsim_find_next_packet_to_send(session)) != NULL) {
			is_rtp_packet = om->reserved1; /*it was set by rtp_session_sendto()*/
			ortp_mutex_unlock(&session->main_mutex);
			if (todrop) {
				freemsg(todrop); /*free the last message while the mutex is not held*/
				todrop = NULL;
			}
			bctbx_get_utc_cur_time(&current);
			packet_time.tv_sec = om->timestamp.tv_sec;
			packet_time.tv_nsec = om->timestamp.tv_usec * 1000LL;
			if (is_rtp_packet && om->timestamp.tv_sec == 0 && om->timestamp.tv_usec == 0) {
				todrop = om; /*simulate a packet loss, only RTP packets can be dropped. Timestamp is not set for RTCP
				                packets*/
			} else if (ortp_timespec_compare(&packet_time, &current) <= 0) {
				/*it is time to send this packet*/

				_ortp_sendto(is_rtp_packet ? session->rtp.gs.socket : session->rtcp.gs.socket, om, 0,
				             (struct sockaddr *)&om->net_addr, om->net_addrlen);
				todrop = om;
			} else {
				/*no packet is to be sent yet; set the time at which we want to be called*/
				*sleep_until = packet_time;
				ortp_mutex_lock(&session->main_mutex);
				break;
			}
			ortp_mutex_lock(&session->main_mutex);
			if (todrop) remq(&session->net_sim_ctx->send_q, todrop); /* remove the message while the mutex is held*/
		}
		ortp_mutex_unlock(&session->main_mutex);
		if (todrop) freemsg(todrop);
		if (sleep_until->tv_sec == 0) {
			bctbx_get_utc_cur_time(&current);
			/*no pending packet in the queue yet, schedule a wake up not too far*/
			sleep_until->tv_sec = current.tv_sec;
			sleep_until->tv_nsec = current.tv_nsec + 1000000LL; /*in 1 ms*/
		}
	}
}
