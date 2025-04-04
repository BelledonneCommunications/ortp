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

/**
 * \file rtpsession.h
 * \brief The RtpSession api
 *
 * The RtpSession objects represent a RTP session: once it is configured with
 * local and remote network addresses and a payload type is given, it let you send
 * and recv a media stream.
 **/

#ifndef RTPSESSION_H
#define RTPSESSION_H

#include <bctoolbox/list.h>

#include <ortp/event.h>
#include <ortp/payloadtype.h>
#include <ortp/port.h>
#include <ortp/rtcp.h>
#include <ortp/rtp.h>
#include <ortp/rtpprofile.h>
#include <ortp/rtpsignaltable.h>
#include <ortp/sessionset.h>
#include <ortp/str_utils.h>
#include <ortp/utils.h>

#define ORTP_AVPF_FEATURE_NONE 0
#define ORTP_AVPF_FEATURE_TMMBR (1 << 0)
#define ORTP_AVPF_FEATURE_GENERIC_NACK (1 << 1)
#define ORTP_AVPF_FEATURE_IMMEDIATE_NACK (1 << 2)
#define ORTP_AVPF_FEATURE_GOOG_REMB (1 << 3)

typedef enum { RTP_SESSION_RECVONLY, RTP_SESSION_SENDONLY, RTP_SESSION_SENDRECV } RtpSessionMode;

typedef enum _OrtpJitterBufferAlgorithm {
	OrtpJitterBufferBasic,
	OrtpJitterBufferRecursiveLeastSquare,
} OrtpJitterBufferAlgorithm;

/*! Jitter buffer parameters
 */
typedef struct _JBParameters {
	int min_size;    /*(adaptive=TRUE only) maximum dynamic delay to be added to incoming packets (ms) */
	int nom_size;    /*(adaptive=TRUE only) initial dynamic delay to be added to incoming packets (ms) */
	int max_size;    /*(adaptive=TRUE only) minimum dynamic delay to be added to incoming packets (ms) */
	bool_t adaptive; /*either a dynamic buffer should be used or not to compensate bursts */
	bool_t enabled;  /*whether jitter buffer is enabled*/
	bool_t pad[2];   /*(dev only) alignment pad: insert your bool_t here*/
	int max_packets; /**max number of packets allowed to be queued in the jitter buffer */
	OrtpJitterBufferAlgorithm buffer_algorithm;
	int refresh_ms;      /* (adaptive=TRUE only) dynamic buffer size update frequency (ms) */
	int ramp_threshold;  /*(adaptive=TRUE, algo=RLS only) Percentage in [0;100] threshold between current jitter and
	                        previous jitter to enable smooth ramp*/
	int ramp_step_ms;    /*(adaptive=TRUE, algo=RLS only) In smooth ramp, how much we should reduce jitter size on each
	                        step*/
	int ramp_refresh_ms; /*(adaptive=TRUE, algo=RLS only) In smooth ramp, frequency of step*/
} JBParameters;

typedef struct _JitterControl {
	JBParameters params;
	unsigned int count; /* number of packets handled in jitter_control_new_packet. Used internally only. */
	int jitt_comp_ts;   /* the nominal jitter buffer size converted in rtp time (same unit as timestamp) */
	int adapt_jitt_comp_ts;
	int32_t clock_offset_ts; /*offset difference between local and distant clock, in timestamp units*/
	int32_t prev_clock_offset_ts;
	int32_t olddiff;
	float jitter;
	float inter_jitter;            /* interarrival jitter as defined in the RFC */
	float jitter_buffer_mean_size; /*effective size (fullness) of jitter buffer*/
	int corrective_step;
	int corrective_slide;
	uint64_t cum_jitter_buffer_size;      /*in timestamp units*/
	unsigned int cum_jitter_buffer_count; /*used for computation of jitter buffer size*/
	int clock_rate;
	uint32_t adapt_refresh_prev_ts; /*last time we refreshed the buffer*/
	OrtpExtremum max_ts_deviation;  /*maximum difference between packet and expected timestamps */
	OrtpKalmanRLS kalman_rls;
	double capped_clock_ratio;
	uint32_t last_log_ts;
	uint32_t local_ts_start;
	uint32_t remote_ts_start;
	uint32_t diverged_start_ts;
	bool_t is_diverging;
	bool_t jb_size_updated;
	bool_t pad[2];
} JitterControl;

typedef struct _WaitPoint {
	ortp_mutex_t lock;
	ortp_cond_t cond;
	uint32_t time;
	bool_t wakeup;
} WaitPoint;

typedef enum {
	RtpTransportModifierLevelEncryption,
	RtpTransportModifierLevelForwardErrorCorrection,
	RtpTransportModifierLevelAudioBandwidthEstimator, // The audio bandwith estimator must be executed last(in sending)
	                                                  // and first (in receiving), keep this enum last
} RtpTransportModifierLevel;

#define ORTP_RTP_TRANSPORT_MODIFIER_DEFAULT_LEVEL RtpTransportModifierLevelEncryption

typedef struct _RtpTransportModifier {
	void *data;
	RtpTransportModifierLevel level;
	struct _RtpSession *session;     //<back pointer to the owning session, set by oRTP
	struct _RtpTransport *transport; //<back point to the owning transport, set by oRTP
	int (*t_process_on_send)(struct _RtpTransportModifier *t, mblk_t *msg);
	int (*t_process_on_receive)(struct _RtpTransportModifier *t, mblk_t *msg);
	void (*t_process_on_schedule)(struct _RtpTransportModifier *t); /*invoked each time rtp_session_recvm is called even
	                                                                   is no message are available*/
	/**
	 * Mandatory callback responsible of freeing the #_RtpTransportModifier AND the pointer.
	 * @param[in] transport #_RtpTransportModifier object to free.
	 */
	void (*t_destroy)(struct _RtpTransportModifier *transport);
} RtpTransportModifier;

typedef struct _RtpTransport {
	void *data;
	struct _RtpSession *session; //<back pointer to the owning session, set by oRTP
	ortp_socket_t (*t_getsocket)(struct _RtpTransport *t);
	int (*t_sendto)(struct _RtpTransport *t, mblk_t *msg, int flags, const struct sockaddr *to, socklen_t tolen);
	int (*t_recvfrom)(struct _RtpTransport *t, mblk_t *msg, int flags, struct sockaddr *from, socklen_t *fromlen);
	void (*t_close)(struct _RtpTransport *transport);
	/**
	 * Mandatory callback responsible of freeing the #_RtpTransport object AND the pointer.
	 * @param[in] transport #_RtpTransport object to free.
	 */
	void (*t_destroy)(struct _RtpTransport *transport);
} RtpTransport;

typedef enum _OrtpNetworkSimulatorMode {
	OrtpNetworkSimulatorInvalid = -1,
	OrtpNetworkSimulatorInbound,           /**<simulation is applied when receiving packets*/
	OrtpNetworkSimulatorOutbound,          /**<simulation is applied to sent packets*/
	OrtpNetworkSimulatorOutboundControlled /**<simulation is applied to sent packets according to sent timestamps
	            set in the timestamps field of mblk_t, which is defined only with -DORTP_TIMESTAMP */
} OrtpNetworkSimulatorMode;

/**
 * Structure describing the network simulator parameters
 **/
typedef struct _OrtpNetworkSimulatorParams {
	int enabled;                        /**<Whether simulation is enabled or off.*/
	float max_bandwidth;                /**<IP bandwidth, in bit/s.
	                                   This limitation is applied after loss are simulated, so incoming bandwidth
	                                   is NOT socket bandwidth, but after-loss-simulation bandwidth e.g with 50% loss, the bandwidth
	                                   will be 50% reduced*/
	int max_buffer_size;                /**<Max number of bit buffered before being discarded*/
	float loss_rate;                    /**<Percentage of lost packets*/
	uint32_t latency;                   /**<Packet transmission delay, in ms*/
	float consecutive_loss_probability; /**< a probability of having a subsequent loss after a loss occurred, in a 0-1
	                                       range. Useful to simulate burst of lost packets*/
	float jitter_burst_density;         /**<density of gap/bursts events. A value of 1 means one gap/burst per second
	                                       approximately*/
	float jitter_strength;              /**<percentage of max_bandwidth artificially consumed during bursts events*/
	bool_t rtp_only;                    /**True for only RTP packet loss, False for both RTP and RTCP */
	bool_t pad[3];
	OrtpNetworkSimulatorMode mode; /**<whether simulation is applied to inbound or outbound stream.*/
} OrtpNetworkSimulatorParams;

typedef struct _OrtpNetworkSimulatorCtx {
	OrtpNetworkSimulatorParams params;
	int bit_budget;
	int qsize;
	queue_t q; /*queue used for simulating bandwidth limit*/
	queue_t latency_q;
	queue_t send_q; /*used only for OrtpNetworkSimulatorOutbound direction*/
	struct timeval last_check;
	uint64_t last_jitter_event;
	int consecutive_drops;
	int drops_to_ignore;
	int drop_by_congestion;
	int drop_by_loss;
	int total_count; /*total number of packets gone through the simulator*/
	ortp_thread_t thread;
	bool_t in_jitter_event;
	bool_t thread_started;
} OrtpNetworkSimulatorCtx;

typedef struct OrtpRtcpSendAlgorithm {
	uint64_t tn;             /* Time of the next scheduled RTCP RR transmission in milliseconds. */
	uint64_t tp;             /* Time of the last scheduled RTCP RR transmission in milliseconds. */
	uint64_t t_rr_last;      /* Time of the last regular RTCP packet sent in milliseconds. */
	uint32_t T_rr;           /* Interval for the scheduling of the next regular RTCP packet. */
	uint32_t T_max_fb_delay; /* Interval within which a feeback message is considered to be useful to the sender. */
	uint32_t T_rr_interval;  /* Minimal interval to be used between regular RTCP packets. */
	uint32_t T_rr_current_interval;
	uint32_t Tmin; /* Minimal interval between RTCP packets. */
	float avg_rtcp_size;
	mblk_t *fb_packets;
	bool_t initialized; /* Whether the RTCP send algorithm is fully initialized. */
	bool_t initial;
	bool_t allow_early;
	bool_t tmmbr_scheduled;
	bool_t tmmbn_scheduled;
	bool_t goog_remb_scheduled;
} OrtpRtcpSendAlgorithm;

typedef struct OrtpRtcpFbConfiguration {
	bool_t generic_nack_enabled;
	bool_t tmmbr_enabled;
	bool_t goog_remb_enabled;
} OrtpRtcpFbConfiguration;

#define ORTP_RTCP_XR_UNAVAILABLE_PARAMETER 127

typedef enum { OrtpRtcpXrNoPlc, OrtpRtcpXrSilencePlc, OrtpRtcpXrEnhancedPlc } OrtpRtcpXrPlcStatus;

typedef OrtpRtcpXrPlcStatus (*OrtpRtcpXrPlcCallback)(void *userdata);
typedef int (*OrtpRtcpXrSignalLevelCallback)(void *userdata);
typedef int (*OrtpRtcpXrNoiseLevelCallback)(void *userdata);
typedef float (*OrtpRtcpXrAverageQualityIndicatorCallback)(void *userdata);

typedef struct OrtpRtcpXrMediaCallbacks {
	OrtpRtcpXrPlcCallback plc;
	OrtpRtcpXrSignalLevelCallback signal_level;
	OrtpRtcpXrNoiseLevelCallback noise_level;
	OrtpRtcpXrAverageQualityIndicatorCallback average_qi;
	OrtpRtcpXrAverageQualityIndicatorCallback average_lq_qi;
	void *userdata;
} OrtpRtcpXrMediaCallbacks;

typedef enum { OrtpRtcpXrRcvrRttNone, OrtpRtcpXrRcvrRttAll, OrtpRtcpXrRcvrRttSender } OrtpRtcpXrRcvrRttMode;

typedef enum {
	OrtpRtcpXrStatSummaryNone = 0,
	OrtpRtcpXrStatSummaryLoss = (1 << 7),
	OrtpRtcpXrStatSummaryDup = (1 << 6),
	OrtpRtcpXrStatSummaryJitt = (1 << 5),
	OrtpRtcpXrStatSummaryTTL = (1 << 3),
	OrtpRtcpXrStatSummaryHL = (1 << 4)
} OrtpRtcpXrStatSummaryFlag;

typedef struct OrtpRtcpXrConfiguration {
	bool_t enabled;
	bool_t stat_summary_enabled;
	bool_t voip_metrics_enabled;
	bool_t pad;
	OrtpRtcpXrRcvrRttMode rcvr_rtt_mode;
	int rcvr_rtt_max_size;
	OrtpRtcpXrStatSummaryFlag stat_summary_flags;
} OrtpRtcpXrConfiguration;

typedef struct OrtpRtcpXrStats {
	uint32_t last_rcvr_rtt_ts;             /* NTP timestamp (middle 32 bits) of last received XR rcvr-rtt */
	struct timeval last_rcvr_rtt_time;     /* Time at which last XR rcvr-rtt was received  */
	uint16_t rcv_seq_at_last_stat_summary; /* Received sequence number at last XR stat-summary sent */
	uint32_t rcv_since_last_stat_summary;  /* The number of packets received since last XR stat-summary was sent */
	uint32_t
	    dup_since_last_stat_summary; /* The number of duplicate packets received since last XR stat-summary was sent */
	uint32_t min_jitter_since_last_stat_summary; /* The minimum value of jitter since last XR stat-summary was sent */
	uint32_t max_jitter_since_last_stat_summary; /* The maximum value of jitter since last XR stat-summary was sent */
	double olds_jitter_since_last_stat_summary;
	double oldm_jitter_since_last_stat_summary;
	double news_jitter_since_last_stat_summary;
	double newm_jitter_since_last_stat_summary;
	int64_t last_jitter_diff_since_last_stat_summary;
	double olds_ttl_or_hl_since_last_stat_summary;
	double oldm_ttl_or_hl_since_last_stat_summary;
	double news_ttl_or_hl_since_last_stat_summary;
	double newm_ttl_or_hl_since_last_stat_summary;
	uint8_t min_ttl_or_hl_since_last_stat_summary; /* The minimum value of TTL/HL since last XR stat-summary was sent */
	uint8_t max_ttl_or_hl_since_last_stat_summary; /* The maximum value of TTL/HL since last XR stat-summary was sent */
	uint32_t first_rcv_seq;
	uint32_t last_rcv_seq;
	uint32_t rcv_count;
	uint32_t discarded_count;
} OrtpRtcpXrStats;

typedef struct OrtpRtcpTmmbrInfo {
	mblk_t *sent;
	mblk_t *received;
} OrtpRtcpTmmbrInfo;

typedef struct OrtpRtcpGooRembInfo {
	mblk_t *sent;
	uint64_t sent_time;
} OrtpRtcpGooRembInfo;

typedef struct _OrtpAddress {
	struct sockaddr_storage addr;
	socklen_t len;
} OrtpAddress;

typedef struct _OrtpStream {
	ortp_socket_t socket;
	int sockfamily;
	int loc_port;
	socklen_t rem_addrlen;
	struct sockaddr_storage rem_addr;
	socklen_t rem_addr_previously_set_len;
	struct sockaddr_storage rem_addr_previously_set;
	socklen_t loc_addrlen;
	struct sockaddr_storage loc_addr;
	socklen_t used_loc_addrlen;
	struct sockaddr_storage used_loc_addr; /*Address used to redirect packets from this source*/
	struct _RtpTransport *tr;
	OrtpBandwidthMeasurer *recv_bw_estimator;
	OrtpBandwidthMeasurer *recv_average_bw_estimator;
	OrtpBandwidthMeasurer *send_bw_estimator;
	OrtpBandwidthMeasurer *send_average_bw_estimator;
	bctbx_list_t *aux_destinations; /*list of OrtpAddress */
	queue_t bundleq;                /* For bundle mode */
	ortp_mutex_t bundleq_lock;
	bool_t remote_address_adaptation;
} OrtpStream;

typedef struct _RtpStream {
	OrtpStream gs;
	int time_jump;
	uint32_t ts_jump;
	queue_t rq;
	queue_t tev_rq;
	void *QoSHandle;
	unsigned long QoSFlowID;
	JitterControl jittctl;
	uint32_t snd_time_offset;     /*the scheduler time when the application send its first timestamp*/
	uint32_t snd_ts_offset;       /* the first application timestamp sent by the application */
	uint32_t snd_rand_offset;     /* a random number added to the user offset to make the stream timestamp*/
	uint32_t snd_last_ts;         /* the last stream timestamp sent */
	uint16_t snd_last_nack;       /* the last nack sent when in immediate mode */
	uint32_t rcv_time_offset;     /*the scheduler time when the application ask for its first timestamp*/
	uint32_t rcv_ts_offset;       /* the first stream timestamp */
	uint32_t rcv_query_ts_offset; /* the first user timestamp asked by the application */
	uint32_t rcv_last_ts;         /* the last stream timestamp got by the application */
	uint16_t rcv_last_seq;        /* the last stream sequence number got by the application*/
	uint16_t snd_seq;             /* send sequence number */
	uint32_t rcv_last_app_ts;     /* the last application timestamp asked by the application */
	uint32_t rcv_last_ret_ts;     /* the timestamp of the last sample returned (only for continuous audio)*/
	uint32_t hwrcv_extseq;        /* last received on socket extended sequence number */
	uint32_t hwrcv_seq_at_last_SR;
	uint32_t hwrcv_since_last_SR;
	uint32_t last_rcv_SR_ts;         /* NTP timestamp (middle 32 bits) of last received SR */
	struct timeval last_rcv_SR_time; /* time at which last SR was received  */
	uint32_t last_rtcp_packet_count; /*the sender's octet count in the last sent RTCP SR*/
	uint32_t sent_payload_bytes;     /*used for RTCP sender reports*/
	int recv_errno;
	int send_errno;
	int snd_socket_size;
	int rcv_socket_size;
	int ssrc_changed_thres;
	jitter_stats_t jitter_stats;
	struct _OrtpCongestionDetector *congdetect;
	struct _OrtpVideoBandwidthEstimator *video_bw_estimator;
	struct _OrtpAudioBandwidthEstimator *audio_bw_estimator;
	ortp_thread_t win_t;
	volatile bool_t is_win_thread_running;
	ortp_mutex_t winthread_lock;
	queue_t winrq;
	ortp_mutex_t winrq_lock;
} RtpStream;

typedef struct _RtcpStream {
	OrtpStream gs;
	OrtpRtcpSendAlgorithm send_algo;
	OrtpRtcpXrConfiguration xr_conf;
	OrtpRtcpXrMediaCallbacks xr_media_callbacks;
	OrtpRtcpTmmbrInfo tmmbr_info;
	OrtpRtcpGooRembInfo goog_remb_info;
	bool_t enabled; /*tells whether we can send RTCP packets */
	bool_t rtcp_xr_dlrr_to_send;
	uint8_t rtcp_fb_fir_seq_nr; /* The FIR command sequence number */
	uint32_t last_rtcp_fb_pli_snt;
} RtcpStream;

typedef struct _RtcpSdesItems {
	char *cname;
	char *name;
	char *email;
	char *phone;
	char *loc;
	char *tool;
	char *note;
} RtcpSdesItems;

typedef struct _RtpSession RtpSession;

/**
 * An object representing a bi-directional RTP session.
 * It holds sockets, jitter buffer, various counters (timestamp, sequence numbers...)
 * Applications SHOULD NOT try to read things within the RtpSession object but use
 * instead its public API (the rtp_session_* methods) where RtpSession is used as a
 * pointer.
 * rtp_session_new() allocates and initialize a RtpSession.
 **/
struct _RtpSession {
	ortp_mutex_t main_mutex; /* To protect data that can be accessed simultaneously by a control thread and the
	                            real-time thread in charge of sending/receiving. */
	RtpSession *next;        /* next RtpSession, when the session are enqueued by the scheduler */
	int mask_pos; /* the position in the scheduler mask of RtpSession : do not move this field: it is part of the ABI
	                 since the session_set macros use it*/
	struct {
		RtpProfile *profile;
		int pt;
		unsigned int ssrc;
		WaitPoint wp;
	} snd, rcv;
	unsigned int inc_ssrc_candidate;
	int inc_same_ssrc_count;
	int hw_recv_pt; /* recv payload type before jitter buffer */
	int recv_buf_size;
	int target_upload_bandwidth;     /* Target upload bandwidth at network layer (with IP and UDP headers) in bits/s */
	int max_target_upload_bandwidth; /* the largest target upload bandwidth at network layer (with IP and UDP headers)
	                                    in bits/s ever set through rtp_session_set_target_upload_bandwidth */
	RtpSignalTable on_ssrc_changed;
	RtpSignalTable on_payload_type_changed;
	RtpSignalTable on_telephone_event_packet;
	RtpSignalTable on_telephone_event;
	RtpSignalTable on_timestamp_jump;
	RtpSignalTable on_network_error;
	RtpSignalTable on_rtcp_bye;
	RtpSignalTable on_new_incoming_ssrc_in_bundle; /**< triggered when we cannot find a session with this send.ssrc when
	                                                  looking for it while dispatching an incoming packet in a bundle
	                                                  and no free sessions are found */
	RtpSignalTable
	    on_new_outgoing_ssrc_in_bundle; /**< triggered when we cannot find a session with this send.ssrc when looking
	                                       for it while doing rtp_bundle_lookup_session_for_outgoing_packet */
	bctbx_list_t *signal_tables;
	bctbx_list_t *eventqs;
	RtpStream rtp;
	RtcpStream rtcp;
	OrtpRtcpXrStats rtcp_xr_stats;
	RtpSessionMode mode;
	struct _RtpScheduler *sched;
	mblk_t *recv_block_cache;
	uint32_t flags;
	int dscp;
	int multicast_ttl;
	int multicast_loopback;
	float duplication_ratio; /* Number of times a packet should be duplicated */
	float duplication_left;  /* Remainder of the duplication ratio, internal use */
	void *user_data;
	/* FIXME: Should be a table for all session participants. */
	struct timeval last_recv_time; /* Time of receiving the RTP/RTCP packet. */
	mblk_t *pending;
	/* telephony events extension */
	int tev_send_pt;     /*telephone event to be used for sending*/
	mblk_t *current_tev; /* the pending telephony events */
	queue_t contributing_sources;
	int lost_packets_test_vector;
	unsigned int interarrival_jitter_test_vector;
	unsigned int delay_test_vector;
	float rtt; /*last round trip delay calculated*/
	int cum_loss;
	OrtpNetworkSimulatorCtx *net_sim_ctx;
	RtpSession *spliced_session; /*a RtpSession that will retransmit everything received on this session*/
	rtp_stats_t stats;
	bctbx_list_t *recv_addr_map;
	uint32_t send_ts_offset; /*additional offset to add when sending packets */
	/* bundle mode */
	struct _RtpBundle *bundle; /* back pointer to the rtp bundle object */
	int mid_sent;
	uint64_t last_mid_sent_time;
	/* fec option */
	struct _FecStream *fec_stream;
	RtcpSdesItems sdes_items;
	bool_t symmetric_rtp;
	bool_t permissive;  /*use the permissive algorithm*/
	bool_t use_connect; /* use connect() on the socket */
	bool_t ssrc_set;

	bool_t reuseaddr; /*setsockopt SO_REUSEADDR */
	bool_t rtcp_mux;
	unsigned char avpf_features; /**< A bitmask of ORTP_AVPF_FEATURE_* macros. */
	bool_t use_pktinfo;

	bool_t is_spliced;
	bool_t congestion_detector_enabled;
	bool_t video_bandwidth_estimator_enabled;
	bool_t is_primary; /* tells if this session is the primary of the rtp bundle */

	bool_t warn_non_working_pkt_info;
	bool_t transfer_mode;
	bool_t audio_bandwidth_estimator_enabled;
};

/**
 * Structure describing the video bandwidth estimator parameters
 **/
typedef struct _OrtpVideoBandwidthEstimatorParams {
	int enabled;                        /**<Whether estimator is enabled or off.*/
	unsigned int packet_count_min;      /**<minimum number of packets with the same sent timestamp to be processed
	                                       continuously before being used */
	unsigned min_required_measurements; /**<Minimum number of measurements required to make an estimate */
	unsigned int
	    trust_percentage; /**<percentage for which the chosen bandwidth value in all available will be inferior */
} OrtpVideoBandwidthEstimatorParams;

/**
 * Structure describing the audio bandwidth estimator parameters
 **/
typedef struct _OrtpAudioBandwidthEstimatorParams {
	int enabled;                       /**<Whether estimator is enabled or off.*/
	unsigned int packets_history_size; /**< number of packets needed to compute the available video bandwidth */
	unsigned int
	    trust_percentage; /**< percentage for which the chosen bandwidth value in all available will be inferior */
	unsigned int duplicated_packet_rate; /**< the rate packets are duplicated by sender */
} OrtpAudioBandwidthEstimatorParams;

#ifdef __cplusplus
extern "C" {
#endif

ORTP_PUBLIC const char *ortp_network_simulator_mode_to_string(OrtpNetworkSimulatorMode mode);
ORTP_PUBLIC OrtpNetworkSimulatorMode ortp_network_simulator_mode_from_string(const char *str);

/* public API */
ORTP_PUBLIC RtpSession *rtp_session_new(RtpSessionMode mode);
ORTP_PUBLIC void rtp_session_set_mode(RtpSession *session, RtpSessionMode mode);
ORTP_PUBLIC void rtp_session_set_scheduling_mode(RtpSession *session, int yesno);
ORTP_PUBLIC void rtp_session_set_blocking_mode(RtpSession *session, int yesno);
ORTP_PUBLIC void rtp_session_set_profile(RtpSession *session, RtpProfile *profile);
ORTP_PUBLIC void rtp_session_set_send_profile(RtpSession *session, RtpProfile *profile);
ORTP_PUBLIC void rtp_session_set_recv_profile(RtpSession *session, RtpProfile *profile);
ORTP_PUBLIC RtpProfile *rtp_session_get_profile(RtpSession *session);
ORTP_PUBLIC RtpProfile *rtp_session_get_send_profile(RtpSession *session);
ORTP_PUBLIC RtpProfile *rtp_session_get_recv_profile(RtpSession *session);
ORTP_PUBLIC int
rtp_session_signal_connect(RtpSession *session, const char *signal_name, RtpCallback cb, void *user_data);
ORTP_PUBLIC int rtp_session_signal_connect_from_source_session(
    RtpSession *session, const char *signal_name, RtpCallback cb, void *user_data, const RtpSession *source);
ORTP_PUBLIC int rtp_session_signal_disconnect_by_callback(RtpSession *session, const char *signal_name, RtpCallback cb);
ORTP_PUBLIC int rtp_session_signal_disconnect_by_callback_and_user_data(RtpSession *session,
                                                                        const char *signal_name,
                                                                        RtpCallback cb,
                                                                        void *user_data);
ORTP_PUBLIC int
rtp_session_signal_disconnect_by_source_session(RtpSession *session, const char *signal_name, const RtpSession *source);
ORTP_PUBLIC void rtp_session_set_ssrc(RtpSession *session, uint32_t ssrc);
ORTP_PUBLIC uint32_t rtp_session_get_send_ssrc(const RtpSession *session);
ORTP_PUBLIC uint32_t rtp_session_get_recv_ssrc(RtpSession *session);
ORTP_PUBLIC void rtp_session_set_seq_number(RtpSession *session, uint16_t seq);
ORTP_PUBLIC uint16_t rtp_session_get_seq_number(RtpSession *session);
ORTP_PUBLIC uint32_t rtp_session_get_rcv_ext_seq_number(RtpSession *session);
ORTP_PUBLIC int rtp_session_get_cum_loss(RtpSession *session);
ORTP_PUBLIC void rtp_session_set_duplication_ratio(RtpSession *session, float ratio);

ORTP_PUBLIC void rtp_session_enable_jitter_buffer(RtpSession *session, bool_t enabled);
ORTP_PUBLIC bool_t rtp_session_jitter_buffer_enabled(const RtpSession *session);
ORTP_PUBLIC void rtp_session_set_jitter_buffer_params(RtpSession *session, const JBParameters *par);
ORTP_PUBLIC void rtp_session_get_jitter_buffer_params(RtpSession *session, JBParameters *par);

/**
 * Set an additional timestamps offset for outgoing stream..
 * @param s		a rtp session freshly created.
 * @param offset		a timestamp offset value
 *
 **/
ORTP_PUBLIC void rtp_session_set_send_ts_offset(RtpSession *s, uint32_t offset);
ORTP_PUBLIC uint32_t rtp_session_get_send_ts_offset(RtpSession *s);

/*deprecated jitter control functions*/
ORTP_PUBLIC void rtp_session_set_jitter_compensation(RtpSession *session, int milisec);
ORTP_PUBLIC void rtp_session_enable_adaptive_jitter_compensation(RtpSession *session, bool_t val);
ORTP_PUBLIC bool_t rtp_session_adaptive_jitter_compensation_enabled(RtpSession *session);

ORTP_PUBLIC void rtp_session_set_time_jump_limit(RtpSession *session, int miliseconds);
/*
 * Join a multicast group.
 * @deprecated Prefer using rtp_session_set_local_addr() by specifying multicast address and port to listen to.
 */
ORTP_PUBLIC int rtp_session_join_multicast_group(RtpSession *session, const char *ip);
ORTP_PUBLIC int rtp_session_set_local_addr(RtpSession *session, const char *addr, int rtp_port, int rtcp_port);
ORTP_PUBLIC int rtp_session_get_local_port(const RtpSession *session);
ORTP_PUBLIC int rtp_session_get_local_rtcp_port(const RtpSession *session);

ORTP_PUBLIC int rtp_session_set_remote_addr_full(
    RtpSession *session, const char *rtp_addr, int rtp_port, const char *rtcp_addr, int rtcp_port);
/*same as previous function, old name:*/
ORTP_PUBLIC int
rtp_session_set_remote_addr_and_port(RtpSession *session, const char *addr, int rtp_port, int rtcp_port);
ORTP_PUBLIC int rtp_session_set_remote_addr(RtpSession *session, const char *addr, int port);
ORTP_PUBLIC int rtp_session_add_aux_remote_addr_full(
    RtpSession *session, const char *rtp_addr, int rtp_port, const char *rtcp_addr, int rtcp_port);
ORTP_PUBLIC void rtp_session_clear_aux_remote_addr(RtpSession *session);
/* alternatively to the set_remote_addr() and set_local_addr(), an application can give
a valid socket (potentially connect()ed )to be used by the RtpSession */
ORTP_PUBLIC void rtp_session_set_sockets(RtpSession *session, int rtpfd, int rtcpfd);

ORTP_PUBLIC void rtp_session_get_transports(const RtpSession *session, RtpTransport **rtptr, RtpTransport **rtcptr);
/*those methods are provided for people who wants to send non-RTP messages using the RTP/RTCP sockets */
ORTP_PUBLIC ortp_socket_t rtp_session_get_rtp_socket(const RtpSession *session);
ORTP_PUBLIC ortp_socket_t rtp_session_get_rtcp_socket(const RtpSession *session);
ORTP_PUBLIC void rtp_session_refresh_sockets(RtpSession *session);

/* QOS / DSCP */
ORTP_PUBLIC int rtp_session_set_dscp(RtpSession *session, int dscp);
ORTP_PUBLIC int rtp_session_get_dscp(const RtpSession *session);

/* Packet info */
ORTP_PUBLIC int rtp_session_set_pktinfo(RtpSession *session, int activate);

/* Multicast methods */
ORTP_PUBLIC int rtp_session_set_multicast_ttl(RtpSession *session, int ttl);
ORTP_PUBLIC int rtp_session_get_multicast_ttl(RtpSession *session);

ORTP_PUBLIC int rtp_session_set_multicast_loopback(RtpSession *session, int yesno);
ORTP_PUBLIC int rtp_session_get_multicast_loopback(RtpSession *session);

ORTP_PUBLIC int rtp_session_set_send_payload_type(RtpSession *session, int paytype);
ORTP_PUBLIC int rtp_session_get_send_payload_type(const RtpSession *session);

ORTP_PUBLIC int rtp_session_get_recv_payload_type(const RtpSession *session);
ORTP_PUBLIC int rtp_session_set_recv_payload_type(RtpSession *session, int pt);

ORTP_PUBLIC int rtp_session_set_send_telephone_event_payload_type(RtpSession *session, int paytype);

ORTP_PUBLIC int rtp_session_set_payload_type(RtpSession *session, int pt);

ORTP_PUBLIC void rtp_session_set_symmetric_rtp(RtpSession *session, bool_t yesno);

ORTP_PUBLIC bool_t rtp_session_get_symmetric_rtp(const RtpSession *session);

ORTP_PUBLIC void rtp_session_enable_rtcp_mux(RtpSession *session, bool_t yesno);

ORTP_PUBLIC bool_t rtp_session_rtcp_mux_enabled(RtpSession *session);

ORTP_PUBLIC void rtp_session_set_connected_mode(RtpSession *session, bool_t yesno);

ORTP_PUBLIC void rtp_session_enable_rtcp(RtpSession *session, bool_t yesno);
/*
 * rtcp status
 * @return TRUE if rtcp is enabled for this session
 */
ORTP_PUBLIC bool_t rtp_session_rtcp_enabled(const RtpSession *session);

ORTP_PUBLIC void rtp_session_set_rtcp_report_interval(RtpSession *session, int value_ms);

/**
 * Define the bandwidth available for RTCP streams based on the upload bandwidth
 * targeted by the application (in bits/s). RTCP streams would not take more than
 * a few percents of the limit bandwidth (around 5%).
 *
 * @param session a rtp session
 * @param target_bandwidth bandwidth limit in bits/s
 */
ORTP_PUBLIC void rtp_session_set_target_upload_bandwidth(RtpSession *session, int target_bandwidth);
ORTP_PUBLIC int rtp_session_get_target_upload_bandwidth(RtpSession *session);

ORTP_PUBLIC void rtp_session_configure_rtcp_xr(RtpSession *session, const OrtpRtcpXrConfiguration *config);
ORTP_PUBLIC void rtp_session_set_rtcp_xr_media_callbacks(RtpSession *session, const OrtpRtcpXrMediaCallbacks *cbs);

ORTP_PUBLIC void rtp_session_set_ssrc_changed_threshold(RtpSession *session, int numpackets);

/* low level packet creation function */
/* deprecated set : use create_packet_header and then chain a payload mblk_t to it */
ORTP_PUBLIC ORTP_DEPRECATED mblk_t *
rtp_session_create_packet(RtpSession *session, size_t header_size, const uint8_t *payload, size_t payload_size);
ORTP_PUBLIC ORTP_DEPRECATED mblk_t *
rtp_session_create_packet_with_data(RtpSession *session, uint8_t *payload, size_t payload_size, void (*freefn)(void *));
ORTP_PUBLIC ORTP_DEPRECATED mblk_t *
rtp_session_create_packet_with_mixer_to_client_audio_level(RtpSession *session,
                                                           size_t header_size,
                                                           int mtc_extension_id,
                                                           size_t audio_levels_size,
                                                           rtp_audio_level_t *audio_levels,
                                                           const uint8_t *payload,
                                                           size_t payload_size);
ORTP_PUBLIC ORTP_DEPRECATED mblk_t *rtp_session_create_packet_raw(const uint8_t *packet, size_t packet_size);
/* end of deprecated functions set */

/**
 * Allocates a new rtp packet. In the header, ssrc and payload_type according to the session's
 * context. Timestamp is not set, it will be set when the packet is going to be
 * sent with rtp_session_sendm_with_ts(). Sequence number is initalized to previous sequence number sent + 1
 *
 * @param[in] 	session 		a rtp session.
 * @param[in] 	extra_header_size 	header size is computed according to needs(CSRC, extension header).
 *					Allocate extra size (when caller knows it will add other extensions or payload) to avoid
 *reallocating buffers
 *
 * @return a rtp packet in a mblk_t (message block) structure holding a packet header.
 **/
ORTP_PUBLIC mblk_t *rtp_session_create_packet_header(RtpSession *session, size_t extra_header_size);

/**
 * Allocates a new rtp packet. In the header, ssrc and payload_type according to the session's
 * context. Add a CSRC fetched from source session SSRC.
 * Timestamp is not set, it will be set when the packet is going to be
 * sent with rtp_session_sendm_with_ts(). Sequence number is initalized to previous sequence number sent + 1
 *
 * @param[in] 	fecSession 		The RTP session used to build the header (bundle and SSRC fetched from this one)
 * @param[in] 	sourceSession 		The SSRC from this RTP session is set as CSRC in the header
 * @param[in] 	extra_header_size 	header size is computed according to needs(CSRC, extension header).
 *					Allocate extra size (when caller knows it will add other extensions or payload) to avoid
 *reallocating buffers
 *
 * @return a rtp packet in a mblk_t (message block) structure holding a packet header.
 **/
ORTP_PUBLIC mblk_t *
rtp_session_create_repair_packet_header(RtpSession *fecSession, RtpSession *sourceSession, size_t extra_header_size);

/**
 *	This will do the same as rtp_session_create_packet_header() but it will also add
 *	mixer to client audio level indication through header extensions.
 *
 * @param[in]	session			a rtp session.
 * @param[in]	extra_header_size 	extra size allocated to the underlying mblk_t, use it to avoid reallocation cause by
 *future extension or payload added
 * @param[in]	mtc_extension_id 	id of the mixer to client extension id.
 * @param[in]	audio_levels_size	size of audio levels contained in audio_levels parameter.
 * @param[in]	audio_levels		list of rtp_audio_level_t to add in this packet.
 *
 * @return a rtp packet in a mblk_t (message block) structure.
 **/
ORTP_PUBLIC mblk_t *rtp_session_create_packet_header_with_mixer_to_client_audio_level(RtpSession *session,
                                                                                      size_t extra_header_size,
                                                                                      int mtc_extension_id,
                                                                                      size_t audio_levels_size,
                                                                                      rtp_audio_level_t *audio_levels);

/** create a packet from the given buffer. No header is added, the buffer is copied in a mblk_t allocated for this
 * purpose use to create non RTP packets (ZRTP, DTLS, STUN) or set a payload in a message (for CNG for example)
 * @param[in] packet		pointer to the data to be copied in the created packet
 * @param[in] packet_size	size of data buffer
 *
 * @return a packet in a message block structure holding the given buffer
 */
ORTP_PUBLIC mblk_t *rtp_create_packet(const uint8_t *packet, size_t packet_size);

/** create a packet from the given buffer. No header is added, the buffer is not copied but integrated to the packet
 * @param[in] packet		pointer to the data to be copied in the created packet
 * @param[in] packet_size	size of data buffer
 * @param[in] freefn		a function that will be called when the payload buffer is no more needed.
 *
 * @return a packet in a message block structure holding the given buffer
 */
ORTP_PUBLIC mblk_t *rtp_package_packet(uint8_t *packet, size_t packet_size, void (*freefn)(void *));

/*low level recv and send functions */

ORTP_PUBLIC mblk_t *rtp_session_recvm_with_ts(RtpSession *session, uint32_t user_ts);
ORTP_PUBLIC int rtp_session_sendm_with_ts(RtpSession *session, mblk_t *mp, uint32_t userts);
ORTP_PUBLIC int rtp_session_sendto(
    RtpSession *session, bool_t is_rtp, mblk_t *m, int flags, const struct sockaddr *destaddr, socklen_t destlen);
ORTP_PUBLIC int rtp_session_recvfrom(
    RtpSession *session, bool_t is_rtp, mblk_t *m, int flags, struct sockaddr *from, socklen_t *fromlen);
/* high level recv and send functions */
ORTP_PUBLIC int rtp_session_recv_with_ts(RtpSession *session, uint8_t *buffer, int len, uint32_t ts, int *have_more);
ORTP_PUBLIC int rtp_session_send_with_ts(RtpSession *session, const uint8_t *buffer, int len, uint32_t userts);

/* Specific function called to reset the winrq queue and if called on windows to stop the async reception thread */
ORTP_PUBLIC void rtp_session_reset_recvfrom(RtpSession *session);

/* event API*/
ORTP_PUBLIC void rtp_session_register_event_queue(RtpSession *session, OrtpEvQueue *q);
ORTP_PUBLIC void rtp_session_unregister_event_queue(RtpSession *session, OrtpEvQueue *q);
ORTP_PUBLIC void rtp_session_unregister_event_queues(RtpSession *session);

/* IP bandwidth usage estimation functions, returning bits/s*/
ORTP_PUBLIC float rtp_session_get_send_bandwidth(RtpSession *session);
ORTP_PUBLIC float rtp_session_get_recv_bandwidth(RtpSession *session);
ORTP_PUBLIC float rtp_session_get_rtp_send_bandwidth(RtpSession *session);
ORTP_PUBLIC float rtp_session_get_rtp_recv_bandwidth(RtpSession *session);
ORTP_PUBLIC float rtp_session_get_rtcp_send_bandwidth(RtpSession *session);
ORTP_PUBLIC float rtp_session_get_rtcp_recv_bandwidth(RtpSession *session);

ORTP_PUBLIC float rtp_session_get_send_bandwidth_smooth(RtpSession *session);
ORTP_PUBLIC float rtp_session_get_recv_bandwidth_smooth(RtpSession *session);

ORTP_PUBLIC void
rtp_session_send_rtcp_APP(RtpSession *session, uint8_t subtype, const char *name, const uint8_t *data, int datalen);
/**
 *	Send the rtcp datagram \a packet to the destination set by rtp_session_set_remote_addr()
 *  The packet (\a packet) is freed once it is sent.
 *
 * @param session a rtp session.
 * @param m a rtcp packet presented as a mblk_t.
 * @return the number of bytes sent over the network.
 **/

ORTP_PUBLIC int rtp_session_rtcp_sendm_raw(RtpSession *session, mblk_t *m);

ORTP_PUBLIC uint32_t rtp_session_get_current_send_ts(RtpSession *session);
ORTP_PUBLIC uint32_t rtp_session_get_current_recv_ts(RtpSession *session);
ORTP_PUBLIC void rtp_session_flush_sockets(RtpSession *session);
ORTP_PUBLIC void rtp_session_release_sockets(RtpSession *session);
ORTP_PUBLIC void rtp_session_resync(RtpSession *session);
ORTP_PUBLIC void rtp_session_reset(RtpSession *session);
ORTP_PUBLIC void rtp_session_destroy(RtpSession *session);

ORTP_PUBLIC const rtp_stats_t *rtp_session_get_stats(const RtpSession *session);
ORTP_PUBLIC const jitter_stats_t *rtp_session_get_jitter_stats(const RtpSession *session);
ORTP_PUBLIC void rtp_session_reset_stats(RtpSession *session);

ORTP_PUBLIC void rtp_session_set_data(RtpSession *session, void *data);
ORTP_PUBLIC void *rtp_session_get_data(const RtpSession *session);

ORTP_PUBLIC void rtp_session_set_recv_buf_size(RtpSession *session, int bufsize);
ORTP_PUBLIC void rtp_session_set_rtp_socket_send_buffer_size(RtpSession *session, unsigned int size);
ORTP_PUBLIC void rtp_session_set_rtp_socket_recv_buffer_size(RtpSession *session, unsigned int size);

/* in use with the scheduler to convert a timestamp in scheduler time unit (ms) */
ORTP_PUBLIC uint32_t rtp_session_ts_to_time(RtpSession *session, uint32_t timestamp);
ORTP_PUBLIC uint32_t rtp_session_time_to_ts(RtpSession *session, int millisecs);
/* this function aims at simulating senders with "imprecise" clocks, resulting in
rtp packets sent with timestamp uncorrelated with the system clock .
This is only availlable to sessions working with the oRTP scheduler */
ORTP_PUBLIC void rtp_session_make_time_distorsion(RtpSession *session, int milisec);

/*RTCP functions */
ORTP_PUBLIC void rtp_session_set_source_description(RtpSession *session,
                                                    const char *cname,
                                                    const char *name,
                                                    const char *email,
                                                    const char *phone,
                                                    const char *loc,
                                                    const char *tool,
                                                    const char *note);
ORTP_PUBLIC void rtp_session_add_contributing_source(RtpSession *session,
                                                     uint32_t csrc,
                                                     const char *cname,
                                                     const char *name,
                                                     const char *email,
                                                     const char *phone,
                                                     const char *loc,
                                                     const char *tool,
                                                     const char *note);
/* DEPRECATED: Use rtp_session_remove_contributing_source instead of rtp_session_remove_contributing_sources */
#define rtp_session_remove_contributing_sources rtp_session_remove_contributing_source
ORTP_PUBLIC void rtp_session_remove_contributing_source(RtpSession *session, uint32_t csrc);
ORTP_PUBLIC void rtp_session_clear_contributing_sources(RtpSession *session);
ORTP_PUBLIC mblk_t *rtp_session_create_rtcp_sdes_packet(RtpSession *session, bool_t full);

ORTP_PUBLIC void rtp_session_get_last_recv_time(RtpSession *session, struct timeval *tv);
ORTP_PUBLIC int rtp_session_bye(RtpSession *session, const char *reason);

ORTP_PUBLIC int rtp_session_get_last_send_error_code(RtpSession *session);
ORTP_PUBLIC void rtp_session_clear_send_error_code(RtpSession *session);
ORTP_PUBLIC int rtp_session_get_last_recv_error_code(RtpSession *session);
ORTP_PUBLIC void rtp_session_clear_recv_error_code(RtpSession *session);

ORTP_PUBLIC float rtp_session_get_round_trip_propagation(RtpSession *session);

ORTP_PUBLIC void rtp_session_enable_network_simulation(RtpSession *session, const OrtpNetworkSimulatorParams *params);
ORTP_PUBLIC void rtp_session_enable_congestion_detection(RtpSession *session, bool_t enabled);
ORTP_PUBLIC void rtp_session_reset_video_bandwidth_estimator(RtpSession *session);
ORTP_PUBLIC void rtp_session_enable_video_bandwidth_estimator(RtpSession *session,
                                                              const OrtpVideoBandwidthEstimatorParams *params);
ORTP_PUBLIC void rtp_session_enable_audio_bandwidth_estimator(RtpSession *session,
                                                              const OrtpAudioBandwidthEstimatorParams *params);

ORTP_PUBLIC void rtp_session_rtcp_set_lost_packet_value(RtpSession *session, const int value);
ORTP_PUBLIC void rtp_session_rtcp_set_jitter_value(RtpSession *session, const unsigned int value);
ORTP_PUBLIC void rtp_session_rtcp_set_delay_value(RtpSession *session, const unsigned int value);
ORTP_PUBLIC mblk_t *rtp_session_pick_with_cseq(RtpSession *session, const uint16_t sequence_number);

ORTP_PUBLIC void rtp_session_send_rtcp_xr_rcvr_rtt(RtpSession *session);
ORTP_PUBLIC void rtp_session_send_rtcp_xr_dlrr(RtpSession *session);
ORTP_PUBLIC void rtp_session_send_rtcp_xr_stat_summary(RtpSession *session);
ORTP_PUBLIC void rtp_session_send_rtcp_xr_voip_metrics(RtpSession *session);

ORTP_PUBLIC bool_t rtp_session_avpf_enabled(RtpSession *session);
ORTP_PUBLIC bool_t rtp_session_avpf_payload_type_feature_enabled(RtpSession *session, unsigned char feature);
ORTP_PUBLIC bool_t rtp_session_avpf_feature_enabled(RtpSession *session, unsigned char feature);
ORTP_PUBLIC void rtp_session_enable_avpf_feature(RtpSession *session, unsigned char feature, bool_t enable);
ORTP_PUBLIC uint16_t rtp_session_get_avpf_rr_interval(RtpSession *session);
ORTP_PUBLIC bool_t rtp_session_rtcp_psfb_scheduled(RtpSession *session, rtcp_psfb_type_t type);
ORTP_PUBLIC bool_t rtp_session_rtcp_rtpfb_scheduled(RtpSession *session, rtcp_rtpfb_type_t type);
ORTP_PUBLIC void rtp_session_send_rtcp_fb_generic_nack(RtpSession *session, uint16_t pid, uint16_t blp);
ORTP_PUBLIC void rtp_session_send_rtcp_fb_pli(RtpSession *session);
ORTP_PUBLIC void rtp_session_send_rtcp_fb_fir(RtpSession *session);
ORTP_PUBLIC void rtp_session_send_rtcp_fb_sli(RtpSession *session, uint16_t first, uint16_t number, uint8_t picture_id);
ORTP_PUBLIC void rtp_session_send_rtcp_fb_rpsi(RtpSession *session, uint8_t *bit_string, uint16_t bit_string_len);
ORTP_PUBLIC void rtp_session_send_rtcp_fb_tmmbr(RtpSession *session, uint64_t mxtbr);
ORTP_PUBLIC void rtp_session_send_rtcp_fb_tmmbn(RtpSession *session, uint32_t ssrc);
ORTP_PUBLIC void rtp_session_send_rtcp_fb_goog_remb(RtpSession *session, uint64_t mxtbr);

ORTP_PUBLIC void rtp_session_enable_transfer_mode(RtpSession *session, bool_t enable);
ORTP_PUBLIC bool_t rtp_session_transfer_mode_enabled(RtpSession *session);

/*private */
ORTP_PUBLIC void rtp_session_init(RtpSession *session, RtpSessionMode mode);
#define rtp_session_set_flag(session, flag) (session)->flags |= (flag)
#define rtp_session_unset_flag(session, flag) (session)->flags &= ~(flag)
ORTP_PUBLIC void rtp_session_uninit(RtpSession *session);
ORTP_PUBLIC void rtp_session_dispatch_event(RtpSession *session, OrtpEvent *ev);

ORTP_PUBLIC void rtp_session_set_reuseaddr(RtpSession *session, bool_t yes);

ORTP_PUBLIC int
meta_rtp_transport_sendto(RtpTransport *t, mblk_t *msg, int flags, const struct sockaddr *to, socklen_t tolen);

ORTP_PUBLIC int
meta_rtp_transport_modifier_inject_packet_to_send(RtpTransport *t, RtpTransportModifier *tpm, mblk_t *msg, int flags);
ORTP_PUBLIC int meta_rtp_transport_modifier_inject_packet_to_send_to(
    RtpTransport *t, RtpTransportModifier *tpm, mblk_t *msg, int flags, const struct sockaddr *to, socklen_t tolen);
ORTP_PUBLIC int
meta_rtp_transport_modifier_inject_packet_to_recv(RtpTransport *t, RtpTransportModifier *tpm, mblk_t *msg, int flags);

ORTP_PUBLIC int
meta_rtp_transport_apply_all_except_one_on_receive(RtpTransport *t, RtpTransportModifier *modifier, mblk_t *msg);
/**
 * get endpoint if any
 * @param[in] transport RtpTransport object.
 * @return #_RtpTransport
 *
 * */
ORTP_PUBLIC RtpTransport *meta_rtp_transport_get_endpoint(const RtpTransport *transport);
/**
 * set endpoint
 * @param[in] transport RtpTransport object.
 * @param[in] endpoint RtpEndpoint.
 *
 * */
ORTP_PUBLIC void meta_rtp_transport_set_endpoint(RtpTransport *transport, RtpTransport *endpoint);

ORTP_PUBLIC void meta_rtp_transport_destroy(RtpTransport *tp);
ORTP_PUBLIC void meta_rtp_transport_append_modifier(RtpTransport *tp, RtpTransportModifier *tpm);
ORTP_PUBLIC void meta_rtp_transport_prepend_modifier(RtpTransport *tp, RtpTransportModifier *tpm);
ORTP_PUBLIC void meta_rtp_transport_remove_modifier(RtpTransport *tp, RtpTransportModifier *tpm);

ORTP_PUBLIC int rtp_session_splice(RtpSession *session, RtpSession *to_session);
ORTP_PUBLIC int rtp_session_unsplice(RtpSession *session, RtpSession *to_session);

ORTP_PUBLIC bool_t ortp_stream_is_ipv6(OrtpStream *os);

/* RtpBundle api */
#define RTP_BUNDLE_MAX_SENT_MID_START 10
#define RTP_BUNDLE_MID_SENDING_INTERVAL 1000

typedef struct _RtpBundle RtpBundle;

ORTP_PUBLIC RtpBundle *rtp_bundle_new(void);
ORTP_PUBLIC void rtp_bundle_delete(RtpBundle *bundle);

ORTP_PUBLIC int rtp_bundle_get_mid_extension_id(RtpBundle *bundle);
ORTP_PUBLIC void rtp_bundle_set_mid_extension_id(RtpBundle *bundle, int id);

ORTP_PUBLIC void rtp_bundle_add_session(RtpBundle *bundle, const char *mid, RtpSession *session);

ORTP_PUBLIC void rtp_bundle_remove_sessions_by_id(RtpBundle *bundle, const char *mid);
ORTP_PUBLIC void rtp_bundle_remove_session(RtpBundle *bundle, RtpSession *session);
ORTP_PUBLIC void rtp_bundle_clear(RtpBundle *bundle);

ORTP_PUBLIC RtpSession *rtp_bundle_get_primary_session(RtpBundle *bundle);
ORTP_PUBLIC void rtp_bundle_set_primary_session(RtpBundle *bundle, RtpSession *session);

ORTP_PUBLIC char *rtp_bundle_get_session_mid(RtpBundle *bundle, RtpSession *session);

ORTP_PUBLIC int rtp_bundle_send_through_primary(
    RtpBundle *bundle, bool_t is_rtp, mblk_t *m, int flags, const struct sockaddr *destaddr, socklen_t destlen);

/**
 * @brief Dispatch a received packet through the bundle
 *
 * @param[in]	bundle	The bundle holding the rtp sessions
 * @param[in]	is_rtp	The type of the packet, RTP or RTCP
 * @param[in]	m	The packet to dispatch
 *
 * @return	the packet at destination of the primary session, NULL if there is none
 */
ORTP_PUBLIC mblk_t *rtp_bundle_dispatch(RtpBundle *bundle, bool_t is_rtp, mblk_t *m);

/**
 * @brief Retrieve a session from a bundle using an outgoing message
 *
 * @param[in]	bundle	The bundle holding the rtp sessions
 * @param[in]	m	The outgoing message
 * @return	the Rtp session used to send this message, NULL if not found in the bundle
 *
 * Warning: this function current implementation assumes a match MID/SSRC, it may change
 */
ORTP_PUBLIC RtpSession *rtp_bundle_lookup_session_for_outgoing_packet(RtpBundle *bundle, mblk_t *m);
ORTP_PUBLIC void
rtp_session_use_local_addr(RtpSession *session, const char *rtp_local_addr, const char *rtcp_local_addr);

typedef struct _FecStream FecStream;
typedef struct _FecParams FecParams;

typedef struct fec_stats_t {
	uint64_t col_repair_sent;
	uint64_t col_repair_received;
	uint64_t row_repair_sent;
	uint64_t row_repair_received;
	uint64_t packets_lost;          // number of source packets lost during the call, that can be repaired by FEC or not
	uint64_t packets_not_recovered; // number of source packets lost and not repaired
	uint64_t packets_recovered;     // number of source packets lost and repaired by FEC
} fec_stats;

ORTP_PUBLIC FecParams *fec_params_new(uint32_t repairWindow);
ORTP_PUBLIC void fec_params_destroy(FecParams *params);
ORTP_PUBLIC void fec_params_update(FecParams *params, uint8_t level);
ORTP_PUBLIC uint8_t fec_params_estimate_best_level(
    FecParams *params, float loss_rate, int bitrate, float current_overhead, float *estimated_overhead);

ORTP_PUBLIC FecStream *fec_stream_new(struct _RtpSession *source, struct _RtpSession *fec, FecParams *fecParams);
ORTP_PUBLIC void fec_stream_destroy(FecStream *fec_stream);
ORTP_PUBLIC void fec_stream_unsubscribe(FecStream *fec_stream, FecParams *fecParams);
ORTP_PUBLIC void fec_stream_reset_cluster(FecStream *fec_stream);
ORTP_PUBLIC void fec_stream_receive_repair_packet(FecStream *fec_stream, uint32_t timestamp);
ORTP_PUBLIC mblk_t *fec_stream_find_missing_packet(FecStream *fec_stream, uint16_t seqnum);
ORTP_PUBLIC RtpSession *fec_stream_get_fec_session(FecStream *fec_stream);
ORTP_PUBLIC void fec_stream_count_lost_packets(FecStream *fec_stream, uint16_t seqnum, int16_t diff);
ORTP_PUBLIC void fec_stream_print_stats(FecStream *fec_stream);
ORTP_PUBLIC fec_stats *fec_stream_get_stats(FecStream *fec_stream);
ORTP_PUBLIC bool_t fec_stream_enabled(FecStream *fec_stream);
ORTP_PUBLIC float fec_stream_get_overhead(FecStream *fec_stream);
ORTP_PUBLIC void fec_stream_reset_overhead_measure(FecStream *fec_stream);

/* Audio Bandwidth Estimator stats */
typedef struct abe_stats {
	uint32_t sent_dup; /**< Number of duplicated packet generated */
	uint32_t recv_dup; /**< Number of duplicated packet received(this includes only the one used to estimate
	                      bandwidth) */
} abe_stats_t;

/**
 * Get the stats from audio bandwidth estimator if any
 * @param[in]	session		The RtpSession holding the ABE
 *
 * @return the ABE stats, NULL if no ABE exists in the session
 */
ORTP_PUBLIC const abe_stats_t *rtp_session_get_audio_bandwidth_estimator_stats(RtpSession *session);

/**
 * Get the current duplication rate for the audio bandwidth estimator
 * @param[in]	session		The RtpSession holding the ABE
 *
 * @return the duplicate rate used by ABE, -1 if no ABE exists in the session
 */
ORTP_PUBLIC int rtp_session_get_audio_bandwidth_estimator_duplicate_rate(RtpSession *session);

#ifdef __cplusplus
}
#endif

#endif
