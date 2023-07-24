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

#ifndef RTP_H
#define RTP_H

#include <ortp/port.h>
#include <ortp/str_utils.h>

#define IPMAXLEN 20
#define UDP_MAX_SIZE 1500
#define RTP_FIXED_HEADER_SIZE 12
#define RTP_DEFAULT_JITTER_TIME 80             /*miliseconds*/
#define RTP_DEFAULT_MULTICAST_TTL 5            /*hops*/
#define RTP_DEFAULT_MULTICAST_LOOPBACK 0       /*false*/
#define RTP_DEFAULT_DSCP 0x00                  /*best effort*/
#define RTP_MAX_MIXER_TO_CLIENT_AUDIO_LEVEL 15 /* 15 because we can only put 15 csrc in a rtp packet */

typedef struct rtp_header {
#ifdef ORTP_BIGENDIAN
	uint16_t version : 2;
	uint16_t padbit : 1;
	uint16_t extbit : 1;
	uint16_t cc : 4;
	uint16_t markbit : 1;
	uint16_t paytype : 7;
#else
	uint16_t cc : 4;
	uint16_t extbit : 1;
	uint16_t padbit : 1;
	uint16_t version : 2;
	uint16_t paytype : 7;
	uint16_t markbit : 1;
#endif
	uint16_t seq_number;
	uint32_t timestamp;
	uint32_t ssrc;
	uint32_t csrc[16];
} rtp_header_t;

typedef struct rtp_stats {
	uint64_t packet_sent;     /*number of outgoing packets */
	uint64_t packet_dup_sent; /*number of outgoing duplicate packets */
	uint64_t sent;            /* outgoing total bytes (excluding IP header) */
	uint64_t packet_recv;     /* number of incoming packets */
	uint64_t packet_dup_recv; /* number of incoming duplicate packets */
	uint64_t recv;            /* incoming bytes of payload and delivered in time to the application */
	uint64_t hw_recv;         /* incoming bytes of payload */
	uint64_t outoftime;       /* number of incoming packets that were received too late */
	int64_t cum_packet_loss;  /* cumulative number of incoming packet lost */
	uint64_t bad;             /* incoming packets that did not appear to be RTP */
	uint64_t discarded;       /* incoming packets discarded because the queue exceeds its max size */
	uint64_t
	    sent_rtcp_packets; /* outgoing RTCP packets counter (only packets that embed a report block are considered) */
	uint64_t
	    recv_rtcp_packets; /* incoming RTCP packets counter (only packets that embed a report block are considered) */
	uint64_t loss_before_nack; /*Number of packets asked for a resend*/
} rtp_stats_t;

typedef struct jitter_stats {
	uint32_t jitter;             /* interarrival jitter at last emitted sender report */
	uint32_t max_jitter;         /* biggest interarrival jitter (value in stream clock unit) */
	uint64_t sum_jitter;         /* sum of all interarrival jitter (value in stream clock unit) */
	uint64_t max_jitter_ts;      /* date (in ms since Epoch) of the biggest interarrival jitter */
	float jitter_buffer_size_ms; /* mean jitter buffer size in milliseconds.*/
} jitter_stats_t;

/* MAX is 15 because we use 1-byte header */
typedef enum {
	RTP_EXTENSION_NONE = 0,
	RTP_EXTENSION_MID = 1,
	RTP_EXTENSION_CLIENT_TO_MIXER_AUDIO_LEVEL = 2,
	RTP_EXTENSION_MIXER_TO_CLIENT_AUDIO_LEVEL = 3,
	RTP_EXTENSION_FRAME_MARKING = 4,
	RTP_EXTENSION_MAX = 15
} rtp_extension_type_t;

typedef struct rtp_audio_level {
	uint32_t csrc;
	int dbov;
} rtp_audio_level_t;

#define RTP_FRAME_MARKER_START (1 << 7)
#define RTP_FRAME_MARKER_END (1 << 6)
#define RTP_FRAME_MARKER_INDEPENDENT (1 << 5)
#define RTP_FRAME_MARKER_DISCARDABLE (1 << 4)

#define RTP_TIMESTAMP_IS_NEWER_THAN(ts1, ts2) ((uint32_t)((uint32_t)(ts1) - (uint32_t)(ts2)) < ((uint32_t)1 << 31))

#define RTP_TIMESTAMP_IS_STRICTLY_NEWER_THAN(ts1, ts2)                                                                 \
	(((uint32_t)((uint32_t)(ts1) - (uint32_t)(ts2)) < ((uint32_t)1 << 31)) && (ts1) != (ts2))

#define RTP_SEQ_IS_STRICTLY_GREATER_THAN(seq1, seq2)                                                                   \
	(((uint16_t)((uint16_t)(seq1) - (uint16_t)(seq2)) < ((uint16_t)1 << 15)) && (seq1) != (seq2))

#define TIME_IS_NEWER_THAN(t1, t2) RTP_TIMESTAMP_IS_NEWER_THAN(t1, t2)

#define TIME_IS_STRICTLY_NEWER_THAN(t1, t2) RTP_TIMESTAMP_IS_STRICTLY_NEWER_THAN(t1, t2)

#ifdef __cplusplus
extern "C" {
#endif

/* packet api */
/* the first argument is a rtp_header_t  */
#define rtp_header_set_seqnumber(hdr, seq) (hdr)->seq_number = (htons(seq))
#define rtp_header_set_timestamp(hdr, ts) (hdr)->timestamp = (htonl(ts))
#define rtp_header_set_ssrc(hdr, _ssrc) (hdr)->ssrc = (htonl(_ssrc))
ORTP_PUBLIC void rtp_header_add_csrc(rtp_header_t *hdr, uint32_t csrc);

#define rtp_header_get_seqnumber(hdr) (ntohs((hdr)->seq_number))
#define rtp_header_get_timestamp(hdr) (ntohl((hdr)->timestamp))
#define rtp_header_get_ssrc(hdr) (ntohl((hdr)->ssrc))
#define rtp_header_get_csrc(hdr, idx) (ntohl((hdr)->csrc[idx]))

/* the first argument is a mblk_t. The header is supposed to be not splitted  */
#define rtp_set_version(mp, value) ((rtp_header_t *)((mp)->b_rptr))->version = (value)
#define rtp_set_padbit(mp, value) ((rtp_header_t *)((mp)->b_rptr))->padbit = (value)
#define rtp_set_extbit(mp, value) ((rtp_header_t *)((mp)->b_rptr))->extbit = (value)
#define rtp_set_cc(mp, value) ((rtp_header_t *)((mp)->b_rptr))->cc = (value)
#define rtp_set_markbit(mp, value) ((rtp_header_t *)((mp)->b_rptr))->markbit = (value)
#define rtp_set_payload_type(mp, pt) ((rtp_header_t *)((mp)->b_rptr))->paytype = (pt)
#define rtp_set_seqnumber(mp, seq) rtp_header_set_seqnumber((rtp_header_t *)((mp)->b_rptr), (seq))
#define rtp_set_timestamp(mp, ts) rtp_header_set_timestamp((rtp_header_t *)((mp)->b_rptr), (ts))
#define rtp_set_ssrc(mp, _ssrc) rtp_header_set_ssrc((rtp_header_t *)((mp)->b_rptr), (_ssrc))
ORTP_PUBLIC void rtp_add_csrc(mblk_t *mp, uint32_t csrc);

#define rtp_get_version(mp) (((rtp_header_t *)((mp)->b_rptr))->version)
#define rtp_get_padbit(mp) (((rtp_header_t *)((mp)->b_rptr))->padbit)
#define rtp_get_markbit(mp) (((rtp_header_t *)((mp)->b_rptr))->markbit)
#define rtp_get_extbit(mp) (((rtp_header_t *)((mp)->b_rptr))->extbit)
#define rtp_get_timestamp(mp) rtp_header_get_timestamp((rtp_header_t *)((mp)->b_rptr))
#define rtp_get_seqnumber(mp) rtp_header_get_seqnumber((rtp_header_t *)((mp)->b_rptr))
#define rtp_get_payload_type(mp) (((rtp_header_t *)((mp)->b_rptr))->paytype)
#define rtp_get_ssrc(mp) rtp_header_get_ssrc((rtp_header_t *)((mp)->b_rptr))
#define rtp_get_cc(mp) (((rtp_header_t *)((mp)->b_rptr))->cc)
#define rtp_get_csrc(mp, idx) rtp_header_get_csrc((rtp_header_t *)((mp)->b_rptr), (idx))

ORTP_PUBLIC int rtp_get_payload(mblk_t *packet, unsigned char **start);
ORTP_PUBLIC int rtp_get_extheader(const mblk_t *packet, uint16_t *profile, uint8_t **start_ext);

/* Extension header api */
ORTP_PUBLIC void rtp_add_extension_header(mblk_t *packet, int id, size_t size, uint8_t *data);
ORTP_PUBLIC void rtp_write_extension_header(mblk_t *packet, int id, size_t size, uint8_t *data);
ORTP_PUBLIC int rtp_get_extension_header(const mblk_t *packet, int id, uint8_t **data);

/* Audio Level api */
ORTP_PUBLIC void rtp_add_client_to_mixer_audio_level(mblk_t *packet, int id, bool_t voice_activity, int audio_level);
ORTP_PUBLIC int rtp_get_client_to_mixer_audio_level(mblk_t *packet, int id, bool_t *voice_activity);

ORTP_PUBLIC void
rtp_add_mixer_to_client_audio_level(mblk_t *packet, int id, size_t size, rtp_audio_level_t *audio_levels);
ORTP_PUBLIC void
rtp_write_mixer_to_client_audio_level(mblk_t *packet, int id, size_t size, rtp_audio_level_t *audio_levels);
ORTP_PUBLIC int rtp_get_mixer_to_client_audio_level(mblk_t *packet, int id, rtp_audio_level_t *audio_levels);

/* Frame marking api */
ORTP_PUBLIC void rtp_add_frame_marker(mblk_t *packet, int id, uint8_t marker);
ORTP_PUBLIC int rtp_get_frame_marker(mblk_t *packet, int id, uint8_t *marker);

#ifdef __cplusplus
}
#endif

#endif
