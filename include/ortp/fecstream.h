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
#ifndef FECSTREAM_H
#define FECSTREAM_H

#include "ortp/port.h"
#include "ortp/str_utils.h"

typedef struct _FecParameters{
    int L;
    int D;
    int source_queue_size;
    int repair_queue_size;
} FecParameters;

typedef struct _FecStream{
    struct _RtpSession *source_session;
    struct _RtpSession *fec_session;
    int cpt;
    size_t max_size;
    uint32_t SSRC;
    uint8_t *bitstring;
    uint16_t *seqnumlist;
    uint8_t *header_bitstring;
    uint8_t *payload_bitstring;
    queue_t source_packets_recvd;
    queue_t repair_packets_recvd;
    FecParameters params;
    int reconstruction_fail;
    int total_lost_packets;
    int repair_packet_not_found;
    int source_packets_not_found;
    int error;
    uint16_t *prec;
    int size_prec;
} FecStream;

ORTP_PUBLIC FecParameters *fec_params_new(int L, int D, int jitter);

ORTP_PUBLIC FecStream *fec_stream_new(struct _RtpSession *source, struct _RtpSession *fec, const FecParameters *params);

ORTP_PUBLIC void fec_stream_destroy(FecStream *fec_stream);

void fec_stream_on_new_source_packet_sent(FecStream *fec_stream, mblk_t *source_packet);

void fec_stream_on_new_source_packet_received(FecStream *fec_stream, mblk_t *source_packet);

ORTP_PUBLIC mblk_t *fec_stream_reconstruct_missing_packet(FecStream *fec_stream, uint16_t seqnum);

mblk_t *fec_stream_reconstruct_packet(FecStream *fec_stream, queue_t *source_packets_set, mblk_t *repair_packet, uint16_t seqnum);

uint16_t *fec_stream_create_sequence_numbers_set(FecStream *fec_stream, mblk_t *repair_packet);

mblk_t *fec_stream_find_repair_packet(FecStream *fec_stream, uint16_t seqnum);

bool_t fec_stream_find_source_packets(FecStream *fec_stream, mblk_t *repair_packet, queue_t *source_packets);

void fec_stream_reconstruction_error(FecStream *fec_stream, uint16_t seqnum);

#endif
