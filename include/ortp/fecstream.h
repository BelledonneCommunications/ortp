#include "ortp/ortp.h"

typedef struct _FecParameters{
    int L;
    int D;
    int size_of_source_queue;
} FecParameters;

typedef struct _FecStream{
    RtpSession *source_session;
    RtpSession *fec_session;
    int cpt;
    uint32_t SSRC;
    uint8_t *bitstring;
    uint16_t *seqnumlist;
    queue_t source_packets_recvd;
    queue_t repair_packets_recvd;
    FecParameters params;
} FecStream;

FecParameters *fec_params_new(int L, int D, int size);

ORTP_PUBLIC FecStream *fec_stream_new(RtpSession *source, RtpSession *fec, const FecParameters *params);

void fec_stream_on_new_source_packet_sent(FecStream *fec_stream, mblk_t *source_packet);

void fec_stream_on_new_source_packet_received(FecStream *fec_stream, mblk_t *source_packet);

mblk_t *fec_stream_reconstruct_missing_packet(FecStream *fec_stream, uint16_t seqnum);

mblk_t *fec_stream_reconstruct_packet(FecStream *fec_stream, queue_t *source_packets_set, mblk_t *repair_packet, uint16_t seqnum);

uint16_t *fec_stream_create_sequence_numbers_set(mblk_t *repair_packet, FecStream *fec_stream);

mblk_t *fec_stream_find_repair_packet(FecStream *fec_stream, uint16_t seqnum);

bool_t fec_stream_find_source_packets(FecStream *fec_stream, mblk_t *repair_packet, queue_t *source_packets);
