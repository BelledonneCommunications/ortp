#include "ortp/str_utils.h"
#include "ortp/rtp.h"
#include "ortp/rtpsession.h"
#include "ortp/fecstream.h"
#include "ortp/port.h"
#include "ortp/logging.h"

#ifndef MIN
#define MIN(a,b) (a < b ? a : b)
#endif

FecParameters *fec_params_new(int L, int D, int jitter){
    FecParameters *fec_params = (FecParameters *) ortp_malloc0(sizeof(FecParameters));
    fec_params->L = L;
    fec_params->D = D;
    fec_params->source_queue_size = L*jitter;
    fec_params->repair_queue_size = (10-L)*5;
    return fec_params;
}

FecStream *fec_stream_new(struct _RtpSession *source, struct _RtpSession *fec, const FecParameters *params){
    FecStream *fec_stream = (FecStream *) ortp_malloc0(sizeof(FecStream));
    fec_stream->source_session = source;
    fec_stream->fec_session = fec;
    rtp_session_enable_jitter_buffer(fec_stream->fec_session, FALSE);
    qinit(&fec_stream->source_packets_recvd);
    qinit(&fec_stream->repair_packets_recvd);
    fec_stream->params = *params;
    fec_stream->seqnumlist = (uint16_t *) ortp_malloc(fec_stream->params.L * sizeof(uint16_t));
    fec_stream->bitstring = (uint8_t *) ortp_malloc(UDP_MAX_SIZE * sizeof(uint8_t));
    fec_stream->header_bitstring = (uint8_t *) ortp_malloc(10 * sizeof(uint8_t));
    fec_stream->payload_bitstring = (uint8_t *) ortp_malloc(UDP_MAX_SIZE * sizeof(uint8_t));
    fec_stream->prec = (uint16_t *) ortp_malloc(fec_stream->params.L * sizeof(uint16_t));
    return fec_stream;
}

void fec_stream_destroy(FecStream *fec_stream){
    if(fec_stream->bitstring != NULL) ortp_free(fec_stream->bitstring);
    if(fec_stream->seqnumlist != NULL) ortp_free(fec_stream->seqnumlist);
    if(fec_stream->header_bitstring != NULL) ortp_free(fec_stream->header_bitstring);
    if(fec_stream->payload_bitstring != NULL) ortp_free(fec_stream->payload_bitstring);
    if(fec_stream->prec != NULL) ortp_free(fec_stream->prec);
    flushq(&fec_stream->source_packets_recvd, 0);
    flushq(&fec_stream->repair_packets_recvd, 0);
}

void fec_stream_on_new_source_packet_sent(FecStream *fec_stream, mblk_t *source_packet){
    msgpullup(source_packet, -1);

    ortp_message("Source packet size (SeqNum : %d) : %d", (int) rtp_get_seqnumber(source_packet), (int) (msgdsize(source_packet)-RTP_FIXED_HEADER_SIZE));

    if(fec_stream->cpt == 0){
        fec_stream->SSRC = rtp_get_ssrc(source_packet);
        memset(fec_stream->bitstring, 0, UDP_MAX_SIZE * sizeof(uint8_t));
        fec_stream->bitstring[0] = 1 << 6;
    }

    if(fec_stream->max_size < (msgdsize(source_packet) - RTP_FIXED_HEADER_SIZE)) fec_stream->max_size = msgdsize(source_packet) - RTP_FIXED_HEADER_SIZE;

    fec_stream->bitstring[0] ^= rtp_get_padbit(source_packet) << 5;
    fec_stream->bitstring[0] ^= rtp_get_extbit(source_packet) << 4;
    fec_stream->bitstring[0] ^= rtp_get_cc(source_packet);
    fec_stream->bitstring[1] ^= rtp_get_markbit(source_packet) << 7;
    fec_stream->bitstring[1] ^= rtp_get_payload_type(source_packet);

    //Length
    *(uint16_t *) &fec_stream->bitstring[2] ^= htons((uint16_t)(msgdsize(source_packet) - RTP_FIXED_HEADER_SIZE));

    //Timestamp
    *(uint32_t *) &fec_stream->bitstring[4] ^= rtp_get_timestamp(source_packet);

    //All octets after the fixed 12-bytes RTPheader
    for(size_t i = 0 ; i < (msgdsize(source_packet) - RTP_FIXED_HEADER_SIZE) ; i++){
        fec_stream->bitstring[8 + i] ^= *(uint8_t *) (source_packet->b_rptr+RTP_FIXED_HEADER_SIZE+i);
    }

    fec_stream->seqnumlist[fec_stream->cpt] = rtp_get_seqnumber(source_packet);

    fec_stream->cpt++;

    if(fec_stream->cpt == fec_stream->params.L){
        uint16_t *p16 = NULL;
        uint8_t *p8 = NULL;
        mblk_t *repair_packet = rtp_session_create_packet(fec_stream->fec_session, RTP_FIXED_HEADER_SIZE, NULL, 0);

        rtp_set_version(repair_packet, 2);
        rtp_set_padbit(repair_packet, 0);
        rtp_set_extbit(repair_packet, 0);
        rtp_set_markbit(repair_packet, 0);

        msgpullup(repair_packet, msgdsize(repair_packet) + 4 + 8 + fec_stream->params.L*4 + fec_stream->max_size);

        rtp_add_csrc(repair_packet, fec_stream->SSRC);
        repair_packet->b_wptr += sizeof(uint32_t);

        memcpy(repair_packet->b_wptr, &fec_stream->bitstring[0], 8*sizeof(uint8_t));
        repair_packet->b_wptr += 8*sizeof(uint8_t);

        for (int i = 0 ; i < fec_stream->params.L ; i++){
            p16 = (uint16_t *) (repair_packet->b_wptr);
            *p16 = fec_stream->seqnumlist[i];
            repair_packet->b_wptr += sizeof(uint16_t);
            p8 = repair_packet->b_wptr;
            *p8 = fec_stream->params.L;
            repair_packet->b_wptr++;
            p8 = repair_packet->b_wptr;
            *p8 = fec_stream->params.D;
            repair_packet->b_wptr++;
        }

        memcpy(repair_packet->b_wptr, &fec_stream->bitstring[8], fec_stream->max_size);
        repair_packet->b_wptr += fec_stream->max_size;

        fec_stream->cpt = 0;
        fec_stream->max_size = 0;

        ortp_message("Repair packet size before sending (SeqNum : %d) : %d", (int) rtp_get_seqnumber(repair_packet), (int) (msgdsize(repair_packet) - (RTP_FIXED_HEADER_SIZE + 12 + 4*(fec_stream->params.L))));

        rtp_session_sendm_with_ts(fec_stream->fec_session, repair_packet, rtp_get_timestamp(repair_packet));
    }
}

void fec_stream_on_new_source_packet_received(FecStream *fec_stream, mblk_t *source_packet){
    mblk_t *repair_packet = NULL;
    putq(&fec_stream->source_packets_recvd, dupmsg(source_packet));
    if(fec_stream->source_packets_recvd.q_mcount > fec_stream->params.source_queue_size){
        mblk_t *mp = qbegin(&fec_stream->source_packets_recvd);
        remq(&fec_stream->source_packets_recvd, mp);
        freemsg(mp);
    }
    repair_packet = rtp_session_recvm_with_ts(fec_stream->fec_session, rtp_get_timestamp(source_packet));
    if(repair_packet != NULL){
        putq(&fec_stream->repair_packets_recvd, dupmsg(repair_packet));
        if(fec_stream->repair_packets_recvd.q_mcount > fec_stream->params.repair_queue_size){
            mblk_t *rp = qbegin(&fec_stream->repair_packets_recvd);
            remq(&fec_stream->repair_packets_recvd, rp);
            freemsg(rp);
        }
    }
}

mblk_t *fec_stream_reconstruct_missing_packet(FecStream *fec_stream, uint16_t seqnum){
    mblk_t *packet = NULL;
    mblk_t *repair_packet = fec_stream_find_repair_packet(fec_stream, seqnum);
    if(repair_packet != NULL){
        bool_t find_all;
        queue_t packets_for_reconstruction;
        qinit(&packets_for_reconstruction);
        find_all = fec_stream_find_source_packets(fec_stream, repair_packet, &packets_for_reconstruction);
        if(find_all){
            packet = fec_stream_reconstruct_packet(fec_stream, &packets_for_reconstruction, repair_packet, seqnum);
        } else {
            fec_stream->source_packets_not_found++;
        }
        flushq(&packets_for_reconstruction, 0);
    } else {
        fec_stream->repair_packet_not_found++;
    }
    return packet;
}

mblk_t *fec_stream_reconstruct_packet(FecStream *fec_stream, queue_t *source_packets_set, mblk_t *repair_packet, uint16_t seqnum){
    mblk_t *packet = NULL;
    uint16_t packet_size;
    uint8_t *p = NULL;

    for(mblk_t *tmp = qbegin(source_packets_set) ; !qend(source_packets_set, tmp) ; tmp = qnext(source_packets_set, tmp)){
        ortp_message("Source packet for reconstruction (Seq Num : %d) : %d", rtp_get_seqnumber(tmp), (int) (msgdsize(tmp) - RTP_FIXED_HEADER_SIZE));
    }

    /* RTP HEADER RECONSTRUCTION */

    //Creation of the bitstring
    memset(fec_stream->header_bitstring, 0, 10);

    for(mblk_t *tmp = qbegin(source_packets_set) ; !qend(source_packets_set, tmp) ; tmp = qnext(source_packets_set, tmp)){
        for(size_t i = 0 ; i < 8 ; i++){
            fec_stream->header_bitstring[i] ^= *(uint8_t *) (tmp->b_rptr+i);
        }
        *(uint16_t *) &(fec_stream->header_bitstring[8]) ^= htons((uint16_t)(msgdsize(tmp) - RTP_FIXED_HEADER_SIZE));
    }

    //XOR with FEC header
    for(size_t j = 0 ; j < 2 ; j++){
        fec_stream->header_bitstring[j] ^= *(uint8_t *) (repair_packet->b_rptr+RTP_FIXED_HEADER_SIZE+sizeof(uint32_t)+j);
    }
    *(uint32_t *) &fec_stream->header_bitstring[4] ^= *(uint32_t *) (repair_packet->b_rptr+RTP_FIXED_HEADER_SIZE+sizeof(uint32_t)+4*sizeof(uint8_t));
    *(uint16_t *) &fec_stream->header_bitstring[8] ^= *(uint16_t *) (repair_packet->b_rptr+RTP_FIXED_HEADER_SIZE+sizeof(uint32_t)+2*sizeof(uint8_t));

    //Recreation of the lost packet
    packet = rtp_session_create_packet(fec_stream->source_session, RTP_FIXED_HEADER_SIZE, NULL, 0);

    rtp_set_version(packet, 2);
    rtp_set_padbit(packet, (fec_stream->header_bitstring[0] >> 5) & 0x1);
    rtp_set_extbit(packet, (fec_stream->header_bitstring[0] >> 4) & 0x1);
    rtp_set_cc(packet, fec_stream->header_bitstring[0] & 0xF);
    rtp_set_markbit(packet, (fec_stream->header_bitstring[1] >> 7) & 0x1);
    rtp_set_payload_type(packet, fec_stream->header_bitstring[1] & 0x7F);
    rtp_set_seqnumber(packet, seqnum);
    rtp_set_timestamp(packet, *(uint32_t *) &fec_stream->header_bitstring[4]);
    rtp_set_ssrc(packet, rtp_get_ssrc(qbegin(source_packets_set)));
    packet_size = ntohs(*(uint16_t *) &(fec_stream->header_bitstring[8]));

    /* PAYLOAD RECONSTRUCTION */

    memset(fec_stream->payload_bitstring, 0, packet_size);
    for(mblk_t *tmp = qbegin(source_packets_set) ; !qend(source_packets_set, tmp) ; tmp = qnext(source_packets_set, tmp)){
        for(size_t i = 0 ; i < MIN((msgdsize(tmp) - RTP_FIXED_HEADER_SIZE), (size_t) packet_size) ; i++){
            fec_stream->payload_bitstring[i] ^= *(uint8_t *) (tmp->b_rptr+RTP_FIXED_HEADER_SIZE+i);
        }
    }
    if((int)(msgdsize(repair_packet) - (RTP_FIXED_HEADER_SIZE + 12 + 4*(fec_stream->params.L))) < packet_size){
        ortp_message("Size of repair payload (Seq Num : %d) : %d | Size of source payload (Seq Num : %d) : %d", rtp_get_seqnumber(repair_packet), (int)(msgdsize(repair_packet) - (RTP_FIXED_HEADER_SIZE + 12 + 4*(fec_stream->params.L))), seqnum, packet_size);
        abort();
    }
    for(size_t i = 0 ; i < packet_size ; i++){
        fec_stream->payload_bitstring[i] ^= *(uint8_t *) (repair_packet->b_rptr + RTP_FIXED_HEADER_SIZE + 12 + 4*(fec_stream->params.L) + i); //Erreur potentielle : Buffer overflow - READ 1 byte
    }

    msgpullup(packet, msgdsize(packet) + packet_size);
    for(size_t i = 0 ; i < packet_size ; i++){
        p = (packet->b_wptr+i);
        *p = fec_stream->payload_bitstring[i];
    }
    packet->b_wptr += packet_size;

    return packet;
}

uint16_t *fec_stream_create_sequence_numbers_set(FecStream *fec_stream, mblk_t *repair_packet){
    uint16_t *seqnum = (uint16_t *) malloc(fec_stream->params.L * sizeof(uint16_t));
    int list_size = 0;
    bool_t seq_num_ok = TRUE;
    for(int i = 0 ; i < fec_stream->params.L ; i++){
        for(int j = 0 ; j < list_size ; j++){
            if(seqnum[j] == *(uint16_t *) (repair_packet->b_rptr + RTP_FIXED_HEADER_SIZE + 4 + 8 + 4*i)){
                seq_num_ok = FALSE;
            }
        }
        if(seq_num_ok){
            seqnum[i] = *(uint16_t *) (repair_packet->b_rptr + RTP_FIXED_HEADER_SIZE + 4 + 8 + 4*i);
            list_size++;
        }
        seq_num_ok = TRUE;
    }
    return seqnum;
}

mblk_t *fec_stream_find_repair_packet(FecStream *fec_stream, uint16_t seqnum){
    mblk_t *tmp = qbegin(&fec_stream->repair_packets_recvd);
    while(!qend(&fec_stream->repair_packets_recvd, tmp)){
        uint16_t *seqnum_list = fec_stream_create_sequence_numbers_set(fec_stream, tmp);
        for(int i = 0 ; i < fec_stream->params.L ; i++){
            if(seqnum_list[i] == seqnum){
                return tmp;
            }
        }
        tmp = qnext(&fec_stream->repair_packets_recvd, tmp);
    }
    return NULL;
}

bool_t fec_stream_find_source_packets(FecStream *fec_stream, mblk_t *repair_packet, queue_t *source_packets){
    uint16_t *seqnum_list = fec_stream_create_sequence_numbers_set(fec_stream, repair_packet);
    for(int i = 0 ; i < fec_stream->params.L ; i++){
        for(mblk_t *tmp = qbegin(&fec_stream->source_packets_recvd) ; !qend(&fec_stream->source_packets_recvd, tmp) ; tmp = qnext(&fec_stream->source_packets_recvd, tmp)){
            if(rtp_get_seqnumber(tmp) == seqnum_list[i]){
                putq(source_packets, dupmsg(tmp));
            }
        }
    }
    return (source_packets->q_mcount != fec_stream->params.L-1) ? FALSE : TRUE;
}

void fec_stream_reconstruction_error(FecStream *fec_stream, uint16_t seqnum){
    if(fec_stream->size_prec == 0){
        fec_stream->prec[0] = seqnum;
        fec_stream->size_prec++;
    } else if(((seqnum - fec_stream->prec[0]) < fec_stream->params.L) && (((fec_stream->prec[0]+1)%fec_stream->params.L) < ((seqnum+1)%fec_stream->params.L))){
        fec_stream->prec[fec_stream->size_prec] = seqnum;
        fec_stream->size_prec++;
    } else if(fec_stream->size_prec == 1){
        fec_stream->error++;
        fec_stream->prec[0] = seqnum;
    } else {
        fec_stream->size_prec = 1;
        fec_stream->prec[0] = seqnum;
    }
}
