#include "ortp/rtpsession.h"
#include "ortp/port.h"
#include <time.h>

FecParameters *fec_params_new_test(int L, int D, int size_of_source_queue){
    FecParameters *fec_params = (FecParameters *) malloc(sizeof(FecParameters));
    fec_params->L = L;
    fec_params->D = D;
    fec_params->source_queue_size = (10-L+5)*10;
    fec_params->repair_queue_size = L+5;
    return fec_params;
}

FecStream *fec_stream_new_test(struct _RtpSession *source, struct _RtpSession *fec, const FecParameters *params){
    FecStream *fec_stream = (FecStream *) malloc(sizeof (FecStream));
    fec_stream->source_session = source;
    fec_stream->fec_session = fec;
    rtp_session_enable_jitter_buffer(fec_stream->fec_session, FALSE);
    fec_stream->cpt = 0;
    qinit(&fec_stream->source_packets_recvd);
    qinit(&fec_stream->repair_packets_recvd);
    fec_stream->params = *params;
    fec_stream->seqnumlist = (uint16_t *) malloc(fec_stream->params.L*sizeof (uint16_t));
    return fec_stream;
}

void fec_stream_destroy_test(FecStream *fec_stream){
    ortp_free(fec_stream->bitstring);
    ortp_free(fec_stream->seqnumlist);
    ortp_free(&fec_stream->source_packets_recvd);
    ortp_free(&fec_stream->repair_packets_recvd);
    ortp_free(&fec_stream->params);
}

mblk_t *fec_stream_on_new_source_packet_sent_test(FecStream *fec_stream, mblk_t *source_packet){
    msgpullup(source_packet, -1);

    if(fec_stream->cpt == 0){
        fec_stream->SSRC = rtp_get_ssrc(source_packet);
        fec_stream->bitstring = ortp_new0(uint8_t, UDP_MAX_SIZE);
        fec_stream->bitstring[0] = 1 << 6;
    }

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
    for(size_t i = 0 ; i < msgdsize(source_packet) - RTP_FIXED_HEADER_SIZE ; i++){
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

        msgpullup(repair_packet, msgdsize(repair_packet) + 4 + 8 + fec_stream->params.L*4 + UDP_MAX_SIZE - 8);

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

        memcpy(repair_packet->b_wptr, &fec_stream->bitstring[8], UDP_MAX_SIZE - 8);
        repair_packet->b_wptr += UDP_MAX_SIZE - 8;

        ortp_free(fec_stream->bitstring);
        fec_stream->cpt = 0;

        return repair_packet;
    }
    return NULL;
}

uint16_t *fec_stream_create_sequence_numbers_set_test(FecStream *fec_stream, mblk_t *repair_packet){
    uint16_t *seqnum = (uint16_t *) malloc(fec_stream->params.L * sizeof(uint16_t));
    for(int i = 0 ; i < fec_stream->params.L  ; i++){
        seqnum[i] = *(uint16_t *) (repair_packet->b_rptr + RTP_FIXED_HEADER_SIZE + 4 + 8 + 4*i);
    }
    return seqnum;
}

mblk_t *fec_stream_find_repair_packet_test(FecStream *fec_stream, uint16_t seqnum){
    mblk_t *tmp = qbegin(&fec_stream->repair_packets_recvd);
    while(!qend(&fec_stream->repair_packets_recvd, tmp)){
        uint16_t *seqnum_list = fec_stream_create_sequence_numbers_set_test(fec_stream, tmp);
        for(int i = 0 ; i < fec_stream->params.L ; i++){
            if(seqnum_list[i] == seqnum){
                return tmp;
            }
        }
        tmp = qnext(&fec_stream->repair_packets_recvd, tmp);
    }
    return NULL;
}

bool_t fec_stream_find_source_packets_test(FecStream *fec_stream, mblk_t *repair_packet, queue_t *source_packets){
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

size_t min_test(size_t a, size_t b){
    return (a<b ? a : b);
}

mblk_t *fec_stream_reconstruct_packet_test(FecStream *fec_stream, queue_t *source_packets_set, mblk_t *repair_packet, uint16_t seqnum){
    uint8_t *bitstring = ortp_new0(uint8_t, 10);
    mblk_t *packet = NULL;
    uint16_t packet_size;
    uint8_t *payload_bitstring = NULL;
    uint8_t *p = NULL;

    /* RTP HEADER RECONSTRUCTION */

    //Creation of the bitstring
    for(mblk_t *tmp = qbegin(source_packets_set) ; !qend(source_packets_set, tmp) ; tmp = qnext(source_packets_set, tmp)){
        for(size_t i = 0 ; i < 8 ; i++){
            bitstring[i] ^= *(uint8_t *) (tmp->b_rptr+i);
        }
        *(uint16_t *) &(bitstring[8]) ^= htons((uint16_t)(msgdsize(tmp) - RTP_FIXED_HEADER_SIZE));
    }

    //XOR with FEC header
    for(size_t j = 0 ; j < 2 ; j++){
        bitstring[j] ^= *(uint8_t *) (repair_packet->b_rptr+12+sizeof(uint32_t)+j);
    }
    *(uint32_t *) &bitstring[4] ^= *(uint32_t *) (repair_packet->b_rptr+RTP_FIXED_HEADER_SIZE+sizeof(uint32_t)+4*sizeof(uint8_t));
    *(uint16_t *) &bitstring[8] ^= *(uint16_t *) (repair_packet->b_rptr+RTP_FIXED_HEADER_SIZE+sizeof(uint32_t)+2*sizeof(uint8_t));

    //Recreation of the lost packet
    packet = rtp_session_create_packet(fec_stream->source_session, RTP_FIXED_HEADER_SIZE, NULL, 0);

    rtp_set_version(packet, 2);
    rtp_set_padbit(packet, (bitstring[0] >> 5) & 0x1);
    rtp_set_extbit(packet, (bitstring[0] >> 4) & 0x1);
    rtp_set_cc(packet, bitstring[0] & 0xF);
    rtp_set_markbit(packet, (bitstring[1] >> 7) & 0x1);
    rtp_set_payload_type(packet, bitstring[1] & 0x7F);
    rtp_set_seqnumber(packet, seqnum);
    rtp_set_timestamp(packet, *(uint32_t *) &bitstring[4]);
    rtp_set_ssrc(packet, rtp_get_ssrc(qbegin(source_packets_set)));
    packet_size = ntohs(*(uint16_t *) &(bitstring[8]));

    /* PAYLOAD RECONSTRUCTION */

    payload_bitstring = ortp_new0(uint8_t, packet_size);
    for(mblk_t *tmp = qbegin(source_packets_set) ; !qend(source_packets_set, tmp) ; tmp = qnext(source_packets_set, tmp)){
        for(size_t i = 0 ; i < min_test((msgdsize(tmp) - RTP_FIXED_HEADER_SIZE), (size_t) packet_size) ; i++){
            payload_bitstring[i] ^= *(uint8_t *) (tmp->b_rptr+RTP_FIXED_HEADER_SIZE+i);
        }
    }
    for(size_t i = 0 ; i < packet_size ; i++){
        payload_bitstring[i] ^= *(uint8_t *) (repair_packet->b_rptr + RTP_FIXED_HEADER_SIZE + 12 + 4*(fec_stream->params.L) + i);
    }

    msgpullup(packet, msgdsize(packet) + packet_size);
    for(size_t i = 0 ; i < packet_size ; i++){
        p = (packet->b_wptr+i);
        *p = payload_bitstring[i];
    }
    packet->b_wptr += packet_size;

    return packet;
}

mblk_t *fec_stream_reconstruct_missing_packet_test(FecStream *fec_stream, uint16_t seqnum){
    mblk_t *packet = NULL;
    mblk_t *repair_packet = fec_stream_find_repair_packet_test(fec_stream, seqnum);
    if(repair_packet != NULL){
        bool_t find_all;
        queue_t packets_for_reconstruction;
        qinit(&packets_for_reconstruction);
        find_all = fec_stream_find_source_packets_test(fec_stream, repair_packet, &packets_for_reconstruction);
        if(find_all){
            packet = fec_stream_reconstruct_packet_test(fec_stream, &packets_for_reconstruction, repair_packet, seqnum);
            printf("Paquet source reconstruit\n");
        }
        flushq(&packets_for_reconstruction, 0);
    }
    return packet;
}

int main(int argc, char** argv){
    int L = 4;

    uint8_t *buffer = NULL;
    mblk_t *packet = NULL;
    mblk_t *repair = NULL;
    RtpSession *source_session = rtp_session_new(RTP_SESSION_SENDONLY);
    RtpSession *repair_session = rtp_session_new(RTP_SESSION_SENDONLY);
    const FecParameters *params = fec_params_new_test(L, 0, 10*L);

    FecStream *fec_stream = fec_stream_new_test(source_session, repair_session, params);

    uint16_t num = 0;

    srand(time(NULL));
    int size = 0;

    for(int i = 0 ; i < 100 ; i++){
        size = rand()%1400;
        buffer = (uint8_t *) malloc(size*sizeof(uint8_t));
        for(int i = 0 ; i < size ; i++){
            buffer[i] = rand()%256;
        }
        packet = rtp_session_create_packet(source_session, RTP_FIXED_HEADER_SIZE, buffer, size);
        rtp_set_seqnumber(packet, num);
        rtp_set_timestamp(packet, rand()%429496729);
        num++;
        putq(&fec_stream->source_packets_recvd, packet);
        repair = fec_stream_on_new_source_packet_sent_test(fec_stream, packet);
        if(repair != NULL){
            putq(&fec_stream->repair_packets_recvd, repair);
        }
        free(buffer);
    }

    mblk_t *lost_packet = NULL;
    int position = 0;
    for(mblk_t *tmp = qbegin(&fec_stream->source_packets_recvd) ; !qend(&fec_stream->source_packets_recvd, tmp) ; tmp = qnext(&fec_stream->source_packets_recvd, tmp)){
        if(position == 2){
            lost_packet = tmp;
            remq(&fec_stream->source_packets_recvd, lost_packet);
            break;
        } position++;
    }

    //mblk_t *lost_packet = getq(&fec_stream->source_packets_recvd);
    //remq(&fec_stream->source_packets_recvd, lost_packet);

    mblk_t *new_packet = fec_stream_reconstruct_missing_packet_test(fec_stream, rtp_get_seqnumber(lost_packet));

    if(new_packet == NULL){
        printf("Lost packet reconstruction : NULL\n");
    } else if(msgdsize(lost_packet) == msgdsize(new_packet)){
        if(memcmp(lost_packet->b_rptr, new_packet->b_rptr, msgdsize(lost_packet)) == 0){
            printf("Lost packet reconstruction : OK\n");
        } else {
            printf("Lost packet reconstruction : FAIL\n");
            for(int i = 0 ; i < min_test(msgdsize(lost_packet), (size_t) 100) ; i++){
                if(*(uint8_t *)(lost_packet->b_rptr+i) != *(uint8_t *)(new_packet->b_rptr+i)){
                    printf("Header lost packet [%d] = %d\n", i, *(uint8_t *)(lost_packet->b_rptr+i));
                    printf("Header new  packet [%d] = %d\n", i, *(uint8_t *)(new_packet->b_rptr+i));
                }
            }
        }
    } else {
        printf("Tailles différentes\n");
        printf("Taille packet d'origine : %d / Taille packet reconstruit : %d\n", (int)msgdsize(lost_packet), (int)msgdsize(new_packet));
        for(int i = 0 ; i < 12 ; i++){
            printf("Header lost packet [%d] = %d\n", i, *(uint8_t *)(lost_packet->b_rptr+i));
            printf("Header new  packet [%d] = %d\n", i, *(uint8_t *)(new_packet->b_rptr+i));
        }
    }

    return 0;
}
