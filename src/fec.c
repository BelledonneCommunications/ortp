#include "ortp/ortp.h"
#include "ortp/str_utils.h"
#include "ortp/rtp.h"
#include <arpa/inet.h>

mblk_t *fec_create_repair_packet(queue_t *source_packets, RtpSession* session){

    /* BITSTRING CREATION */
    mblk_t *tmp = NULL;
    size_t maxsize = 0;
    for(tmp= qbegin(source_packets) ; !qend(source_packets, tmp) ; tmp = qnext(source_packets, tmp)){
        if(msgdsize(tmp) > maxsize){
            maxsize = msgdsize(tmp);
        }
    }
    uint8_t *bitstring = ortp_new0(uint8_t, 2 + 2 + 4 + (maxsize - RTP_FIXED_HEADER_SIZE));
    bitstring[0] = 1 << 6;

    mblk_t *current_packet = qbegin(source_packets);

    uint32_t SSRC = rtp_get_ssrc(current_packet);

    while(!qend(source_packets, current_packet)){

        bitstring[0] ^= rtp_get_padbit(current_packet) << 5;
        bitstring[0] ^= rtp_get_extbit(current_packet) << 4;
        bitstring[0] ^= rtp_get_cc(current_packet);
        bitstring[1] ^= rtp_get_markbit(current_packet) << 7;
        bitstring[1] ^= rtp_get_payload_type(current_packet);

        //Length
        *(uint16_t *) &bitstring[2] ^= htons(msgdsize(current_packet) - RTP_FIXED_HEADER_SIZE);

        //Timestamp
        *(uint32_t *) &bitstring[4] ^= htonl(rtp_get_timestamp(current_packet));

        //All octets after the fixed 12-bytes RTPheader
        for(size_t i = 0 ; i < msgdsize(current_packet) - RTP_FIXED_HEADER_SIZE ; i++){
            bitstring[8 + i] ^= *(uint8_t *) current_packet->b_rptr+RTP_FIXED_HEADER_SIZE+i;
        }

        current_packet = qnext(source_packets, current_packet); //next source packet
    }

    /*  REPAIR PACKET BUILDING */
    mblk_t *repair_packet = rtp_session_create_packet(session, RTP_FIXED_HEADER_SIZE, NULL, 0);

    //RTP header init of the repair packet
    rtp_set_version(repair_packet, 2);
    rtp_set_padbit(repair_packet, 0);
    rtp_set_extbit(repair_packet, 0);
    rtp_set_markbit(repair_packet, 0);

    msgpullup(repair_packet, msgdsize(repair_packet) + 8 * sizeof (uint8_t) + (source_packets->q_mcount + 1) * sizeof(uint32_t) + maxsize - RTP_FIXED_HEADER_SIZE);

    //Add SSRC of source packets in CSRC fields
    rtp_add_csrc(repair_packet, SSRC);
    repair_packet->b_wptr += sizeof(uint32_t);

    //Add FEC header
    memcpy(repair_packet->b_wptr, &bitstring[0], 8);
    repair_packet->b_wptr += 8*sizeof(uint8_t);

    //Add sequence numbers, L and D
    uint16_t *p16;
    uint8_t *p8;
    for (tmp = qbegin(source_packets); !qend(source_packets, tmp); tmp = qnext(source_packets, tmp)){
        p16 = (uint16_t *)repair_packet->b_wptr;
        *p16 = rtp_get_seqnumber(tmp);
        repair_packet->b_wptr += sizeof(uint16_t);
        p8 = repair_packet->b_wptr;
        *p8 = 1;
        repair_packet->b_wptr++;
        p8 = repair_packet->b_wptr;
        *p8 = 0;
        repair_packet->b_wptr++;
    }

    //Add all octets after the fixed 12-bytes RTPheader
    memcpy(repair_packet->b_wptr, &bitstring[8], maxsize - RTP_FIXED_HEADER_SIZE);
    repair_packet->b_wptr += (maxsize - RTP_FIXED_HEADER_SIZE);

    return repair_packet;
}

mblk_t *source_packet_reconstruction(queue_t *source_packets, mblk_t *repair_packet, RtpSession *session, uint16_t seqnum){

    //Max size of source packets
    size_t maxsize = 0;
    for(mblk_t *p= qbegin(source_packets) ; !qend(source_packets, p) ; p = qnext(source_packets, p)){
        if(msgdsize(p) - RTP_FIXED_HEADER_SIZE > maxsize){
            maxsize = msgdsize(p) - RTP_FIXED_HEADER_SIZE;
        }
    }

    /* RTP HEADER RECONSTRUCTION */

    //Creation of the bitstring
    uint8_t *bitstring = ortp_new0(uint8_t, 10);
    for(mblk_t *tmp = qbegin(source_packets) ; !qend(source_packets, tmp) ; tmp = qnext(source_packets, tmp)){
        for(size_t i = 0 ; i < 8 ; i++){
            bitstring[i] ^= *(uint8_t *) tmp->b_rptr+i;
            *(uint16_t *) &bitstring[8] ^= htons(msgdsize(tmp) - RTP_FIXED_HEADER_SIZE);
        }
    }

    //XOR with FEC header
    for(size_t j = 0 ; j < 10 ; j++){
        bitstring[j] ^= *(uint8_t *) repair_packet->b_rptr+RTP_FIXED_HEADER_SIZE+j;
    }

    //Recreation of the lost packet
    mblk_t *packet = rtp_session_create_packet(session, RTP_FIXED_HEADER_SIZE, NULL, 0);

    rtp_set_version(packet, 2);
    rtp_set_padbit(packet, (bitstring[0] >> 5) & 1);
    rtp_set_extbit(packet, (bitstring[0] >> 4) & 1);
    rtp_set_cc(packet, bitstring[0] & 0xF);
    rtp_set_markbit(packet, (bitstring[1] >> 7) & 1);
    rtp_set_payload_type(packet, bitstring[1] & 0x7F);
    rtp_set_seqnumber(packet, seqnum);
    uint16_t packet_size = *(uint16_t *) &bitstring[2];
    rtp_set_timestamp(packet, *(uint32_t *) &bitstring[4]);
    rtp_set_ssrc(packet, rtp_get_ssrc(qbegin(source_packets)));

    /* PAYLOAD RECONSTRUCTION */

    uint8_t *payload_bitstring = ortp_new0(uint8_t, packet_size);
    msgpullup(packet, msgdsize(packet) + packet_size);
    for(mblk_t *tmp = qbegin(source_packets) ; !qend(source_packets, tmp) ; tmp = qnext(source_packets, tmp)){
        for(size_t i = 0 ; i < (msgdsize(tmp) - RTP_FIXED_HEADER_SIZE) ; i++){
            payload_bitstring[i] ^= *(uint8_t *) tmp->b_rptr+RTP_FIXED_HEADER_SIZE+i;
            payload_bitstring[i] ^= *(uint8_t *) repair_packet->b_rptr + RTP_FIXED_HEADER_SIZE + 8 + 4*(source_packets->q_mcount+1) + i;
        }
    }

    uint8_t *p;
    for(size_t i = 0 ; i < packet_size ; i++){
        p = packet->b_wptr+i;
        *p = payload_bitstring[i];
    }
    packet->b_wptr += packet_size;

    return packet;
}
