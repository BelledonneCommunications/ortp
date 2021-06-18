#include "ortp/rtpsession.h"
#include "ortp/fecstream.h"

int main(int argc, char** argv){

    int A = 5;
    int B = 8;
    int L = A + B;

    uint8_t *buffer = (uint8_t *) malloc(2*sizeof(uint8_t));
    uint8_t *buffer2 = (uint8_t *) malloc(3*sizeof(uint8_t));
    mblk_t *packet;
    queue_t source_packets;
    qinit(&source_packets);
    RtpSession *source_session = rtp_session_new(RTP_SESSION_SENDONLY);
    RtpSession *repair_session = rtp_session_new(RTP_SESSION_SENDONLY);

    for(int i = 0 ; i < A ; i++){
        buffer[0] = i+5;
        buffer[1] = i+5;
        packet = rtp_session_create_packet(source_session, RTP_FIXED_HEADER_SIZE, buffer, 2);
        putq(&source_packets, packet);
    }
    for(int i = 0 ; i < B ; i++){
        buffer2[0] = i+7;
        buffer2[1] = i+8;
        buffer2[2] = i+9;
        packet = rtp_session_create_packet(source_session, RTP_FIXED_HEADER_SIZE, buffer2, 3);
        putq(&source_packets, packet);
    }
    mblk_t *repair_packet = fec_stream_create_repair_packet(&source_packets, repair_session);

    uint16_t *seqnum = fec_create_sequence_numbers_set(repair_packet, L);
    for(int i = 0 ; i < L ; i++){
        printf("Seqnum %d : %u\n", i, seqnum[i]);
    }

    mblk_t *lost_packet = qlast(&source_packets);

    remq(&source_packets, lost_packet);

    mblk_t *new_packet = fec_stream_reconstruct_packet(&source_packets, repair_packet, source_session, rtp_get_seqnumber(lost_packet));

    if(memcmp(lost_packet, new_packet, msgdsize(lost_packet)) == 0){
        printf("Lost packet reconstruction : OK\n");
    } else {
        printf("Lost packet reconstruction : FAIL\n");
    }

    return 0;
}
