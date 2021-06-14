#include "ortp/rtpsession.h"

int main(int argc, char** argv){

    uint8_t *buffer = (uint8_t *) malloc(2*sizeof(uint8_t));
    mblk_t *packet;
    queue_t source_packets;
    qinit(&source_packets);
    RtpSession *source_session = rtp_session_new(RTP_SESSION_SENDONLY);
    RtpSession *repair_session = rtp_session_new(RTP_SESSION_SENDONLY);
    for(int i = 0 ; i < 12 ; i++){
        buffer[0] = i;
        buffer[1] = i;
        packet = rtp_session_create_packet(source_session, RTP_FIXED_HEADER_SIZE, buffer, 2);
        putq(&source_packets, packet);
    }
    mblk_t *repair_packet = fec_create_repair_packet(&source_packets, repair_session);

    mblk_t *lost_packet = qbegin(&source_packets);

    remq(&source_packets, lost_packet);

    mblk_t *new_packet = source_packet_reconstruction(&source_packets, repair_packet, source_session, rtp_get_seqnumber(lost_packet));

    if(memcmp(lost_packet, new_packet, msgdsize(lost_packet)) == 0){
        printf("Lost packet reconstruction : OK\n");
    } else {
        printf("Lost packet reconstruction : FAIL\n");
    }

    return 0;
}
