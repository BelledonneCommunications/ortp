#include "ortp/rtpsession.h"
#include "ortp/fecstream.h"

int main(int argc, char** argv){
    int A = 5;
    int B = 8;
    int L = A + B;

    uint8_t *buffer = (uint8_t *) malloc(2*sizeof(uint8_t));
    uint8_t *buffer2 = (uint8_t *) malloc(3*sizeof(uint8_t));
    mblk_t *packet;
    RtpSession *source_session = rtp_session_new(RTP_SESSION_SENDONLY);
    RtpSession *repair_session = rtp_session_new(RTP_SESSION_SENDONLY);
    const FecParameters *params = fec_params_new(L, 0, 10*L);

    FecStream *fec_stream = fec_stream_new(source_session, repair_session, params);

    uint16_t num = 0;

    for(int i = 0 ; i < A ; i++){
        buffer[0] = i+5;
        buffer[1] = i+5;
        packet = rtp_session_create_packet(source_session, RTP_FIXED_HEADER_SIZE, buffer, 2);
        rtp_set_seqnumber(packet, num);
        num++;
        putq(&fec_stream->source_packets_recvd, packet);
        fec_stream_on_new_source_packet_sent(fec_stream, packet);
    }
    for(int i = 0 ; i < B ; i++){
        buffer2[0] = i+7;
        buffer2[1] = i+8;
        buffer2[2] = i+9;
        packet = rtp_session_create_packet(source_session, RTP_FIXED_HEADER_SIZE, buffer2, 3);
        rtp_set_seqnumber(packet, num);
        num++;
        putq(&fec_stream->source_packets_recvd, packet);
        fec_stream_on_new_source_packet_sent(fec_stream, packet);
    }

    mblk_t *lost_packet = qlast(&fec_stream->source_packets_recvd);
    remq(&fec_stream->source_packets_recvd, lost_packet);

    mblk_t *new_packet = fec_stream_reconstruct_missing_packet(fec_stream, rtp_get_seqnumber(lost_packet));

    if(new_packet == NULL){
        printf("Lost packet reconstruction : NULL\n");
    } else if(memcmp(lost_packet, new_packet, msgdsize(lost_packet)) == 0){
        printf("Lost packet reconstruction : OK\n");
    } else {
        printf("Lost packet reconstruction : FAIL\n");
    }

    return 0;
}
