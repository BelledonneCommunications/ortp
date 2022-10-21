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

#include <ortp/ortp.h>
#include <signal.h>
#include <stdlib.h>

#ifndef _WIN32
#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#endif

int runcond=1;

void stophandler(int signum)
{
	runcond=0;
}

static const char *help = "Usage: rtptransfer <filename>\n";

int main(int argc, char *argv[]) {
	RtpSession *session;
	RtpSession *transfer_session;
	int rtp_port, rtcp_port;
	FILE *infile;
	unsigned char buffer[160];
	uint32_t user_ts = 0;
	int len = 0;
	bool_t error = FALSE;

	if (argc < 2) {
		printf("%s", help);
		return -1;
	}

#ifndef _WIN32
	infile = fopen(argv[1], "r");
#else
	infile = fopen(argv[1], "rb");
#endif

	if (infile == NULL) {
		perror("Cannot open file");
		return -1;
	}

	ortp_init();
	ortp_scheduler_init();
	ortp_set_log_level_mask(NULL, ORTP_MESSAGE|ORTP_WARNING|ORTP_ERROR);

	// Create the default session
	session = rtp_session_new(RTP_SESSION_SENDRECV);

	rtp_session_set_scheduling_mode(session, 1);
	rtp_session_set_blocking_mode(session, 1);
	rtp_session_set_connected_mode(session, TRUE);
	rtp_session_set_local_addr(session, "127.0.0.1", -1, -1);
	rtp_session_set_payload_type(session, 0);
	rtp_session_enable_jitter_buffer(session, FALSE);

	// Create the session that will be used to transfer the packets
	transfer_session = rtp_session_new(RTP_SESSION_SENDRECV);

	rtp_session_set_scheduling_mode(transfer_session, 1);
	rtp_session_set_blocking_mode(transfer_session, 1);
	rtp_session_set_connected_mode(transfer_session, TRUE);
	rtp_session_set_local_addr(transfer_session, "127.0.0.1", -1, -1);
	rtp_session_enable_transfer_mode(transfer_session, TRUE);

	// Connect the two sessions
	rtp_port = rtp_session_get_local_port(transfer_session);
	rtcp_port = rtp_session_get_local_rtcp_port(transfer_session);
	rtp_session_set_remote_addr_full(session, "127.0.0.1", rtp_port, "127.0.0.1", rtcp_port);

	rtp_port = rtp_session_get_local_port(session);
	rtcp_port = rtp_session_get_local_rtcp_port(session);
	rtp_session_set_remote_addr_full(transfer_session, "127.0.0.1", rtp_port, "127.0.0.1", rtcp_port);

	signal(SIGINT, stophandler);
	while(((len = fread(buffer, 1, 160, infile)) > 0) && (!error) && (runcond)) {
		// Send a packet through the "normal" session and retrieve it with the transfer session
		mblk_t *sent_packet = rtp_session_create_packet(session, RTP_FIXED_HEADER_SIZE, (uint8_t *)buffer, len);

		int size = rtp_session_sendm_with_ts(session, copymsg(sent_packet), user_ts);
		if (size < 0) {
			ortp_error("Session [%p] could not send the packet (%d)", session, size);
			error = TRUE;
		}

		mblk_t *transfered_packet = rtp_session_recvm_with_ts(transfer_session, user_ts);
		if (transfered_packet == NULL) {
			ortp_error("Transfer session [%p] did not received any packets!", transfer_session);
			error = TRUE;
		} else {
			bool_t same = FALSE;

			// We cannot compare bytes by bytes here as sent_packet has been modified by rtp_session_sendm_with_ts before sending
			// So we check the parts that this function didn't change which is everything but timestamp
			if (rtp_get_version(transfered_packet) == rtp_get_version(sent_packet)
				&& rtp_get_padbit(transfered_packet) == rtp_get_padbit(sent_packet)
				&& rtp_get_markbit(transfered_packet) == rtp_get_markbit(sent_packet)
				&& rtp_get_extbit(transfered_packet) == rtp_get_extbit(sent_packet)
				&& rtp_get_seqnumber(transfered_packet) == rtp_get_seqnumber(sent_packet)
				&& rtp_get_payload_type(transfered_packet) == rtp_get_payload_type(sent_packet)
				&& rtp_get_ssrc(transfered_packet) == rtp_get_ssrc(sent_packet)
				&& rtp_get_cc(transfered_packet) == rtp_get_cc(sent_packet)
				&& memcmp(transfered_packet->b_rptr + RTP_FIXED_HEADER_SIZE, sent_packet->b_rptr + RTP_FIXED_HEADER_SIZE, msgdsize(transfered_packet) - RTP_FIXED_HEADER_SIZE) == 0
			) {
				same = TRUE;
			}

			if (!same) {
				ortp_error("Packet received by the transfer session is not the same!");
				freemsg(transfered_packet);
				error = TRUE;
			} else {
				// Send it again via the transfer session and retrieve it with the "normal" session
				rtp_session_sendm_with_ts(transfer_session, copymsg(transfered_packet), user_ts);

				mblk_t *received_packet = rtp_session_recvm_with_ts(session, user_ts);
				if (received_packet == NULL) {
					ortp_error("Session [%p] did not receive the transfered packet!", session);
					error = TRUE;
				} else {
					// Check that the packet received is the same as the transfered one as the "transfer" session shouldn't modify it's content
					int ret = memcmp(received_packet->b_rptr, transfered_packet->b_rptr, msgdsize(received_packet));

					if (ret != 0) {
						ortp_error("Packet received by the session is not the same!");
						error = TRUE;
					}

					freemsg(received_packet);
				}
			}

			freemsg(transfered_packet);
		}

		freemsg(sent_packet);

		user_ts += 160;
	}

	if (!error) {
		ortp_message("Test completed successfully.");
	}

	fclose(infile);
	rtp_session_destroy(session);
	rtp_session_destroy(transfer_session);
	ortp_exit();

	return 0;
}
