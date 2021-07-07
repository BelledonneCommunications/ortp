/*
 * Copyright (c) 2010-2019 Belledonne Communications SARL.
 *
 * This file is part of oRTP.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <ortp/ortp.h>
#include <time.h>

int main(int argc, char *argv[]) {
	RtpSession *session;
	mblk_t *packet;
	size_t size;
	unsigned int i;
	char *test = "running test";
	char *foo = "foo";
	char *bar = "bar123";
	char *data;
	rtp_audio_level_t audio_levels[15] = {0};
	int audio_size, result;
	bool_t voice_activity;

	srand(time(NULL));

	ortp_init();
	ortp_scheduler_init();
	ortp_set_log_level_mask(NULL, ORTP_MESSAGE|ORTP_WARNING|ORTP_ERROR);
	session = rtp_session_new(RTP_SESSION_SENDONLY);

	// Multiple test of extension into a packet
	for (i = 0; i < 1000; i++) {
		uint16_t extbit;
		char *tmp;
		unsigned int random = (rand() % 3) + 1;
		unsigned int expected_size;

		packet = rtp_session_create_packet(session, RTP_FIXED_HEADER_SIZE, NULL, 0);

		if (random == 1) tmp = test;
		else if (random == 2) tmp = foo;
		else tmp = bar;

		rtp_add_extension_header(packet, 10, strlen(tmp), tmp);

		extbit = rtp_get_extbit(packet);
		if (extbit != 1) {
			ortp_error("extbit has not been set correctly (%d)!", i);
		}

		size = rtp_get_extheader(packet, NULL, NULL);

		expected_size = (strlen(tmp) + 1); // extension + 1-byte header + potential padding
		if (expected_size % 4 != 0) {
			expected_size = expected_size + (4 - expected_size % 4);
		}

		if (size != expected_size) {
			ortp_error("Size of extension header is wrong at %d with size %d instead of %d", i, size, expected_size);
		}

		freemsg(packet);
	}

	// Test multiple extension into the same packet
	packet = rtp_session_create_packet(session, RTP_FIXED_HEADER_SIZE, NULL, 0);

	for (i = 0; i < 10; i++) {
		switch((rand() % 3) + 1) {
			case 1:
				rtp_add_extension_header(packet, i + 1, strlen(test), test);
				break;
			case 2:
				rtp_add_extension_header(packet, i + 1, strlen(foo), foo);
				break;
			default:
				rtp_add_extension_header(packet, i + 1, strlen(bar), bar);
				break;
		}

		size = rtp_get_extheader(packet, NULL, NULL);
		if (size != (size_t)-1) {
			ortp_message("Size of extension header at %d is %d", (i + 1), size);
		}
	}

	for (i = 0; i < 10; i++) {
		size = rtp_get_extension_header(packet, i + 1, &data);
		if (size != (size_t)-1) {
			char *cpy = strndup(data, size);
			ortp_message("Data for id = %d is \"%s\" of size %d", (i + 1), cpy, size);
			free(cpy);
		}
	}

	freemsg(packet);

	// Test client to mixer audio level api
	packet = rtp_session_create_packet(session, RTP_FIXED_HEADER_SIZE, NULL, 0);

	rtp_add_client_to_mixer_audio_level(packet, 2, TRUE, -64);
	result = rtp_get_client_to_mixer_audio_level(packet, 2, &voice_activity);
	if (result != -64) {
		ortp_error("Client to mixer wrong value! %d", result);
	} else {
		ortp_message("Audio level for -64 with voice activity, value returned: %d, voice activity: %d", result, voice_activity ? 1 : 0);
	}

	freemsg(packet);

	// Test mixer to client audio level api
	packet = rtp_session_create_packet(session, RTP_FIXED_HEADER_SIZE, NULL, 0);
	rtp_audio_level_t values[5] = {{1, -127}, {2, -115}, {0, -53}, {4, -28}, {5, 0}};

	rtp_add_mixer_to_client_audio_level(packet, 2, 5, values);
	audio_size = rtp_get_mixer_to_client_audio_level(packet, 2, audio_levels);

	ortp_message("Audio levels' expected values: [1, -127], [2, -115], [0, -53], [4, -28], [5, 0]");
	ortp_message("Results (%d):", audio_size);
	if (audio_size != -1) {
		for (i = 0; i < audio_size; i++) {
			ortp_message("\tcsrc: %d, level: %d", audio_levels[i].csrc, audio_levels[i].dbov);
		}
	} else {
		ortp_error("Mixer to client has no values!");
	}

	freemsg(packet);

	rtp_session_destroy(session);
	ortp_exit();

	return 0;
}
