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

	rtp_session_destroy(session);
	ortp_exit();

	return 0;
}
