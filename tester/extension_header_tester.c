/*
 * Copyright (c) 2010-2022 Belledonne Communications SARL.
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

#include "ortp_tester.h"
#include <ortp/ortp.h>

static RtpSession *session = NULL;

static int tester_before_all(void) {
	ortp_init();
	ortp_scheduler_init();

	session = rtp_session_new(RTP_SESSION_SENDONLY);

	return 0;
}

static int tester_after_all(void) {
	rtp_session_destroy(session);
	session = NULL;

	ortp_exit();

	return 0;
}

static void insert_extension_header_into_packet(void) {
	uint16_t extbit;
	size_t size, expected_size;
	char *test = "Running test";

	mblk_t *packet = rtp_session_create_packet(session, RTP_FIXED_HEADER_SIZE, NULL, 0);

	rtp_add_extension_header(packet, 10, strlen(test), (uint8_t *) test);

	extbit = rtp_get_extbit(packet);
	BC_ASSERT_EQUAL(extbit, 1, uint16_t, "%d");

	size = rtp_get_extheader(packet, NULL, NULL);

	expected_size = (strlen(test) + 1); // extension + 1-byte header + potential padding
	if (expected_size % 4 != 0) {
		expected_size = expected_size + (4 - expected_size % 4);
	}

	BC_ASSERT_EQUAL(size, expected_size, size_t, "%zu");

	freemsg(packet);
}

static void insert_multiple_extension_headers_into_packet(void) {
	size_t size;
	char *test = "Running test";
	char *test2 = "foo";
	char *test3 = "C'est pas faux";
	uint8_t *data;
	char *copy;

	mblk_t *packet = rtp_session_create_packet(session, RTP_FIXED_HEADER_SIZE, NULL, 0);

	rtp_add_extension_header(packet, 1, strlen(test), (uint8_t *) test);
	rtp_add_extension_header(packet, 2, strlen(test2), (uint8_t *) test2);
	rtp_add_extension_header(packet, 3, strlen(test3), (uint8_t *) test3);

	size = rtp_get_extheader(packet, NULL, NULL);
	BC_ASSERT_GREATER(size, 0, size_t, "%zu");

	size = rtp_get_extension_header(packet, 1, &data);
	BC_ASSERT_EQUAL(size, strlen(test), size_t, "%zu");

	copy = ortp_strndup((char *) data, (int) size);
	BC_ASSERT_STRING_EQUAL(copy, test);
	free(copy);

	size = rtp_get_extension_header(packet, 2, &data);
	BC_ASSERT_EQUAL(size, strlen(test2), size_t, "%zu");

	copy = ortp_strndup((char *) data, (int) size);
	BC_ASSERT_STRING_EQUAL(copy, test2);
	free(copy);

	size = rtp_get_extension_header(packet, 3, &data);
	BC_ASSERT_EQUAL(size, strlen(test3), size_t, "%zu");

	copy = ortp_strndup((char *) data, (int) size);
	BC_ASSERT_STRING_EQUAL(copy, test3);
	free(copy);

	freemsg(packet);
}

static void insert_client_to_mixer_into_packet(void) {
	int result;
	bool_t voice_activity;

	mblk_t *packet = rtp_session_create_packet(session, RTP_FIXED_HEADER_SIZE, NULL, 0);

	rtp_add_client_to_mixer_audio_level(packet, RTP_EXTENSION_CLIENT_TO_MIXER_AUDIO_LEVEL, TRUE, -64);

	result = rtp_get_client_to_mixer_audio_level(packet, RTP_EXTENSION_CLIENT_TO_MIXER_AUDIO_LEVEL, &voice_activity);
	BC_ASSERT_EQUAL(result, -64, int, "%d");
	BC_ASSERT_EQUAL(voice_activity, TRUE, bool_t, "%d");

	freemsg(packet);
}

static void insert_mixer_to_client_into_packet(void) {
	int audio_size;
	rtp_audio_level_t audio_levels[15];

	mblk_t *packet = rtp_session_create_packet(session, RTP_FIXED_HEADER_SIZE, NULL, 0);
	rtp_audio_level_t values[5] = {{1, -127}, {2, -115}, {0, -53}, {4, -28}, {5, 0}};

	rtp_add_mixer_to_client_audio_level(packet, RTP_EXTENSION_MIXER_TO_CLIENT_AUDIO_LEVEL, 5, values);
	audio_size = rtp_get_mixer_to_client_audio_level(packet, RTP_EXTENSION_MIXER_TO_CLIENT_AUDIO_LEVEL, audio_levels);

	BC_ASSERT_EQUAL(audio_size, 5, int, "%d");

	BC_ASSERT_EQUAL(audio_levels[0].csrc, 1, int, "%d");
	BC_ASSERT_EQUAL(audio_levels[0].dbov, -127, int, "%d");

	BC_ASSERT_EQUAL(audio_levels[1].csrc, 2, int, "%d");
	BC_ASSERT_EQUAL(audio_levels[1].dbov, -115, int, "%d");

	BC_ASSERT_EQUAL(audio_levels[2].csrc, 0, int, "%d");
	BC_ASSERT_EQUAL(audio_levels[2].dbov, -53, int, "%d");

	BC_ASSERT_EQUAL(audio_levels[3].csrc, 4, int, "%d");
	BC_ASSERT_EQUAL(audio_levels[3].dbov, -28, int, "%d");

	BC_ASSERT_EQUAL(audio_levels[4].csrc, 5, int, "%d");
	BC_ASSERT_EQUAL(audio_levels[4].dbov, 0, int, "%d");

	freemsg(packet);
}

static void insert_frame_marking_into_packet(void) {
	size_t size;
	int ret;
	uint8_t result;

	mblk_t *packet = rtp_session_create_packet(session, RTP_FIXED_HEADER_SIZE, NULL, 0);
	uint8_t marker = RTP_FRAME_MARKER_START | RTP_FRAME_MARKER_INDEPENDENT;

	rtp_add_frame_marker(packet, RTP_EXTENSION_FRAME_MARKING, marker);

	size = rtp_get_extheader(packet, NULL, NULL);
	BC_ASSERT_GREATER(size, 0, size_t, "%zu");

	ret = rtp_get_frame_marker(packet, RTP_EXTENSION_FRAME_MARKING, &result);
	BC_ASSERT_EQUAL(ret, 1, int, "%d");
	BC_ASSERT_TRUE(result & RTP_FRAME_MARKER_START);
	BC_ASSERT_TRUE(result & RTP_FRAME_MARKER_INDEPENDENT);

	freemsg(packet);
}

static test_t tests[] = {
	TEST_NO_TAG("Insert an extension header into a packet", insert_extension_header_into_packet),
	TEST_NO_TAG("Insert multiple extension headers into a packet", insert_multiple_extension_headers_into_packet),
	TEST_NO_TAG("Insert client to mixer audio level into a packet", insert_client_to_mixer_into_packet),
	TEST_NO_TAG("Insert mixer to client audio level into a packet", insert_mixer_to_client_into_packet),
	TEST_NO_TAG("Insert frame marking into a packet", insert_frame_marking_into_packet)
};

test_suite_t extension_header_test_suite = {
	"Extension header",				  // Name of test suite
	tester_before_all,				  // Before all callback
	tester_after_all,				  // After all callback
	NULL,							  // Before each callback
	NULL,							  // After each callback
	sizeof(tests) / sizeof(tests[0]), // Size of test table
	tests							  // Table of test suite
};