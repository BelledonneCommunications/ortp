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

#include <bctoolbox/defs.h>

#include "ortp_tester.h"
#include <ortp/ortp.h>

static RtpSession *session = NULL;
static RtpSession *bundled_session = NULL;
static RtpSession *csrc_session = NULL;
static RtpSession *csrc_bundled_session = NULL;
static RtpBundle *bundle = NULL;
static RtpBundle *csrc_bundle = NULL;
static char mid[9] = "bundleid";
static uint32_t CSRC = 0xaa55a55a;
#define PAYLOAD_SIZE 33
static uint8_t payload[PAYLOAD_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

static int tester_before_all(void) {
	ortp_init();
	ortp_scheduler_init();

	session = rtp_session_new(RTP_SESSION_SENDONLY);

	/* create a session and bundle with id */
	bundled_session = rtp_session_new(RTP_SESSION_SENDONLY);
	bundle = rtp_bundle_new();
	rtp_bundle_add_session(bundle, mid, bundled_session);
	rtp_bundle_set_mid_extension_id(bundle, RTP_EXTENSION_MID);

	/* create a session with a CSRC */
	csrc_session = rtp_session_new(RTP_SESSION_SENDONLY);
	rtp_session_add_contributing_source(csrc_session, CSRC, "cname", "name", "email", "phone", "location", "tool",
	                                    "note");

	/* create a session with CSRC and bundle it */
	csrc_bundled_session = rtp_session_new(RTP_SESSION_SENDONLY);
	csrc_bundle = rtp_bundle_new();
	rtp_bundle_add_session(csrc_bundle, mid, csrc_bundled_session);
	rtp_bundle_set_mid_extension_id(csrc_bundle, RTP_EXTENSION_MID);
	rtp_session_add_contributing_source(csrc_bundled_session, CSRC, "cname", "name", "email", "phone", "location",
	                                    "tool", "note");

	return 0;
}

static int tester_after_all(void) {
	rtp_session_destroy(session);
	rtp_bundle_delete(bundle);
	bundle = NULL;
	rtp_bundle_delete(csrc_bundle);
	csrc_bundle = NULL;
	rtp_session_destroy(bundled_session);
	rtp_session_destroy(csrc_session);
	rtp_session_destroy(csrc_bundled_session);
	session = NULL;
	bundled_session = NULL;
	csrc_session = NULL;
	csrc_bundled_session = NULL;

	ortp_exit();

	return 0;
}

/* reset mid sent infos as mid is not sent every packet */
static void tester_before_each(void) {
	session->mid_sent = 0;
	session->last_mid_sent_time = 0;

	bundled_session->mid_sent = 0;
	bundled_session->last_mid_sent_time = 0;

	csrc_session->mid_sent = 0;
	csrc_session->last_mid_sent_time = 0;

	csrc_bundled_session->mid_sent = 0;
	csrc_bundled_session->last_mid_sent_time = 0;
}

#define NO_PAYLOAD 0
#define PAYLOAD 1
#define DETACHED_PAYLOAD 2

static void insert_extension_header_into_packet_base(uint8_t with_payload, RtpSession *test_session) {
	uint16_t extbit;
	size_t size, expected_size;
	char *test = "Running test";

	mblk_t *packet;
	switch (with_payload) {
		case PAYLOAD:
			/* payload and header in one continuous message block */
			packet = rtp_session_create_packet_header(
			    test_session, PAYLOAD_SIZE); // ask for PAYLOAD size to be allocated after the header
			memcpy(packet->b_wptr, payload, PAYLOAD_SIZE);
			packet->b_wptr += PAYLOAD_SIZE;
			break;
		case DETACHED_PAYLOAD:
			/* fragmented message block */
			packet = rtp_session_create_packet_header(test_session, 0);
			packet->b_cont = rtp_create_packet(payload, PAYLOAD_SIZE);
			break;
		case NO_PAYLOAD:
		default: // NO PAYLAOD
			packet = rtp_session_create_packet_header(test_session, 0);
	}

	rtp_add_extension_header(packet, 10, strlen(test), (uint8_t *)test);

	extbit = rtp_get_extbit(packet);
	BC_ASSERT_EQUAL(extbit, 1, uint16_t, "%d");

	size = rtp_get_extheader(packet, NULL, NULL);

	expected_size = (strlen(test) + 1); // extension + 1-byte header + potential padding
	if (test_session == bundled_session || test_session == csrc_bundled_session) {
		expected_size += strlen(mid) + 1;
	}
	if (expected_size % 4 != 0) {
		expected_size = expected_size + (4 - expected_size % 4);
	}

	BC_ASSERT_EQUAL(size, expected_size, size_t, "%zu");
	if (with_payload != NO_PAYLOAD) {
		uint8_t *p = NULL;
		int psize = rtp_get_payload(packet, &p);
		if (BC_ASSERT_TRUE(psize == PAYLOAD_SIZE)) {
			BC_ASSERT_TRUE(memcmp(p, payload, PAYLOAD_SIZE) == 0);
		}
	}

	if (test_session == bundled_session || test_session == csrc_bundled_session) {
		uint8_t *data = NULL;
		/* check the session id is in the header */
		int size = rtp_get_extension_header(packet, RTP_EXTENSION_MID, &data);
		BC_ASSERT_EQUAL(size, (int)(strlen(mid)), int, "%d");
		if (size == (int)strlen(mid)) {
			BC_ASSERT_TRUE(memcmp(data, mid, size) == 0);
		}
	}

	if (test_session == csrc_session || test_session == csrc_bundled_session) {
		uint16_t cc = rtp_get_cc(packet);
		BC_ASSERT_EQUAL(cc, 1, uint16_t, "%d");
		if (cc == 1) {
			uint32_t csrc = rtp_get_csrc(packet, 0);
			BC_ASSERT_EQUAL(csrc, CSRC, uint32_t, "%d");
		}
	}

	freemsg(packet);
}

static void insert_extension_header_into_packet(void) {
	insert_extension_header_into_packet_base(NO_PAYLOAD, session);
}

static void insert_extension_header_into_packet_with_payload(void) {
	insert_extension_header_into_packet_base(PAYLOAD, session);
}

static void insert_extension_header_into_packet_with_detached_payload(void) {
	insert_extension_header_into_packet_base(DETACHED_PAYLOAD, session);
}

static void insert_extension_header_into_packet_in_bundled_session(void) {
	insert_extension_header_into_packet_base(NO_PAYLOAD, bundled_session);
}
static void insert_extension_header_into_packet_with_payload_in_bundled_session(void) {
	insert_extension_header_into_packet_base(PAYLOAD, bundled_session);
}
static void insert_extension_header_into_packet_with_detached_payload_in_bundled_session(void) {
	insert_extension_header_into_packet_base(DETACHED_PAYLOAD, bundled_session);
}

static void insert_extension_header_into_packet_in_csrc_session(void) {
	insert_extension_header_into_packet_base(NO_PAYLOAD, csrc_session);
}
static void insert_extension_header_into_packet_with_payload_in_csrc_session(void) {
	insert_extension_header_into_packet_base(PAYLOAD, csrc_session);
}
static void insert_extension_header_into_packet_with_detached_payload_in_csrc_session(void) {
	insert_extension_header_into_packet_base(DETACHED_PAYLOAD, csrc_session);
}

static void insert_extension_header_into_packet_in_csrc_bundled_session(void) {
	insert_extension_header_into_packet_base(NO_PAYLOAD, csrc_bundled_session);
}
static void insert_extension_header_into_packet_with_payload_in_csrc_bundled_session(void) {
	insert_extension_header_into_packet_base(PAYLOAD, csrc_bundled_session);
}
static void insert_extension_header_into_packet_with_detached_payload_in_csrc_bundled_session(void) {
	insert_extension_header_into_packet_base(DETACHED_PAYLOAD, csrc_bundled_session);
}

static void insert_multiple_extension_headers_into_packet_base(uint8_t with_payload, RtpSession *test_session) {
	int i;
	mblk_t *packet;
	char *test = "running test"; // 12 bytes -> 13 with header, 1 padding bytes
	char *foo = "foo";           // -> no padding bytes
	char *bar = "bar12";         // -> 2 padding bytes
	int expected_header_size = 0;
	int expected_header_size_with_padding = 0;
	uint8_t expected_extensions_values[10][64];
	int expected_extensions_size[10];

	// Test multiple extension into the same packet
	switch (with_payload) {
		case PAYLOAD:
			/* payload and header in one continuous message block */
			packet = rtp_session_create_packet_header(
			    test_session, PAYLOAD_SIZE); // ask for PAYLOAD size to be allocated after the header
			memcpy(packet->b_wptr, payload, PAYLOAD_SIZE);
			packet->b_wptr += PAYLOAD_SIZE;
			break;
		case DETACHED_PAYLOAD:
			/* fragmented message block */
			packet = rtp_session_create_packet_header(test_session, 0);
			packet->b_cont = rtp_create_packet(payload, PAYLOAD_SIZE);
			break;
		case NO_PAYLOAD:
		default: // NO PAYLAOD
			packet = rtp_session_create_packet_header(test_session, 0);
	}

	if (test_session == bundled_session || test_session == csrc_bundled_session) {
		expected_header_size += strlen(mid) + 1;
	}

	for (i = 1; i < 11; i++) {
		if ((test_session == bundled_session || test_session == csrc_bundled_session) && i == RTP_EXTENSION_MID)
			continue; // Do no overwritte MID header if any
		switch ((bctbx_random() % 3) + 1) {
			case 1:
				rtp_add_extension_header(packet, i, strlen(test), (uint8_t *)test);
				expected_header_size += 1 + strlen(test); // 1 byte header plus extension itself
				expected_extensions_size[i - 1] = strlen(test);
				memcpy(expected_extensions_values[i - 1], test, strlen(test));
				break;
			case 2:
				rtp_add_extension_header(packet, i, strlen(foo), (uint8_t *)foo);
				expected_header_size += 1 + strlen(foo); // 1 byte header plus extension itself
				expected_extensions_size[i - 1] = strlen(foo);
				memcpy(expected_extensions_values[i - 1], foo, strlen(foo));
				break;
			default:
				rtp_add_extension_header(packet, i, strlen(bar), (uint8_t *)bar);
				expected_header_size += 1 + strlen(bar); // 1 byte header plus extension itself
				expected_extensions_size[i - 1] = strlen(bar);
				memcpy(expected_extensions_values[i - 1], bar, strlen(bar));
				break;
		}

		if (expected_header_size % 4 != 0) {
			expected_header_size_with_padding = expected_header_size + (4 - expected_header_size % 4);
		} else {
			expected_header_size_with_padding = expected_header_size;
		}
		BC_ASSERT_EQUAL(rtp_get_extheader(packet, NULL, NULL), expected_header_size_with_padding, int, "%d");
	}

	for (i = 0; i < 10; i++) {
		uint8_t *data = NULL;
		int size = rtp_get_extension_header(packet, i + 1, &data);
		if ((test_session == bundled_session || test_session == csrc_bundled_session) && i + 1 == RTP_EXTENSION_MID) {
			BC_ASSERT_EQUAL(size, (int)(strlen(mid)), int, "%d");
			if (size == (int)strlen(mid)) {
				BC_ASSERT_TRUE(memcmp(data, mid, size) == 0);
			}
		} else {
			BC_ASSERT_EQUAL(size, expected_extensions_size[i], int, "%d");
			if (size == expected_extensions_size[i]) {
				BC_ASSERT_TRUE(memcmp(data, expected_extensions_values[i], size) == 0);
			}
		}
	}
	if (with_payload == TRUE) {
		uint8_t *p = NULL;
		int psize = rtp_get_payload(packet, &p);
		if (BC_ASSERT_TRUE(psize == PAYLOAD_SIZE)) {
			BC_ASSERT_TRUE(memcmp(p, payload, PAYLOAD_SIZE) == 0);
		}
	}

	if (test_session == csrc_session || test_session == csrc_bundled_session) {
		uint16_t cc = rtp_get_cc(packet);
		BC_ASSERT_EQUAL(cc, 1, uint16_t, "%d");
		if (cc == 1) {
			uint32_t csrc = rtp_get_csrc(packet, 0);
			BC_ASSERT_EQUAL(csrc, CSRC, uint32_t, "%d");
		}
	}

	freemsg(packet);
}

static void insert_multiple_extension_headers_into_packet(void) {
	insert_multiple_extension_headers_into_packet_base(NO_PAYLOAD, session);
}
static void insert_multiple_extension_headers_into_packet_with_payload(void) {
	insert_multiple_extension_headers_into_packet_base(PAYLOAD, session);
}
static void insert_multiple_extension_headers_into_packet_with_detached_payload(void) {
	insert_multiple_extension_headers_into_packet_base(DETACHED_PAYLOAD, session);
}

static void insert_multiple_extension_headers_into_packet_in_bundled_session(void) {
	insert_multiple_extension_headers_into_packet_base(NO_PAYLOAD, bundled_session);
}
static void insert_multiple_extension_headers_into_packet_with_payload_in_bundled_session(void) {
	insert_multiple_extension_headers_into_packet_base(PAYLOAD, bundled_session);
}
static void insert_multiple_extension_headers_into_packet_with_detached_payload_in_bundled_session(void) {
	insert_multiple_extension_headers_into_packet_base(DETACHED_PAYLOAD, bundled_session);
}

static void insert_multiple_extension_headers_into_packet_in_csrc_session(void) {
	insert_multiple_extension_headers_into_packet_base(NO_PAYLOAD, csrc_session);
}
static void insert_multiple_extension_headers_into_packet_with_payload_in_csrc_session(void) {
	insert_multiple_extension_headers_into_packet_base(PAYLOAD, csrc_session);
}
static void insert_multiple_extension_headers_into_packet_with_detached_payload_in_csrc_session(void) {
	insert_multiple_extension_headers_into_packet_base(DETACHED_PAYLOAD, csrc_session);
}

static void insert_multiple_extension_headers_into_packet_in_csrc_bundled_session(void) {
	insert_multiple_extension_headers_into_packet_base(NO_PAYLOAD, csrc_bundled_session);
}
static void insert_multiple_extension_headers_into_packet_with_payload_in_csrc_bundled_session(void) {
	insert_multiple_extension_headers_into_packet_base(PAYLOAD, csrc_bundled_session);
}
static void insert_multiple_extension_headers_into_packet_with_detached_payload_in_csrc_bundled_session(void) {
	insert_multiple_extension_headers_into_packet_base(DETACHED_PAYLOAD, csrc_bundled_session);
}

static void insert_client_to_mixer_into_packet_base(uint8_t with_payload, RtpSession *test_session) {
	int result;
	bool_t voice_activity;
	mblk_t *packet = NULL;

	switch (with_payload) {
		case PAYLOAD:
			/* payload and header in one continuous message block */
			packet = rtp_session_create_packet_header(
			    test_session, PAYLOAD_SIZE); // ask for PAYLOAD size to be allocated after the header
			memcpy(packet->b_wptr, payload, PAYLOAD_SIZE);
			packet->b_wptr += PAYLOAD_SIZE;
			break;
		case DETACHED_PAYLOAD:
			/* fragmented message block */
			packet = rtp_session_create_packet_header(test_session, 0);
			packet->b_cont = rtp_create_packet(payload, PAYLOAD_SIZE);
			break;
		case NO_PAYLOAD:
		default: // NO PAYLAOD
			packet = rtp_session_create_packet_header(test_session, 0);
	}

	rtp_add_client_to_mixer_audio_level(packet, RTP_EXTENSION_CLIENT_TO_MIXER_AUDIO_LEVEL, TRUE, -64);

	result = rtp_get_client_to_mixer_audio_level(packet, RTP_EXTENSION_CLIENT_TO_MIXER_AUDIO_LEVEL, &voice_activity);
	BC_ASSERT_EQUAL(result, -64, int, "%d");
	BC_ASSERT_EQUAL(voice_activity, TRUE, bool_t, "%d");
	rtp_add_client_to_mixer_audio_level(packet, RTP_EXTENSION_CLIENT_TO_MIXER_AUDIO_LEVEL + 1, FALSE, 0);
	result = rtp_get_client_to_mixer_audio_level(packet, RTP_EXTENSION_CLIENT_TO_MIXER_AUDIO_LEVEL, &voice_activity);
	BC_ASSERT_EQUAL(result, -64, int, "%d");
	BC_ASSERT_EQUAL(voice_activity, TRUE, int, "%d");
	result =
	    rtp_get_client_to_mixer_audio_level(packet, RTP_EXTENSION_CLIENT_TO_MIXER_AUDIO_LEVEL + 1, &voice_activity);
	BC_ASSERT_EQUAL(result, 0, int, "%d");
	BC_ASSERT_EQUAL(voice_activity, FALSE, int, "%d");

	if (with_payload == TRUE) {
		uint8_t *p = NULL;
		int psize = rtp_get_payload(packet, &p);
		if (BC_ASSERT_TRUE(psize == PAYLOAD_SIZE)) {
			BC_ASSERT_TRUE(memcmp(p, payload, PAYLOAD_SIZE) == 0);
		}
	}

	if (test_session == bundled_session || test_session == csrc_bundled_session) {
		uint8_t *data = NULL;
		/* check the session id is in the header */
		int size = rtp_get_extension_header(packet, RTP_EXTENSION_MID, &data);
		BC_ASSERT_EQUAL(size, (int)(strlen(mid)), int, "%d");
		if (size == (int)strlen(mid)) {
			BC_ASSERT_TRUE(memcmp(data, mid, size) == 0);
		}
	}

	if (test_session == csrc_session || test_session == csrc_bundled_session) {
		uint16_t cc = rtp_get_cc(packet);
		BC_ASSERT_EQUAL(cc, 1, uint16_t, "%d");
		if (cc == 1) {
			uint32_t csrc = rtp_get_csrc(packet, 0);
			BC_ASSERT_EQUAL(csrc, CSRC, uint32_t, "%d");
		}
	}

	freemsg(packet);
}

static void insert_client_to_mixer_into_packet(void) {
	insert_client_to_mixer_into_packet_base(NO_PAYLOAD, session);
}
static void insert_client_to_mixer_into_packet_with_payload(void) {
	insert_client_to_mixer_into_packet_base(PAYLOAD, session);
}
static void insert_client_to_mixer_into_packet_with_detached_payload(void) {
	insert_client_to_mixer_into_packet_base(DETACHED_PAYLOAD, session);
}

static void insert_client_to_mixer_into_packet_in_bundled_session(void) {
	insert_client_to_mixer_into_packet_base(NO_PAYLOAD, bundled_session);
}
static void insert_client_to_mixer_into_packet_with_payload_in_bundled_session(void) {
	insert_client_to_mixer_into_packet_base(PAYLOAD, bundled_session);
}
static void insert_client_to_mixer_into_packet_with_detached_payload_in_bundled_session(void) {
	insert_client_to_mixer_into_packet_base(DETACHED_PAYLOAD, bundled_session);
}

static void insert_client_to_mixer_into_packet_in_csrc_session(void) {
	insert_client_to_mixer_into_packet_base(NO_PAYLOAD, csrc_session);
}
static void insert_client_to_mixer_into_packet_with_payload_in_csrc_session(void) {
	insert_client_to_mixer_into_packet_base(PAYLOAD, csrc_session);
}
static void insert_client_to_mixer_into_packet_with_detached_payload_in_csrc_session(void) {
	insert_client_to_mixer_into_packet_base(DETACHED_PAYLOAD, csrc_session);
}

static void insert_client_to_mixer_into_packet_in_csrc_bundled_session(void) {
	insert_client_to_mixer_into_packet_base(NO_PAYLOAD, csrc_bundled_session);
}
static void insert_client_to_mixer_into_packet_with_payload_in_csrc_bundled_session(void) {
	insert_client_to_mixer_into_packet_base(PAYLOAD, csrc_bundled_session);
}
static void insert_client_to_mixer_into_packet_with_detached_payload_in_csrc_bundled_session(void) {
	insert_client_to_mixer_into_packet_base(DETACHED_PAYLOAD, csrc_bundled_session);
}

static void
insert_mixer_to_client_into_packet_base(bool_t with_payload, bool_t use_create_with_mixer, RtpSession *test_session) {
	int audio_size;
	rtp_audio_level_t audio_levels[15];
	rtp_audio_level_t values[5] = {{1, -127}, {2, -115}, {0, -53}, {4, -28}, {5, 0}};
	mblk_t *packet = NULL;

	if (use_create_with_mixer) {
		packet = rtp_session_create_packet_header_with_mixer_to_client_audio_level(
		    test_session, 0, RTP_EXTENSION_MIXER_TO_CLIENT_AUDIO_LEVEL, 5, values);
		if (with_payload == TRUE) {
			packet->b_cont = rtp_create_packet(payload, PAYLOAD_SIZE);
		}
	} else {
		packet = rtp_session_create_packet_header(test_session, 0);
		if (with_payload == TRUE) {
			packet->b_cont = rtp_create_packet(payload, PAYLOAD_SIZE);
		}
		rtp_add_mixer_to_client_audio_level(packet, RTP_EXTENSION_MIXER_TO_CLIENT_AUDIO_LEVEL, 5, values);
	}

	audio_size = rtp_get_mixer_to_client_audio_level(packet, RTP_EXTENSION_MIXER_TO_CLIENT_AUDIO_LEVEL, audio_levels);

	BC_ASSERT_EQUAL(audio_size, 5, int, "%d");

	if (audio_size == 5) {
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
	}

	if (with_payload == TRUE) {
		uint8_t *p = NULL;
		int psize = rtp_get_payload(packet, &p);
		if (BC_ASSERT_TRUE(psize == PAYLOAD_SIZE)) {
			BC_ASSERT_TRUE(memcmp(p, payload, PAYLOAD_SIZE) == 0);
		}
	}

	if (test_session == bundled_session) {
		uint8_t *data = NULL;
		/* check the session id is in the header */
		int size = rtp_get_extension_header(packet, RTP_EXTENSION_MID, &data);
		BC_ASSERT_EQUAL(size, (int)(strlen(mid)), int, "%d");
		if (size == (int)strlen(mid)) {
			BC_ASSERT_TRUE(memcmp(data, mid, size) == 0);
		}
	}

	freemsg(packet);
}
static void insert_mixer_to_client_into_packet(void) {
	insert_mixer_to_client_into_packet_base(FALSE, FALSE, session);
}
static void insert_mixer_to_client_into_packet_with_payload(void) {
	insert_mixer_to_client_into_packet_base(TRUE, FALSE, session);
}
static void insert_mixer_to_client_into_packet_in_bundled_session(void) {
	insert_mixer_to_client_into_packet_base(FALSE, FALSE, bundled_session);
}
static void insert_mixer_to_client_into_packet_with_payload_in_bundled_session(void) {
	insert_mixer_to_client_into_packet_base(TRUE, FALSE, bundled_session);
}

static void insert_mixer_to_client_into_packet_use_create_with_mixer(void) {
	insert_mixer_to_client_into_packet_base(FALSE, TRUE, session);
}
static void insert_mixer_to_client_into_packet_with_payload_use_create_with_mixer(void) {
	insert_mixer_to_client_into_packet_base(TRUE, TRUE, session);
}
static void insert_mixer_to_client_into_packet_in_bundled_session_use_create_with_mixer(void) {
	insert_mixer_to_client_into_packet_base(FALSE, TRUE, bundled_session);
}
static void insert_mixer_to_client_into_packet_with_payload_in_bundled_session_use_create_with_mixer(void) {
	insert_mixer_to_client_into_packet_base(TRUE, TRUE, bundled_session);
}

static void insert_frame_marking_into_packet_base(BCTBX_UNUSED(bool_t with_payload),
                                                  BCTBX_UNUSED(RtpSession *test_session)) {
	size_t size;
	int ret;
	uint8_t result;

	mblk_t *packet = rtp_session_create_packet_header(session, 0);
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
static void insert_frame_marking_into_packet(void) {
	insert_frame_marking_into_packet_base(FALSE, session);
}
static void insert_frame_marking_into_packet_with_payload(void) {
	insert_frame_marking_into_packet_base(TRUE, session);
}
static void insert_frame_marking_into_packet_in_bundled_session(void) {
	insert_frame_marking_into_packet_base(FALSE, bundled_session);
}
static void insert_frame_marking_into_packet_with_payload_in_bundled_session(void) {
	insert_frame_marking_into_packet_base(TRUE, bundled_session);
}

static void padding_test(void) {
	// packet with the header, ext are 1 : bar1, 2:foo, 3 padding bytes
	uint8_t ext1[4] = {0x62, 0x61, 0x72, 0x31};       // extension with id 1 is "bar1"
	uint8_t ext2[3] = {0x66, 0x6f, 0x6f};             // extension with id 2 is "foo"
	uint8_t ext3[5] = {0x01, 0x02, 0x03, 0x04, 0x05}; // extension with id 3
	uint8_t raw_packet_padding_at_the_end[28] = {0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x8a,
	                                             0x1a, 0x76, 0xbe, 0xde, 0x00, 0x03, 0x13, 0x62, 0x61, 0x72,
	                                             0x31, 0x22, 0x66, 0x6f, 0x6f, 0x00, 0x00, 0x00};
	uint8_t raw_packet_padding_at_the_begining[28] = {0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x8a,
	                                                  0x1a, 0x76, 0xbe, 0xde, 0x00, 0x03, 0x00, 0x00, 0x00, 0x13,
	                                                  0x62, 0x61, 0x72, 0x31, 0x22, 0x66, 0x6f, 0x6f};
	uint8_t raw_packet_padding_in_the_middle[28] = {0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x8a,
	                                                0x1a, 0x76, 0xbe, 0xde, 0x00, 0x03, 0x13, 0x62, 0x61, 0x72,
	                                                0x31, 0x00, 0x00, 0x00, 0x22, 0x66, 0x6f, 0x6f};
	uint8_t *raw_packets[3] = {raw_packet_padding_at_the_end, raw_packet_padding_at_the_begining,
	                           raw_packet_padding_in_the_middle};
	mblk_t *packet;
	uint8_t *data;

	int i, size;

	for (i = 0; i < 3; i++) {
		ortp_message("run on pattern %d", i);
		packet = rtp_create_packet(raw_packets[i], 28);
		/* check ext bit and size - expected to be 12 */
		BC_ASSERT_EQUAL(rtp_get_extbit(packet), 1, uint16_t, "%d");
		size = rtp_get_extheader(packet, NULL, NULL);
		BC_ASSERT_EQUAL(size, 12, unsigned int, "%d");

		/* check ext 1*/
		size = rtp_get_extension_header(packet, 1, &data);
		BC_ASSERT_EQUAL(size, sizeof(ext1), int, "%d");
		if (size == sizeof(ext1)) {
			BC_ASSERT_TRUE(memcmp(data, ext1, size) == 0);
		}

		/* check ext 2*/
		size = rtp_get_extension_header(packet, 2, &data);
		BC_ASSERT_EQUAL(size, sizeof(ext2), int, "%d");
		if (size == sizeof(ext2)) {
			BC_ASSERT_TRUE(memcmp(data, ext2, size) == 0);
		}

		/* add a new header ext */
		rtp_add_extension_header(packet, 3, sizeof(ext3), ext3);

		/* check ext bit and size - expected to be 16 */
		BC_ASSERT_EQUAL(rtp_get_extbit(packet), 1, uint16_t, "%d");
		size = rtp_get_extheader(packet, NULL, NULL);
		if (i == 0) {
			// when padding is at the end, it is re-used, so we can fit the 3 extensions in 16 bytes
			// 4+3+5 for content, 3 for ids = 15 bytes -> 16 bytes with rounding up to %4=0
			BC_ASSERT_EQUAL(size, 16, unsigned int, "%d");
		} else {
			// when padding is not at the end, we will not reuse it when adding an extension. We need 20 bytes to fit
			// the 3 extensions 4+3+5 for content, 3 for ids + 3 padding bytes from the original message = 18 -> 20
			// bytes with rounding up to %4=0
			BC_ASSERT_EQUAL(size, 20, unsigned int, "%d");
		}

		/* check ext 1*/
		size = rtp_get_extension_header(packet, 1, &data);
		BC_ASSERT_EQUAL(size, sizeof(ext1), int, "%d");
		if (size == sizeof(ext1)) {
			BC_ASSERT_TRUE(memcmp(data, ext1, size) == 0);
		}

		/* check ext 2*/
		size = rtp_get_extension_header(packet, 2, &data);
		BC_ASSERT_EQUAL(size, sizeof(ext2), int, "%d");
		if (size == sizeof(ext2)) {
			BC_ASSERT_TRUE(memcmp(data, ext2, size) == 0);
		}

		/* check ext 3*/
		size = rtp_get_extension_header(packet, 3, &data);
		BC_ASSERT_EQUAL(size, sizeof(ext3), int, "%d");
		if (size == sizeof(ext3)) {
			BC_ASSERT_TRUE(memcmp(data, ext3, size) == 0);
		}

		freemsg(packet);
	}
}

static void create_packet_with_payload_in_bundled_session(void) {
	uint8_t *data;
	int size = 0;
	mblk_t *packet = NULL;

	/* create a packet in the bundled session, without payload */
	packet = rtp_session_create_packet_header(bundled_session, 0);
	/* check the session id is in the header */
	size = rtp_get_extension_header(packet, RTP_EXTENSION_MID, &data);
	BC_ASSERT_EQUAL(size, (int)(strlen(mid)), int, "%d");
	if (size == (int)(strlen(mid))) {
		BC_ASSERT_TRUE(memcmp(data, mid, size) == 0);
	}
	freemsg(packet);

	/* same but with a payload in a non fragmented message block */
	packet = rtp_session_create_packet_header(bundled_session, PAYLOAD_SIZE);
	memcpy(packet->b_wptr, payload, PAYLOAD_SIZE);
	packet->b_wptr += PAYLOAD_SIZE;
	/* check the session id is in the header */
	size = rtp_get_extension_header(packet, RTP_EXTENSION_MID, &data);
	BC_ASSERT_EQUAL(size, (int)(strlen(mid)), int, "%d");
	if (size == (int)(strlen(mid))) {
		BC_ASSERT_TRUE(memcmp(data, mid, size) == 0);
	}
	size = rtp_get_payload(packet, &data);
	if (BC_ASSERT_TRUE(size == PAYLOAD_SIZE)) {
		BC_ASSERT_TRUE(memcmp(data, payload, PAYLOAD_SIZE) == 0);
	}
	freemsg(packet);

	/* same but with a payload in a fragmented message block */
	packet = rtp_session_create_packet_header(bundled_session, 0);
	packet->b_cont = rtp_create_packet(payload, PAYLOAD_SIZE);
	/* check the session id is in the header */
	size = rtp_get_extension_header(packet, RTP_EXTENSION_MID, &data);
	BC_ASSERT_EQUAL(size, (int)(strlen(mid)), int, "%d");
	if (size == (int)(strlen(mid))) {
		BC_ASSERT_TRUE(memcmp(data, mid, size) == 0);
	}
	size = rtp_get_payload(packet, &data);
	if (BC_ASSERT_TRUE(size == PAYLOAD_SIZE)) {
		BC_ASSERT_TRUE(memcmp(data, payload, PAYLOAD_SIZE) == 0);
	}
	freemsg(packet);
}

static test_t tests[] = {
    TEST_NO_TAG("Create packet with payload in a bundled session", create_packet_with_payload_in_bundled_session),
    TEST_NO_TAG("Insert an extension header into a packet", insert_extension_header_into_packet),
    TEST_NO_TAG("Insert an extension header into a packet with payload",
                insert_extension_header_into_packet_with_payload),
    TEST_NO_TAG("Insert an extension header into a packet with detached payload",
                insert_extension_header_into_packet_with_detached_payload),
    TEST_NO_TAG("Insert an extension header into a packet in bundled session",
                insert_extension_header_into_packet_in_bundled_session),
    TEST_NO_TAG("Insert an extension header into a packet with payload in bundled session",
                insert_extension_header_into_packet_with_payload_in_bundled_session),
    TEST_NO_TAG("Insert an extension header into a packet with detached payload in bundled session",
                insert_extension_header_into_packet_with_detached_payload_in_bundled_session),
    TEST_NO_TAG("Insert an extension header into a packet in csrc session",
                insert_extension_header_into_packet_in_csrc_session),
    TEST_NO_TAG("Insert an extension header into a packet with payload in csrc session",
                insert_extension_header_into_packet_with_payload_in_csrc_session),
    TEST_NO_TAG("Insert an extension header into a packet with detached payload in csrc session",
                insert_extension_header_into_packet_with_detached_payload_in_csrc_session),
    TEST_NO_TAG("Insert an extension header into a packet in csrc bundled session",
                insert_extension_header_into_packet_in_csrc_bundled_session),
    TEST_NO_TAG("Insert an extension header into a packet with payload in csrc bundled session",
                insert_extension_header_into_packet_with_payload_in_csrc_bundled_session),
    TEST_NO_TAG("Insert an extension header into a packet with detached payload in csrc bundled session",
                insert_extension_header_into_packet_with_detached_payload_in_csrc_bundled_session),
    TEST_NO_TAG("Insert multiple extension headers into a packet", insert_multiple_extension_headers_into_packet),
    TEST_NO_TAG("Insert multiple extension headers into a packet with payload",
                insert_multiple_extension_headers_into_packet_with_payload),
    TEST_NO_TAG("Insert multiple extension headers into a packet with detached payload",
                insert_multiple_extension_headers_into_packet_with_detached_payload),
    TEST_NO_TAG("Insert multiple extension headers into a packet in bundled session",
                insert_multiple_extension_headers_into_packet_in_bundled_session),
    TEST_NO_TAG("Insert multiple extension headers into a packet with payload in bundled session",
                insert_multiple_extension_headers_into_packet_with_payload_in_bundled_session),
    TEST_NO_TAG("Insert multiple extension headers into a packet with detached payload in bundled session",
                insert_multiple_extension_headers_into_packet_with_detached_payload_in_bundled_session),
    TEST_NO_TAG("Insert multiple extension headers into a packet in csrc session",
                insert_multiple_extension_headers_into_packet_in_csrc_session),
    TEST_NO_TAG("Insert multiple extension headers into a packet with payload in bundled session",
                insert_multiple_extension_headers_into_packet_with_payload_in_csrc_session),
    TEST_NO_TAG("Insert multiple extension headers into a packet with detached payload in bundled session",
                insert_multiple_extension_headers_into_packet_with_detached_payload_in_csrc_session),
    TEST_NO_TAG("Insert multiple extension headers into a packet in csrc bundled session",
                insert_multiple_extension_headers_into_packet_in_csrc_bundled_session),
    TEST_NO_TAG("Insert multiple extension headers into a packet with payload in csrc bundled session",
                insert_multiple_extension_headers_into_packet_with_payload_in_csrc_bundled_session),
    TEST_NO_TAG("Insert multiple extension headers into a packet with detached payload in csrc bundled session",
                insert_multiple_extension_headers_into_packet_with_detached_payload_in_csrc_bundled_session),
    TEST_NO_TAG("Insert client to mixer audio level into a packet", insert_client_to_mixer_into_packet),
    TEST_NO_TAG("Insert client to mixer audio level into a packet with payload",
                insert_client_to_mixer_into_packet_with_payload),
    TEST_NO_TAG("Insert client to mixer audio level into a packet with detached payload",
                insert_client_to_mixer_into_packet_with_detached_payload),
    TEST_NO_TAG("Insert client to mixer audio level into a packet in bundled session",
                insert_client_to_mixer_into_packet_in_bundled_session),
    TEST_NO_TAG("Insert client to mixer audio level into a packet with payload in bundled session",
                insert_client_to_mixer_into_packet_with_payload_in_bundled_session),
    TEST_NO_TAG("Insert client to mixer audio level into a packet with detached payload in bundled session",
                insert_client_to_mixer_into_packet_with_detached_payload_in_bundled_session),
    TEST_NO_TAG("Insert client to mixer audio level into a packet in csrc session",
                insert_client_to_mixer_into_packet_in_csrc_session),
    TEST_NO_TAG("Insert client to mixer audio level into a packet with payload in csrc session",
                insert_client_to_mixer_into_packet_with_payload_in_csrc_session),
    TEST_NO_TAG("Insert client to mixer audio level into a packet with detached payload in csrc session",
                insert_client_to_mixer_into_packet_with_detached_payload_in_csrc_session),
    TEST_NO_TAG("Insert client to mixer audio level into a packet in csrc bundled session",
                insert_client_to_mixer_into_packet_in_csrc_bundled_session),
    TEST_NO_TAG("Insert client to mixer audio level into a packet with payload in csrc bundled session",
                insert_client_to_mixer_into_packet_with_payload_in_csrc_bundled_session),
    TEST_NO_TAG("Insert client to mixer audio level into a packet with detached payload in csrc bundled session",
                insert_client_to_mixer_into_packet_with_detached_payload_in_csrc_bundled_session),
    TEST_NO_TAG("Insert mixer to client audio level into a packet", insert_mixer_to_client_into_packet),
    TEST_NO_TAG("Insert mixer to client audio level into a packet with payload",
                insert_mixer_to_client_into_packet_with_payload),
    TEST_NO_TAG("Insert mixer to client audio level into a packet in bundled session",
                insert_mixer_to_client_into_packet_in_bundled_session),
    TEST_NO_TAG("Insert mixer to client audio level into a packet with payload in bundled session",
                insert_mixer_to_client_into_packet_with_payload_in_bundled_session),
    TEST_NO_TAG("Insert mixer to client audio level into a packet using create packet with mixer",
                insert_mixer_to_client_into_packet_use_create_with_mixer),
    TEST_NO_TAG("Insert mixer to client audio level into a packet with payload using create packet with mixer",
                insert_mixer_to_client_into_packet_with_payload_use_create_with_mixer),
    TEST_NO_TAG("Insert mixer to client audio level into a packet in bundled session using create packet with mixer",
                insert_mixer_to_client_into_packet_in_bundled_session_use_create_with_mixer),
    TEST_NO_TAG("Insert mixer to client audio level into a packet with payload in bundled session using create packet "
                "with mixer",
                insert_mixer_to_client_into_packet_with_payload_in_bundled_session_use_create_with_mixer),
    TEST_NO_TAG("Insert frame marking into a packet", insert_frame_marking_into_packet),
    TEST_NO_TAG("Insert frame marking into a packet with payload", insert_frame_marking_into_packet_with_payload),
    TEST_NO_TAG("Insert frame marking into a packet in bundled session",
                insert_frame_marking_into_packet_in_bundled_session),
    TEST_NO_TAG("Insert frame marking into a packet with payload in bundled session",
                insert_frame_marking_into_packet_with_payload_in_bundled_session),
    TEST_NO_TAG("Padding", padding_test)};

test_suite_t extension_header_test_suite = {
    "Extension header",               // Name of test suite
    tester_before_all,                // Before all callback
    tester_after_all,                 // After all callback
    tester_before_each,               // Before each callback
    NULL,                             // After each callback
    sizeof(tests) / sizeof(tests[0]), // Size of test table
    tests                             // Table of test suite
};
