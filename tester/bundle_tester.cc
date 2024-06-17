/*
 * Copyright (c) 2010-2024 Belledonne Communications SARL.
 *
 * This file is part of ortp
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

#include <bctoolbox/defs.h>

#include "ortp_tester.h"
#include "ortp_tester_utils.h"
#include "rtpbundle.h"

static void add_sessions() {
	RtpBundleCxx bundle;

	auto *session = rtp_session_new(RTP_SESSION_SENDRECV);
	bundle.addSession("main", session);

	BC_ASSERT_TRUE(bundle.findSession(session));
	BC_ASSERT_STRING_EQUAL(bundle.getSessionMid(session).c_str(), "main");

	auto *session2 = rtp_session_new(RTP_SESSION_SENDRECV);
	bundle.addSession("secondary", session2);

	BC_ASSERT_TRUE(bundle.findSession(session2));
	BC_ASSERT_STRING_EQUAL(bundle.getSessionMid(session2).c_str(), "secondary");

	auto *session3 = rtp_session_new(RTP_SESSION_SENDONLY);
	bundle.addSession("secondary", session3);

	BC_ASSERT_TRUE(bundle.findSession(session3));
	BC_ASSERT_STRING_EQUAL(bundle.getSessionMid(session3).c_str(), "secondary");

	bundle.removeSession(session);

	BC_ASSERT_FALSE(bundle.findSession(session));
	BC_ASSERT_PTR_NULL(bundle.getPrimarySession());

	bundle.removeSessions("secondary");

	BC_ASSERT_FALSE(bundle.findSession(session2));
	BC_ASSERT_FALSE(bundle.findSession(session3));

	rtp_session_destroy(session);
	rtp_session_destroy(session2);
	rtp_session_destroy(session3);
}

static void primary_change() {
	RtpBundleCxx bundle;

	auto *session = rtp_session_new(RTP_SESSION_SENDRECV);
	bundle.addSession("main", session);

	BC_ASSERT_PTR_EQUAL(bundle.getPrimarySession(), session);

	auto *newSession = rtp_session_new(RTP_SESSION_SENDRECV);
	bundle.addSession("main2", newSession);

	BC_ASSERT_PTR_EQUAL(bundle.getPrimarySession(), session);

	bundle.setPrimarySession(newSession);

	BC_ASSERT_PTR_EQUAL(bundle.getPrimarySession(), newSession);

	bundle.clear();

	rtp_session_destroy(session);
	rtp_session_destroy(newSession);
}

static void dispatch_packet() {
	RtpBundleCxx bundle;

	RtpProfile profile = {};
	rtp_profile_set_payload(&profile, 90, &payload_type_opus);

	auto *session = rtp_session_new(RTP_SESSION_SENDRECV);
	rtp_session_set_recv_profile(session, &profile);

	// Add a session that already knows it's ssrc.
	bundle.addSession("main", session);

	RtpProfile profile2 = {};
	rtp_profile_set_payload(&profile2, 96, &payload_type_vp8);

	auto *session2 = rtp_session_new(RTP_SESSION_SENDRECV);
	rtp_session_set_recv_profile(session2, &profile2);

	// Add a session that do not know it's ssrc yet.
	bundle.addSession("secondary", session2);

	// Using the wanted session to create the packet and automatically add the correct mid.
	auto packet = rtp_session_create_packet_header(session, 0);
	rtp_set_payload_type(packet, 90);
	rtp_set_ssrc(packet, 1021991);

	// That packet should not be dispatched as it for the primary session.
	BC_ASSERT_FALSE(bundle.dispatch(true, packet));
	BC_ASSERT_EQUAL(session->rtp.gs.bundleq.q_mcount, 0, int, "%d");

	freemsg(packet);

	packet = rtp_session_create_packet_header(session2, 0);
	rtp_set_payload_type(packet, 96);
	rtp_set_ssrc(packet, 18173254);

	// That packet should be dispatched and present in the bundleq.
	BC_ASSERT_TRUE(bundle.dispatch(true, packet));
	BC_ASSERT_EQUAL(session2->rtp.gs.bundleq.q_mcount, 1, int, "%d");

	// And the session should now know it's recv ssrc.
	BC_ASSERT_TRUE(session2->ssrc_set);
	BC_ASSERT_EQUAL(session2->rcv.ssrc, 18173254, uint32_t, "%d");

	packet = rtp_session_create_packet_header(session, 0);
	rtp_set_payload_type(packet, 96);
	rtp_set_ssrc(packet, 78986545);

	// That packet has an unkown ssrc, it should be marked has dispatched but is freed and no session received it.
	BC_ASSERT_TRUE(bundle.dispatch(true, packet));
	BC_ASSERT_EQUAL(session->rtp.gs.bundleq.q_mcount, 0, int, "%d");
	BC_ASSERT_EQUAL(session2->rtp.gs.bundleq.q_mcount, 1, int, "%d");

	bundle.clear();

	rtp_session_destroy(session);
	rtp_session_destroy(session2);
}

static void dispatch_packet_without_mid() {
	RtpBundleCxx bundle;

	auto *session = rtp_session_new(RTP_SESSION_SENDRECV);

	bundle.addSession("main", session);

	RtpProfile profile = {};
	rtp_profile_set_payload(&profile, 96, &payload_type_vp8);

	auto *session2 = rtp_session_new(RTP_SESSION_SENDRECV);
	rtp_session_set_recv_profile(session2, &profile);

	// Send a first packet with the mid that we'll use for session2.
	auto *packet = rtp_session_create_packet_header(session2, 0);
	rtp_set_payload_type(packet, 96);
	rtp_set_ssrc(packet, 18173254);

	auto *mid = "secondary";
	rtp_add_extension_header(packet, RTP_EXTENSION_MID, strlen(mid), (uint8_t *)mid);

	// That packet should marked as dispatched but freed because the session isn't in the bundle.
	BC_ASSERT_TRUE(bundle.dispatch(true, packet));
	BC_ASSERT_EQUAL(session->rtp.gs.bundleq.q_mcount, 0, int, "%d");
	BC_ASSERT_EQUAL(session2->rtp.gs.bundleq.q_mcount, 0, int, "%d");

	// Now we add our session.
	bundle.addSession("secondary", session2);

	// Creating a new packet but removing the mid to make sure it isn't there.
	// Since the bundle now knows that this ssrc has the mid "secondary" it should correctly assign the, now added,
	// session.
	packet = rtp_session_create_packet_header(session2, 0);
	rtp_set_payload_type(packet, 96);
	rtp_set_ssrc(packet, 18173254);

	rtp_delete_extension_header(packet, RTP_EXTENSION_MID);

	// That packet should be dispatched and present in bundleq.
	BC_ASSERT_TRUE(bundle.dispatch(true, packet));
	BC_ASSERT_EQUAL(session2->rtp.gs.bundleq.q_mcount, 1, int, "%d");

	bundle.clear();

	rtp_session_destroy(session);
	rtp_session_destroy(session2);
}

static void dispatch_rtcp_packet_with_referred_ssrc() {
	RtpBundleCxx bundle;

	auto *session = rtp_session_new(RTP_SESSION_SENDRECV);
	session->ssrc_set = TRUE;
	session->rcv.ssrc = 1021991;
	bundle.addSession("main", session);

	// A SENDONLY session is already assigned as we know it's ssrc
	auto *session2 = rtp_session_new(RTP_SESSION_SENDONLY);
	bundle.addSession("secondary", session2);

	RtpProfile profile2 = {};
	rtp_profile_set_payload(&profile2, 97, &payload_type_av1);

	auto *session3 = rtp_session_new(RTP_SESSION_SENDRECV);
	rtp_session_set_recv_profile(session3, &profile2);
	bundle.addSession("tertiary", session3);

	// Send a packet so that this session is assigned otherwise, referring won't work
	auto *packet = rtp_session_create_packet_header(session3, 0);
	rtp_set_payload_type(packet, 97);
	rtp_set_ssrc(packet, 22081992);

	BC_ASSERT_TRUE(bundle.dispatch(true, packet));
	BC_ASSERT_EQUAL(session3->rtp.gs.bundleq.q_mcount, 1, int, "%d");

	// Create a RTCP packet at destination of session but is referring session2
	auto *rtcpPacket = ortp_tester_make_dummy_rtcp_fb_pli(session, session->rcv.ssrc, session2->snd.ssrc);

	// Packet should be dispatched and in the RCTP bundle queue of session2
	BC_ASSERT_TRUE(bundle.dispatch(false, rtcpPacket));
	BC_ASSERT_EQUAL(session->rtcp.gs.bundleq.q_mcount, 0, int, "%d");
	BC_ASSERT_EQUAL(session2->rtcp.gs.bundleq.q_mcount, 1, int, "%d");
	BC_ASSERT_EQUAL(session3->rtcp.gs.bundleq.q_mcount, 0, int, "%d");

	// Create another RTCP packet at destination of session but is referring session3
	rtcpPacket = ortp_tester_make_dummy_rtcp_fb_pli(session, session->rcv.ssrc, session3->snd.ssrc);

	// Packet should be dispatched and in the RCTP bundle queue of session3
	BC_ASSERT_TRUE(bundle.dispatch(false, rtcpPacket));
	BC_ASSERT_EQUAL(session->rtcp.gs.bundleq.q_mcount, 0, int, "%d");
	BC_ASSERT_EQUAL(session2->rtcp.gs.bundleq.q_mcount, 1, int, "%d");
	BC_ASSERT_EQUAL(session3->rtcp.gs.bundleq.q_mcount, 1, int, "%d");

	bundle.clear();

	rtp_session_destroy(session);
	rtp_session_destroy(session2);
	rtp_session_destroy(session3);
}

static void on_incoming_ssrc_in_bundle(BCTBX_UNUSED(RtpSession *session), void *mp, void *s, void *userData) {
	const auto *m = static_cast<mblk_t *>(mp);

	uint8_t *data;
	const size_t midSize = rtp_get_extension_header(m, RTP_EXTENSION_MID, &data);
	BC_ASSERT_GREATER(midSize, 0, size_t, "%zu");

	const auto mid = std::string{reinterpret_cast<char *>(data), midSize};
	BC_ASSERT_STRING_EQUAL(mid.c_str(), "secondary");

	auto **newSessionForBundle = static_cast<RtpSession **>(s);
	auto **newSession = static_cast<RtpSession **>(userData);

	*newSessionForBundle = *newSession = rtp_session_new(RTP_SESSION_SENDRECV);
}

static void dispatch_new_ssrc_with_incoming_callback_set() {
	RtpBundleCxx bundle;

	auto *session = rtp_session_new(RTP_SESSION_SENDRECV);
	bundle.addSession("main", session);

	auto *session2 = rtp_session_new(RTP_SESSION_SENDRECV);
	bundle.addSession("secondary", session2);

	// Set the incoming ssrc callback into the bundle primary session.
	auto *primary = bundle.getPrimarySession();
	BC_ASSERT_PTR_EQUAL(primary, session);

	RtpSession *newSession = nullptr;
	rtp_session_signal_connect(primary, "new_incoming_ssrc_found_in_bundle", on_incoming_ssrc_in_bundle, &newSession);

	// Send a packet with the "secondary" mid but another ssrc.
	auto *packet = rtp_session_create_packet_header(session2, 0);
	rtp_set_ssrc(packet, 36587422);

	BC_ASSERT_TRUE(bundle.dispatch(true, packet));

	// The callback should have been called and set newSession to the new session created.
	if (BC_ASSERT_PTR_NOT_NULL(newSession)) {
		BC_ASSERT_TRUE(bundle.findSession(newSession));
		BC_ASSERT_TRUE(newSession->ssrc_set);
		BC_ASSERT_EQUAL(newSession->rcv.ssrc, 36587422, uint32_t, "%u");
		BC_ASSERT_EQUAL(newSession->rtp.gs.bundleq.q_mcount, 1, int, "%d");
	}

	rtp_session_signal_disconnect_by_callback(primary, "new_incoming_ssrc_found_in_bundle", on_incoming_ssrc_in_bundle);

	bundle.clear();

	rtp_session_destroy(session);
	rtp_session_destroy(session2);
	if (newSession != nullptr) rtp_session_destroy(newSession);
}

static void look_out_for_outgoing_session() {
	RtpBundleCxx bundle;

	auto *session = rtp_session_new(RTP_SESSION_SENDRECV);
	bundle.addSession("main", session);

	auto *session2 = rtp_session_new(RTP_SESSION_SENDONLY);
	bundle.addSession("secondary", session2);

	// Create a packet with "secondary" mid and session2 sender.
	auto *packet = rtp_session_create_packet_header(session2, 0);

	// checkForSession should return the session2.
	BC_ASSERT_PTR_EQUAL(bundle.checkForSession(packet, true, true), session2);

	freemsg(packet);

	bundle.clear();

	rtp_session_destroy(session);
	rtp_session_destroy(session2);
}

static void on_outgoing_ssrc_in_bundle(BCTBX_UNUSED(RtpSession *session), void *mp, void *s, void *userData) {
	const auto *m = static_cast<mblk_t *>(mp);

	uint8_t *data;
	const size_t midSize = rtp_get_extension_header(m, RTP_EXTENSION_MID, &data);
	BC_ASSERT_GREATER(midSize, 0, size_t, "%zu");

	const auto mid = std::string{reinterpret_cast<char *>(data), midSize};
	BC_ASSERT_STRING_EQUAL(mid.c_str(), "secondary");

	auto **newSessionForBundle = static_cast<RtpSession **>(s);
	auto **newSession = static_cast<RtpSession **>(userData);

	*newSessionForBundle = *newSession = rtp_session_new(RTP_SESSION_SENDONLY);
}

static void look_out_for_outgoing_session_with_outgoing_callback_set() {
	RtpBundleCxx bundle;

	auto *session = rtp_session_new(RTP_SESSION_SENDRECV);
	bundle.addSession("main", session);

	auto *session2 = rtp_session_new(RTP_SESSION_SENDONLY);
	bundle.addSession("secondary", session2);

	// Set the outgoing ssrc onto the bundle primary session
	auto *primary = bundle.getPrimarySession();
	BC_ASSERT_PTR_EQUAL(primary, session);

	RtpSession *newSession = nullptr;
	rtp_session_signal_connect(primary, "new_outgoing_ssrc_found_in_bundle", on_outgoing_ssrc_in_bundle, &newSession);

	// Send a packet with the "secondary" mid but another ssrc.
	auto *packet = rtp_session_create_packet_header(session2, 0);
	rtp_set_ssrc(packet, 36587422);

	// checkForSession should return the new session.
	const auto *returnedSession = bundle.checkForSession(packet, true, true);

	BC_ASSERT_PTR_NOT_NULL(newSession);
	BC_ASSERT_PTR_EQUAL(returnedSession, newSession);

	rtp_session_signal_disconnect_by_callback(primary, "new_outgoing_ssrc_found_in_bundle", on_outgoing_ssrc_in_bundle);

	freemsg(packet);

	bundle.clear();

	rtp_session_destroy(session);
	rtp_session_destroy(session2);
	if (newSession != nullptr) rtp_session_destroy(newSession);
}

static test_t tests[] = {
    TEST_NO_TAG("Add sessions", add_sessions),
    TEST_NO_TAG("Primary change", primary_change),
    TEST_NO_TAG("Dispatch packet", dispatch_packet),
    TEST_NO_TAG("Dispatch packet without mid", dispatch_packet_without_mid),
    TEST_NO_TAG("Dispatch RTCP packet with referred SSRC", dispatch_rtcp_packet_with_referred_ssrc),
    TEST_NO_TAG("Dispatch new SSRC with incoming callback set", dispatch_new_ssrc_with_incoming_callback_set),
    TEST_NO_TAG("Look for outgoing session", look_out_for_outgoing_session),
    TEST_NO_TAG("Look for outgoing session with outgoing callback set",
                look_out_for_outgoing_session_with_outgoing_callback_set),
};

test_suite_t bundle_test_suite = {
    "Bundle",         // Name of test suite
    nullptr,          // Before all callback
    nullptr,          // After all callback
    nullptr,          // Before each callback
    nullptr,          // After each callback
    std::size(tests), // Size of test table
    tests,            // Table of test suite
    0                 // Average execution time
};