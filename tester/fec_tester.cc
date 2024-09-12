
#include "fecstream/fec-stream-stats.h"
#include "fecstream/fecstream.h"
#include "ortp_tester.h"
#include <numeric>

using namespace ortp;

static mblk_t *
newPacketWithLetter(struct _RtpSession *session, int seqnum, uint32_t timestamp, uint8_t car, size_t packet_size) {
	mblk_t *packet = NULL;
	packet = rtp_session_create_packet_header(session, packet_size); // reserve packet_size after the header
	memset(packet->b_wptr, car, packet_size);
	packet->b_wptr += packet_size;
	rtp_set_seqnumber(packet, seqnum);
	rtp_set_timestamp(packet, timestamp);
	return packet;
}

static bool_t compare_sizes(mblk_t *ma, mblk_t *mb) {
	size_t sizea = msgdsize(ma);
	size_t sizeb = msgdsize(mb);
	return sizea == sizeb;
}

static bool_t compare_header_fields(mblk_t *ma, mblk_t *mb) {

	uint16_t cc = rtp_get_cc(ma);
	uint16_t ext = rtp_get_extbit(ma);

	return (rtp_get_version(ma) == rtp_get_version(mb)) && (rtp_get_padbit(ma) == rtp_get_padbit(mb)) &&
	       (cc == rtp_get_cc(mb)) && (ext == rtp_get_extbit(mb)) && (rtp_get_markbit(ma) == rtp_get_markbit(mb)) &&
	       (rtp_get_payload_type(ma) == rtp_get_payload_type(mb)) && (rtp_get_seqnumber(ma) == rtp_get_seqnumber(mb)) &&
	       (rtp_get_ssrc(ma) == rtp_get_ssrc(mb));
}

static bool_t compare_csrc_fields(mblk_t *ma, mblk_t *mb) {
	uint16_t cc = rtp_get_cc(ma);
	if (cc != rtp_get_cc(mb)) return FALSE;
	for (uint8_t i = 0; i < cc; i++) {
		if (rtp_get_csrc(ma, i) != rtp_get_csrc(mb, i)) return FALSE;
	}
	return TRUE;
}

static bool_t compare_ext_headers(mblk_t *ma, mblk_t *mb) {
	uint8_t *data_ext_a = NULL;
	uint8_t *data_ext_b = NULL;
	uint16_t profile_ext_a, profile_ext_b;
	int size_ext_a, size_ext_b;
	uint16_t ext = rtp_get_extbit(ma);

	if (ext) {

		if (ext != rtp_get_extbit(mb)) return FALSE;

		size_ext_a = rtp_get_extheader(ma, &profile_ext_a, &data_ext_a);
		size_ext_b = rtp_get_extheader(mb, &profile_ext_b, &data_ext_b);
		if (size_ext_a != size_ext_b) return FALSE;
		if (!((profile_ext_a == profile_ext_b) && (memcmp(data_ext_a, data_ext_b, size_ext_a) == 0))) return FALSE;
	}
	return TRUE;
}

static bool_t compare_payloads(mblk_t *ma, mblk_t *mb) {
	uint8_t *payload_a = NULL;
	uint8_t *payload_b = NULL;
	int size_payload_a, size_payload_b;

	size_payload_a = rtp_get_payload(ma, &payload_a);
	size_payload_b = rtp_get_payload(mb, &payload_b);
	if (size_payload_a != size_payload_b) return FALSE;
	if (memcmp(payload_a, payload_b, size_payload_a) != 0) return FALSE;
	return TRUE;
}

static bool_t packets_are_equals(mblk_t *ma, mblk_t *mb) {
	if (!compare_sizes(ma, mb)) return FALSE;
	if (!compare_header_fields(ma, mb)) return FALSE;
	if (!compare_csrc_fields(ma, mb)) return FALSE;
	if (!compare_ext_headers(ma, mb)) return FALSE;
	if (!compare_payloads(ma, mb)) return FALSE;
	return TRUE;
}

static void fec_params_update_test(void) {
	FecParamsController params(42);
	BC_ASSERT_EQUAL(params.getRepairWindow(), 42, uint32_t, "%u");

	BC_ASSERT_EQUAL(params.getL(), 0, int, "%d");
	BC_ASSERT_EQUAL(params.getD(), 0, int, "%d");
	BC_ASSERT_FALSE(params.is2D());
	BC_ASSERT_FALSE(params.getEnabled());

	params.updateParams(0);
	BC_ASSERT_EQUAL(params.getL(), 0, int, "%d");
	BC_ASSERT_EQUAL(params.getD(), 0, int, "%d");
	BC_ASSERT_FALSE(params.is2D());
	BC_ASSERT_FALSE(params.getEnabled());

	params.updateParams(1);
	BC_ASSERT_EQUAL(params.getL(), 10, int, "%d");
	BC_ASSERT_EQUAL(params.getD(), 0, int, "%d");
	BC_ASSERT_FALSE(params.is2D());
	BC_ASSERT_TRUE(params.getEnabled());

	params.updateParams(2);
	BC_ASSERT_EQUAL(params.getL(), 5, int, "%d");
	BC_ASSERT_EQUAL(params.getD(), 5, int, "%d");
	BC_ASSERT_FALSE(params.is2D());
	BC_ASSERT_TRUE(params.getEnabled());

	params.updateParams(3);
	BC_ASSERT_EQUAL(params.getL(), 5, int, "%d");
	BC_ASSERT_EQUAL(params.getD(), 5, int, "%d");
	BC_ASSERT_TRUE(params.is2D());
	BC_ASSERT_TRUE(params.getEnabled());

	params.updateParams(4);
	BC_ASSERT_EQUAL(params.getL(), 4, int, "%d");
	BC_ASSERT_EQUAL(params.getD(), 4, int, "%d");
	BC_ASSERT_TRUE(params.is2D());
	BC_ASSERT_TRUE(params.getEnabled());

	params.updateParams(5);
	BC_ASSERT_EQUAL(params.getL(), 3, int, "%d");
	BC_ASSERT_EQUAL(params.getD(), 3, int, "%d");
	BC_ASSERT_TRUE(params.is2D());
	BC_ASSERT_TRUE(params.getEnabled());

	// this FEC level doesn't exist, the parameters are unchanged
	params.updateParams(42);
	BC_ASSERT_EQUAL(params.getL(), 3, int, "%d");
	BC_ASSERT_EQUAL(params.getD(), 3, int, "%d");
	BC_ASSERT_TRUE(params.is2D());
	BC_ASSERT_TRUE(params.getEnabled());
}

static void fec_params_level_test(void) {
	FecParamsController params(200000);
	float eps = 0.000001;

	// check the thresholds of loss rates the find the best fec level, for the cases with low, medium and high
	// bandwidth available, when the measurement of the current overhead is 0
	float crt_ov = 0.;
	float new_ov = 0;
	int low_bw = 10000;
	BC_ASSERT_EQUAL(params.estimateBestLevel(2.9, low_bw, crt_ov, &new_ov), 0, int, "%d");
	BC_ASSERT_EQUAL(params.estimateBestLevel(3.1, low_bw, crt_ov, &new_ov), 1, int, "%d");
	BC_ASSERT_EQUAL(params.estimateBestLevel(4.6, low_bw, crt_ov, &new_ov), 1, int, "%d");
	BC_ASSERT_EQUAL(params.estimateBestLevel(4.7, low_bw, crt_ov, &new_ov), 2, int, "%d");
	BC_ASSERT_EQUAL(params.estimateBestLevel(20.0, low_bw, crt_ov, &new_ov), 2, int, "%d");
	int med_bw = 200000;
	BC_ASSERT_EQUAL(params.estimateBestLevel(0.4, med_bw, crt_ov, &new_ov), 0, int, "%d");
	BC_ASSERT_EQUAL(params.estimateBestLevel(0.6, med_bw, crt_ov, &new_ov), 1, int, "%d");
	BC_ASSERT_EQUAL(params.estimateBestLevel(1.2, med_bw, crt_ov, &new_ov), 1, int, "%d");
	BC_ASSERT_EQUAL(params.estimateBestLevel(1.4, med_bw, crt_ov, &new_ov), 2, int, "%d");
	BC_ASSERT_EQUAL(params.estimateBestLevel(20.0, med_bw, crt_ov, &new_ov), 2, int, "%d");
	int high_bw = 400000;
	BC_ASSERT_EQUAL(params.estimateBestLevel(0., high_bw, crt_ov, &new_ov), 1, int, "%d");
	BC_ASSERT_EQUAL(params.estimateBestLevel(0.17, high_bw, crt_ov, &new_ov), 1, int, "%d");
	BC_ASSERT_EQUAL(params.estimateBestLevel(0.18, high_bw, crt_ov, &new_ov), 2, int, "%d");
	BC_ASSERT_EQUAL(params.estimateBestLevel(0.51, high_bw, crt_ov, &new_ov), 2, int, "%d");
	BC_ASSERT_EQUAL(params.estimateBestLevel(0.53, high_bw, crt_ov, &new_ov), 3, int, "%d");
	BC_ASSERT_EQUAL(params.estimateBestLevel(20.0, high_bw, crt_ov, &new_ov), 3, int, "%d");

	// check that the best FEC level is 0 when the loss rate is too high
	BC_ASSERT_EQUAL(params.estimateBestLevel(20.1, low_bw, crt_ov, &new_ov), 0, int, "%d");
	BC_ASSERT_EQUAL(params.estimateBestLevel(20.1, med_bw, crt_ov, &new_ov), 0, int, "%d");
	BC_ASSERT_EQUAL(params.estimateBestLevel(20.1, high_bw, crt_ov, &new_ov), 0, int, "%d");

	// check the value of the estimated overhead when the measurement of the current overhead is 0
	float overhead_factor = 2.;
	params.estimateBestLevel(0., high_bw, crt_ov, &new_ov);
	BC_ASSERT_EQUAL(new_ov, overhead_factor * 0.1, float, "%f");
	params.estimateBestLevel(0.2, high_bw, crt_ov, &new_ov);
	BC_ASSERT_EQUAL(new_ov, overhead_factor * 0.2, float, "%f");
	params.estimateBestLevel(0.6, high_bw, crt_ov, &new_ov);
	BC_ASSERT_EQUAL(new_ov, overhead_factor * 0.4, float, "%f");
	params.estimateBestLevel(0.75, high_bw, crt_ov, &new_ov);
	BC_ASSERT_EQUAL(new_ov, overhead_factor * 0.4, float, "%f");
	params.estimateBestLevel(2.0, high_bw, crt_ov, &new_ov);
	BC_ASSERT_EQUAL(new_ov, overhead_factor * 0.4, float, "%f");

	// check the fec level and the estimated overhead when it is not necessary to reduce the fec level
	crt_ov = 0.5;
	params.updateParams(3);
	BC_ASSERT_EQUAL(params.estimateBestLevel(0., high_bw, crt_ov, &new_ov), 1, int, "%d");
	BC_ASSERT_EQUAL(new_ov, 0.1 / 0.4 * crt_ov, float, "%f");
	BC_ASSERT_EQUAL(params.estimateBestLevel(0.4, high_bw, crt_ov, &new_ov), 2, int, "%d");
	BC_ASSERT_EQUAL(new_ov, 0.2 / 0.4 * crt_ov, float, "%f");
	BC_ASSERT_EQUAL(params.estimateBestLevel(0.7, high_bw, crt_ov, &new_ov), 3, int, "%d");
	BC_ASSERT_EQUAL(new_ov, 0.4 / 0.4 * crt_ov, float, "%f");
	BC_ASSERT_EQUAL(params.estimateBestLevel(0.8, high_bw, crt_ov, &new_ov), 4, int, "%d");
	BC_ASSERT_EQUAL(new_ov, 0.5 / 0.4 * crt_ov, float, "%f");
	BC_ASSERT_EQUAL(params.estimateBestLevel(1.2, high_bw, crt_ov, &new_ov), 5, int, "%d");
	BC_ASSERT_TRUE((new_ov < 2. / 3. / 0.4 * crt_ov + eps) && (new_ov > 2. / 3. / 0.4 * crt_ov - eps));

	// check the range of loss rates when the FEC level doesn't  change, with theortical overhead value
	params.updateParams(2);
	crt_ov = 0.2;
	BC_ASSERT_EQUAL(params.estimateBestLevel(2.8, med_bw, crt_ov, &new_ov), 2, int, "%d");
	BC_ASSERT_EQUAL(new_ov, crt_ov, float, "%f");
	BC_ASSERT_EQUAL(params.estimateBestLevel(0.4, high_bw, crt_ov, &new_ov), 2, int, "%d");
	BC_ASSERT_EQUAL(new_ov, crt_ov, float, "%f");
	params.updateParams(3);
	crt_ov = 0.4;
	BC_ASSERT_EQUAL(params.estimateBestLevel(2.9, med_bw, crt_ov, &new_ov), 3, int, "%d");
	BC_ASSERT_EQUAL(new_ov, crt_ov, float, "%f");
	BC_ASSERT_EQUAL(params.estimateBestLevel(3.6, med_bw, crt_ov, &new_ov), 3, int, "%d");
	BC_ASSERT_EQUAL(new_ov, crt_ov, float, "%f");
	BC_ASSERT_EQUAL(params.estimateBestLevel(0.53, high_bw, crt_ov, &new_ov), 3, int, "%d");
	BC_ASSERT_EQUAL(new_ov, crt_ov, float, "%f");
	BC_ASSERT_EQUAL(params.estimateBestLevel(0.69, high_bw, crt_ov, &new_ov), 3, int, "%d");
	BC_ASSERT_EQUAL(new_ov, crt_ov, float, "%f");
	params.updateParams(4);
	crt_ov = 0.5;
	BC_ASSERT_EQUAL(params.estimateBestLevel(3.7, med_bw, crt_ov, &new_ov), 4, int, "%d");
	BC_ASSERT_EQUAL(new_ov, crt_ov, float, "%f");
	BC_ASSERT_EQUAL(params.estimateBestLevel(4.9, med_bw, crt_ov, &new_ov), 4, int, "%d");
	BC_ASSERT_EQUAL(new_ov, crt_ov, float, "%f");
	BC_ASSERT_EQUAL(params.estimateBestLevel(0.75, high_bw, crt_ov, &new_ov), 4, int, "%d");
	BC_ASSERT_EQUAL(new_ov, crt_ov, float, "%f");
	BC_ASSERT_EQUAL(params.estimateBestLevel(0.99, high_bw, crt_ov, &new_ov), 4, int, "%d");
	BC_ASSERT_EQUAL(new_ov, crt_ov, float, "%f");
	params.updateParams(5);
	crt_ov = 2. / 3.;
	BC_ASSERT_EQUAL(params.estimateBestLevel(5.0, med_bw, crt_ov, &new_ov), 5, int, "%d");
	BC_ASSERT_EQUAL(new_ov, crt_ov, float, "%f");
	BC_ASSERT_EQUAL(params.estimateBestLevel(20., med_bw, crt_ov, &new_ov), 5, int, "%d");
	BC_ASSERT_EQUAL(new_ov, crt_ov, float, "%f");
	BC_ASSERT_EQUAL(params.estimateBestLevel(1.0, high_bw, crt_ov, &new_ov), 5, int, "%d");
	BC_ASSERT_EQUAL(new_ov, crt_ov, float, "%f");
	BC_ASSERT_EQUAL(params.estimateBestLevel(20., high_bw, crt_ov, &new_ov), 5, int, "%d");
	BC_ASSERT_EQUAL(new_ov, crt_ov, float, "%f");

	// check the fec level and the estimated overhead when it is necessary to reduce the fec level to reduce the
	// overhead
	params.updateParams(5);
	crt_ov = 1.1;
	BC_ASSERT_EQUAL(params.estimateBestLevel(6., high_bw, crt_ov, &new_ov), 4, int, "%d");
	float expected_ov = 0.5 * 3. / 2. * crt_ov;
	BC_ASSERT_TRUE((new_ov < expected_ov + eps) && (new_ov > expected_ov - eps));
	crt_ov = 1.4;
	BC_ASSERT_EQUAL(params.estimateBestLevel(6., high_bw, crt_ov, &new_ov), 3, int, "%d");
	expected_ov = 0.4 * 3. / 2. * crt_ov;
	BC_ASSERT_TRUE((new_ov < expected_ov + eps) && (new_ov > expected_ov - eps));
	crt_ov = 2.9;
	BC_ASSERT_EQUAL(params.estimateBestLevel(6., high_bw, crt_ov, &new_ov), 2, int, "%d");
	expected_ov = 0.2 * 3. / 2. * crt_ov;
	BC_ASSERT_TRUE((new_ov < expected_ov + eps) && (new_ov > expected_ov - eps));
	crt_ov = 5.9;
	BC_ASSERT_EQUAL(params.estimateBestLevel(6., high_bw, crt_ov, &new_ov), 1, int, "%d");
	expected_ov = 0.1 * 3. / 2. * crt_ov;
	BC_ASSERT_TRUE((new_ov < expected_ov + eps) && (new_ov > expected_ov - eps));
	crt_ov = 5.9;
	BC_ASSERT_EQUAL(params.estimateBestLevel(6., high_bw, crt_ov, &new_ov), 1, int, "%d");
	expected_ov = 0.1 * 3. / 2. * crt_ov;
	BC_ASSERT_TRUE((new_ov < expected_ov + eps) && (new_ov > expected_ov - eps));
	crt_ov = 6.1;
	BC_ASSERT_EQUAL(params.estimateBestLevel(6., high_bw, crt_ov, &new_ov), 0, int, "%d");
	BC_ASSERT_EQUAL(new_ov, 0., float, "%f");

	// check that fec parameters haven't changed
	BC_ASSERT_EQUAL(params.getL(), 3, int, "%d");
	BC_ASSERT_EQUAL(params.getD(), 3, int, "%d");
	BC_ASSERT_TRUE(params.getEnabled());
	BC_ASSERT_TRUE(params.is2D());
}

static void bitstring_add_test(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	rtp_session_set_payload_type(session, 98);
	mblk_t *packetA = newPacketWithLetter(session, 0, 123456, 'a', 150);
	mblk_t *packetB = newPacketWithLetter(session, 1, 456789, 'b', 160);

	Bitstring bsA(packetA);
	Bitstring bsB(packetB);
	BC_ASSERT_EQUAL(bsA.getTimestamp(), 123456, uint32_t, "%u");
	BC_ASSERT_EQUAL(bsB.getTimestamp(), 456789, uint32_t, "%u");
	BC_ASSERT_EQUAL(bsA.getLength(), 150, uint32_t, "%u");
	BC_ASSERT_EQUAL(bsB.getLength(), 160, uint32_t, "%u");

	bsA.add(bsB);
	uint16_t header = bsA.getHeader();
	uint16_t expectedHeader = 0;
	int expectedTs = (123456 ^ 456789);
	int expectedLength = (150 ^ 160);

	BC_ASSERT_EQUAL(header, expectedHeader, uint16_t, "%d");
	BC_ASSERT_EQUAL(bsA.getLength(), expectedLength, int, "%d");
	BC_ASSERT_EQUAL(bsA.getTimestamp(), expectedTs, int, "%d");

	freemsg(packetA);
	freemsg(packetB);
	rtp_session_destroy(session);
}

static void source_packet_get_payload_test(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	rtp_session_set_payload_type(session, 98);
	uint8_t *rptr = NULL;
	mblk_t *packetA = newPacketWithLetter(session, 0, 123456, 'a', 150);
	FecSourcePacket pA(packetA);
	size_t sizeA = pA.getPayloadBuffer(&rptr);

	BC_ASSERT_EQUAL(sizeA, 150, size_t, "%zu");

	rtp_session_destroy(session);
}

static void source_packet_add_payload_test1(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	rtp_session_set_payload_type(session, 98);
	uint8_t *rptr = NULL;
	mblk_t *packetA = newPacketWithLetter(session, 0, 123456, 'a', 150);
	mblk_t *packetB = newPacketWithLetter(session, 0, 456789, 'a', 150);

	FecSourcePacket pA(packetA);
	FecSourcePacket pB(packetB);

	pA.addPayload(pB);
	uint8_t expectedPayload[150] = {0};

	size_t sizeA = pA.getPayloadBuffer(&rptr);
	BC_ASSERT_EQUAL(sizeA, 150, size_t, "%zu");
	BC_ASSERT_TRUE(memcmp(rptr, expectedPayload, sizeA) == 0);

	rtp_session_destroy(session);
}

static void source_packet_add_payload_test2(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	rtp_session_set_payload_type(session, 98);
	uint8_t *rptr = NULL;
	mblk_t *packetA = newPacketWithLetter(session, 0, 123456, 'a', 150);
	mblk_t *packetB = newPacketWithLetter(session, 0, 456789, 'b', 180);

	FecSourcePacket pA(packetA);
	FecSourcePacket pB(packetB);

	pA.addPayload(pB);
	uint8_t expectedPayload[150] = {0};
	for (int i = 0; i < 150; i++) {
		expectedPayload[i] = 'a' ^ 'b';
	}

	size_t sizeA = pA.getPayloadBuffer(&rptr);
	BC_ASSERT_EQUAL(sizeA, 150, size_t, "%zu");
	BC_ASSERT_TRUE(memcmp(rptr, expectedPayload, sizeA) == 0);

	rtp_session_destroy(session);
}

static void source_packet_add_payload_test3(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	rtp_session_set_payload_type(session, 98);
	uint8_t *rptr = NULL;
	mblk_t *packetA = newPacketWithLetter(session, 0, 123456, 'a', 150);
	mblk_t *packetB = newPacketWithLetter(session, 0, 456789, 'b', 120);

	FecSourcePacket pA(packetA);
	FecSourcePacket pB(packetB);

	pA.addPayload(pB);
	uint8_t expectedPayload[180] = {0};
	for (int i = 0; i < 180; i++) {
		if (i < 120) expectedPayload[i] = 'a' ^ 'b';
		else expectedPayload[i] = 'a';
	}

	size_t sizeA = pA.getPayloadBuffer(&rptr);
	BC_ASSERT_EQUAL(sizeA, 150, size_t, "%zu");
	BC_ASSERT_TRUE(memcmp(rptr, expectedPayload, sizeA) == 0);

	rtp_session_destroy(session);
}

static void repair_packet_bitstring_test(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	mblk_t *packetA = newPacketWithLetter(session, 0, 123456, 'a', 150);

	FecSourcePacket sourceA(packetA);
	FecRepairPacket repair(session, session, 0, 5, 0);

	auto bsA = sourceA.getBitstring();
	repair.addBitstring(bsA);
	auto extracted = repair.extractBitstring();

	BC_ASSERT_EQUAL(extracted.getHeader(), bsA.getHeader(), uint16_t, "%d");
	BC_ASSERT_EQUAL(extracted.getLength(), bsA.getLength(), uint16_t, "%d");
	BC_ASSERT_EQUAL(extracted.getTimestamp(), bsA.getTimestamp(), uint32_t, "%d");

	rtp_session_destroy(session);
}

static void repair_packet_add_payload1(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	rtp_session_set_payload_type(session, 98);

	mblk_t *packetA = newPacketWithLetter(session, 0, 123456, 'a', 150);
	FecSourcePacket sourceA(packetA);
	FecRepairPacket repair(session, session, 0, 5, 1);

	repair.addPayload(sourceA);
	uint8_t *expectedBuffer = NULL;
	uint8_t *buffer = NULL;
	size_t expectedSize = sourceA.getPayloadBuffer(&expectedBuffer);
	size_t size = repair.repairPayloadStart(&buffer);

	BC_ASSERT_EQUAL(size, expectedSize, size_t, "%zu");
	BC_ASSERT_TRUE(memcmp(buffer, expectedBuffer, size) == 0);

	rtp_session_destroy(session);
}

static void repair_packet_seqnumListNonInterleaved_test(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	{
		uint8_t L = 3;
		uint8_t D = 0;
		FecRepairPacket repair(session, session, 0, L, D);
		auto liste = repair.createSequenceNumberList();
		BC_ASSERT_EQUAL(liste.size(), 3, size_t, "%zu");
		for (int i = 0; i < 3; i++) {
			BC_ASSERT_EQUAL(liste[i], i, uint16_t, "%u");
		}
		BC_ASSERT_EQUAL(repair.getL(), L, int, "%d");
		BC_ASSERT_EQUAL(repair.getD(), D, int, "%d");
	}
	{
		uint8_t L = 3;
		uint8_t D = 1;
		FecRepairPacket repair(session, session, 0, L, D);
		auto liste = repair.createSequenceNumberList();
		BC_ASSERT_EQUAL(liste.size(), 3, size_t, "%zu");
		for (int i = 0; i < 3; i++) {
			BC_ASSERT_EQUAL(liste[i], i, uint16_t, "%u");
		}
		BC_ASSERT_EQUAL(repair.getL(), L, int, "%d");
		BC_ASSERT_EQUAL(repair.getD(), D, int, "%d");
	}

	rtp_session_destroy(session);
}

static void repair_packet_seqnumListInterleaved_test(void) {
	uint8_t L = 3;
	uint8_t D = 3;
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecRepairPacket repair(session, session, 0, L, D);
	auto liste = repair.createSequenceNumberList();
	BC_ASSERT_EQUAL(liste.size(), 3, size_t, "%zu");
	int seqnum = 0;
	for (int i = 0; i < 3; i++) {
		BC_ASSERT_EQUAL(liste[i], seqnum, uint16_t, "%u");
		seqnum += 3;
	}
	BC_ASSERT_EQUAL(repair.getL(), L, int, "%d");
	BC_ASSERT_EQUAL(repair.getD(), D, int, "%d");

	rtp_session_destroy(session);
}

static void encoder_init_1D_non_interleaved_test(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);

	FecParamsController params(200000);
	params.updateParams(1);
	FecEncoder encoder(&params);
	BC_ASSERT_TRUE(encoder.isEmpty());
	BC_ASSERT_FALSE(encoder.isFull());

	encoder.init(session, session);

	auto rowRepair0 = encoder.getRowRepair(0);
	BC_ASSERT_PTR_NOT_NULL(rowRepair0);
	if (rowRepair0) {
		BC_ASSERT_EQUAL(rowRepair0->getL(), 10, int, "%d");
		BC_ASSERT_EQUAL(rowRepair0->getD(), 0, int, "%d");
	}
	auto rowRepair1 = encoder.getRowRepair(1);
	BC_ASSERT_PTR_NULL(rowRepair1);
	auto colRepair = encoder.getColRepair(0);
	BC_ASSERT_PTR_NULL(colRepair);

	rtp_session_destroy(session);
}

static void encoder_init_1D_interleaved_test(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);

	FecParamsController params(200000);
	// params.updateParams(1);
	params.updateParams(2);
	FecEncoder encoder(&params);
	encoder.init(session, session);
	BC_ASSERT_TRUE(encoder.isEmpty());
	BC_ASSERT_FALSE(encoder.isFull());

	auto rowRepair0 = encoder.getRowRepair(0);
	BC_ASSERT_PTR_NULL(rowRepair0);
	for (int i = 0; i < 5; i++) {
		auto colRepair = encoder.getColRepair(i);
		BC_ASSERT_PTR_NOT_NULL(colRepair);
		if (colRepair) {
			BC_ASSERT_EQUAL(colRepair->getL(), 5, int, "%d");
			BC_ASSERT_EQUAL(colRepair->getD(), 5, int, "%d");
		}
	}
	auto colRepair5 = encoder.getColRepair(5);
	BC_ASSERT_PTR_NULL(colRepair5);
	rtp_session_destroy(session);
}

static void encoder_init_2D_test(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);

	FecParamsController params(200000);
	params.updateParams(3);
	FecEncoder encoder(&params);
	encoder.init(session, session);

	for (int i = 0; i < 5; i++) {
		auto rowRepair = encoder.getRowRepair(i);
		BC_ASSERT_PTR_NOT_NULL(rowRepair);
		if (rowRepair) {
			BC_ASSERT_EQUAL(rowRepair->getL(), 5, int, "%d");
			BC_ASSERT_EQUAL(rowRepair->getD(), 1, int, "%d");
		}
		auto colRepair = encoder.getColRepair(i);
		BC_ASSERT_PTR_NOT_NULL(colRepair);
		if (colRepair) {
			BC_ASSERT_EQUAL(colRepair->getL(), 5, int, "%d");
			BC_ASSERT_EQUAL(colRepair->getD(), 5, int, "%d");
		}
	}
	auto rowRepair5 = encoder.getRowRepair(5);
	BC_ASSERT_PTR_NULL(rowRepair5);
	auto colRepair5 = encoder.getColRepair(5);
	BC_ASSERT_PTR_NULL(colRepair5);
	rtp_session_destroy(session);
}

static void encoder_update_test(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecParamsController params(200000);
	params.updateParams(2);
	FecEncoder encoder(&params);
	encoder.init(session, session);
	encoder.update(5, 0, false);
	{
		BC_ASSERT_TRUE(encoder.isEmpty());
		BC_ASSERT_FALSE(encoder.isFull());
		auto rowRepair0 = encoder.getRowRepair(0);
		BC_ASSERT_PTR_NOT_NULL(rowRepair0);
		if (rowRepair0) {
			BC_ASSERT_EQUAL(rowRepair0->getL(), 5, int, "%d");
			BC_ASSERT_EQUAL(rowRepair0->getD(), 0, int, "%d");
		}
		auto rowRepair1 = encoder.getRowRepair(1);
		BC_ASSERT_PTR_NULL(rowRepair1);
		auto colRepair = encoder.getColRepair(0);
		BC_ASSERT_PTR_NULL(colRepair);
	}
	encoder.update(5, 10, false);
	{
		BC_ASSERT_TRUE(encoder.isEmpty());
		BC_ASSERT_FALSE(encoder.isFull());

		auto rowRepair0 = encoder.getRowRepair(0);
		BC_ASSERT_PTR_NULL(rowRepair0);
		for (int i = 0; i < 5; i++) {
			auto colRepair = encoder.getColRepair(i);
			BC_ASSERT_PTR_NOT_NULL(colRepair);
			if (colRepair) {
				BC_ASSERT_EQUAL(colRepair->getL(), 5, int, "%d");
				BC_ASSERT_EQUAL(colRepair->getD(), 10, int, "%d");
			}
		}
		auto colRepair5 = encoder.getColRepair(5);
		BC_ASSERT_PTR_NULL(colRepair5);
	}
	encoder.update(3, 4, true);
	{
		BC_ASSERT_TRUE(encoder.isEmpty());
		BC_ASSERT_FALSE(encoder.isFull());
		for (int i = 0; i < 4; i++) {
			auto rowRepair = encoder.getRowRepair(i);
			BC_ASSERT_PTR_NOT_NULL(rowRepair);
			if (rowRepair) {
				BC_ASSERT_EQUAL(rowRepair->getL(), 3, int, "%d");
				BC_ASSERT_EQUAL(rowRepair->getD(), 1, int, "%d");
			}
		}
		auto rowRepair4 = encoder.getRowRepair(4);
		BC_ASSERT_PTR_NULL(rowRepair4);
		for (int i = 0; i < 3; i++) {
			auto colRepair = encoder.getColRepair(i);
			BC_ASSERT_PTR_NOT_NULL(colRepair);
			if (colRepair) {
				BC_ASSERT_EQUAL(colRepair->getL(), 3, int, "%d");
				BC_ASSERT_EQUAL(colRepair->getD(), 4, int, "%d");
			}
		}
		auto colRepair3 = encoder.getColRepair(3);
		BC_ASSERT_PTR_NULL(colRepair3);
	}
	rtp_session_destroy(session);
}

static void encoder_add_1D_test(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecParamsController params(200000);
	params.updateParams(1);
	FecEncoder encoder(&params);
	encoder.init(session, session);
	uint8_t *sourcePayload = NULL;
	uint8_t *repairPayload = NULL;
	mblk_t *packet = newPacketWithLetter(session, 0, 123456, 'a', 150);
	FecSourcePacket source(packet);
	encoder.add(source);
	auto repair = encoder.getRowRepair(0);
	BC_ASSERT_PTR_NOT_NULL(repair);
	if (repair) {
		size_t repairSize = repair->repairPayloadStart(&repairPayload);
		size_t sourceSize = source.getPayloadBuffer(&sourcePayload);
		BC_ASSERT_TRUE(repair->extractBitstring().equals(source.getBitstring()));
		BC_ASSERT_EQUAL(repairSize, sourceSize, size_t, "%zu");
		BC_ASSERT_TRUE(memcmp(sourcePayload, repairPayload, sourceSize) == 0);
	}
	auto repairCol = encoder.getColRepair(0);
	BC_ASSERT_PTR_NULL(repairCol);
	rtp_session_destroy(session);
}

static void encoder_add_1D_interleaved_test(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecParamsController params(200000);
	params.updateParams(2);
	FecEncoder encoder(&params);
	encoder.init(session, session);
	encoder.update(5, 10, false);
	uint8_t *sourcePayload = NULL;
	uint8_t *repairPayload = NULL;
	std::vector<std::shared_ptr<FecSourcePacket>> sources;
	for (int i = 0; i < 5; i++) {
		mblk_t *packet = newPacketWithLetter(session, i, 123456, 'a', 150 + i * 10);
		auto source = std::make_shared<FecSourcePacket>(packet);
		sources.push_back(source);
		encoder.add(*source);
	}
	for (int i = 0; i < 5; i++) {
		auto repair = encoder.getColRepair(i);
		BC_ASSERT_PTR_NOT_NULL(repair);
		if (repair) {
			size_t repairSize = repair->repairPayloadStart(&repairPayload);
			size_t sourceSize = sources.at(i)->getPayloadBuffer(&sourcePayload);
			BC_ASSERT_TRUE(repair->extractBitstring().equals(sources.at(i)->getBitstring()));
			BC_ASSERT_EQUAL(repairSize, sourceSize, size_t, "%zu");
			BC_ASSERT_TRUE(memcmp(sourcePayload, repairPayload, sourceSize) == 0);
		}
	}
	auto repairRow = encoder.getRowRepair(0);
	BC_ASSERT_PTR_NULL(repairRow);
	rtp_session_destroy(session);
}

static void encoder_add_2D_test(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecParamsController params(200000);
	params.updateParams(3);
	FecEncoder encoder(&params);
	encoder.init(session, session);
	uint8_t *sourcePayload = NULL;
	uint8_t *repairPayload = NULL;
	std::vector<std::shared_ptr<FecSourcePacket>> sources;
	{
		mblk_t *packet = newPacketWithLetter(session, 0, 123456, 'a', 150);
		auto source = std::make_shared<FecSourcePacket>(packet);
		sources.push_back(source);
		encoder.add(*source);
	}
	{
		auto repair = encoder.getRowRepair(0);
		BC_ASSERT_PTR_NOT_NULL(repair);
		if (repair) {
			size_t repairSize = repair->repairPayloadStart(&repairPayload);
			size_t sourceSize = sources.at(0)->getPayloadBuffer(&sourcePayload);
			BC_ASSERT_TRUE(repair->extractBitstring().equals(sources.at(0)->getBitstring()));
			BC_ASSERT_EQUAL(repairSize, sourceSize, size_t, "%zu");
			BC_ASSERT_TRUE(memcmp(sourcePayload, repairPayload, sourceSize) == 0);
		}
	}
	for (int i = 1; i < 3; i++) {
		mblk_t *packet = newPacketWithLetter(session, i, 123456, 'a', 150 + i * 10);
		auto source = std::make_shared<FecSourcePacket>(packet);
		sources.push_back(source);
		encoder.add(*source);
	}
	for (int i = 0; i < 3; i++) {
		auto repair = encoder.getColRepair(i);
		BC_ASSERT_PTR_NOT_NULL(repair);
		if (repair) {
			size_t repairSize = repair->repairPayloadStart(&repairPayload);
			size_t sourceSize = sources.at(i)->getPayloadBuffer(&sourcePayload);
			BC_ASSERT_TRUE(repair->extractBitstring().equals(sources.at(i)->getBitstring()));
			BC_ASSERT_EQUAL(repairSize, sourceSize, size_t, "%zu");
			BC_ASSERT_TRUE(memcmp(sourcePayload, repairPayload, sourceSize) == 0);
		}
	}
	rtp_session_destroy(session);
}

static void encoder_full_test(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecParamsController params(200000);
	params.updateParams(1);
	FecEncoder encoder(&params);
	encoder.init(session, session);
	mblk_t *packet = NULL;
	// 1D non interleaved
	for (int i = 0; i < 10; i++) {
		packet = newPacketWithLetter(session, i, i * 60, 'a' + i, 150 + i);
		FecSourcePacket source(packet);
		encoder.add(source);
		int crtCol = i;
		int crtRow = 0;
		BC_ASSERT_EQUAL(encoder.getCurrentRow(), crtRow, int, "%d");
		BC_ASSERT_EQUAL(encoder.getCurrentColumn(), crtCol, int, "%d");
		BC_ASSERT_FALSE(encoder.isColFull());
		if (i < 9) {
			BC_ASSERT_FALSE(encoder.isRowFull());
			BC_ASSERT_FALSE(encoder.isFull());
		} else {
			BC_ASSERT_TRUE(encoder.isRowFull());
			BC_ASSERT_TRUE(encoder.isFull());
		}
	}
	BC_ASSERT_TRUE(encoder.isFull());
	encoder.clear();
	// 1D interleaved
	encoder.update(4, 3, false);
	for (int i = 0; i < 12; i++) {
		packet = newPacketWithLetter(session, i, i * 60, 'a' + i, 150 + i);
		FecSourcePacket source(packet);
		encoder.add(source);
		int crtCol = i % 4;
		int crtRow = (i - crtCol) / 4;
		BC_ASSERT_EQUAL(encoder.getCurrentRow(), crtRow, int, "%d");
		BC_ASSERT_EQUAL(encoder.getCurrentColumn(), crtCol, int, "%d");
		BC_ASSERT_FALSE(encoder.isRowFull());
		if (crtRow == 2) {
			BC_ASSERT_TRUE(encoder.isColFull());
		} else {
			BC_ASSERT_FALSE(encoder.isColFull());
		}
		if (i < 11) {
			BC_ASSERT_FALSE(encoder.isFull());
		} else {
			BC_ASSERT_TRUE(encoder.isFull());
		}
	}
	BC_ASSERT_TRUE(encoder.isFull());
	encoder.clear();
	// 2D
	encoder.update(4, 3, true);
	for (int i = 0; i < 12; i++) {
		packet = newPacketWithLetter(session, i, i * 60, 'a' + i, 150 + i);
		FecSourcePacket source(packet);
		encoder.add(source);
		int crtCol = i % 4;
		int crtRow = (i - crtCol) / 4;
		BC_ASSERT_EQUAL(encoder.getCurrentRow(), crtRow, int, "%d");
		BC_ASSERT_EQUAL(encoder.getCurrentColumn(), crtCol, int, "%d");
		if (crtCol == 3) {
			BC_ASSERT_TRUE(encoder.isRowFull());
		} else {
			BC_ASSERT_FALSE(encoder.isRowFull());
		}
		if (crtRow == 2) {
			BC_ASSERT_TRUE(encoder.isColFull());
		} else {
			BC_ASSERT_FALSE(encoder.isColFull());
		}
		if (i < 11) {
			BC_ASSERT_FALSE(encoder.isFull());
		} else {
			BC_ASSERT_TRUE(encoder.isFull());
		}
	}
	BC_ASSERT_TRUE(encoder.isFull());
	rtp_session_destroy(session);
}

static void encoder_fill_test(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecParamsController params(200000);
	params.updateParams(5);
	FecEncoder encoder(&params);
	encoder.init(session, session);
	for (int i = 0; i < 9; i++) {
		mblk_t *packet = newPacketWithLetter(session, i, i * 20, 'a' + i, 10);
		FecSourcePacket source(packet);
		encoder.add(source);
	}
	uint8_t *rptr = nullptr;
	encoder.getRowRepair(0)->repairPayloadStart(&rptr);
	uint8_t value = ('a' ^ 'b' ^ 'c');
	BC_ASSERT_EQUAL(*rptr, value, uint8_t, "%u");
	rptr = nullptr;
	encoder.getRowRepair(1)->repairPayloadStart(&rptr);
	value = ('d' ^ 'e' ^ 'f');
	BC_ASSERT_EQUAL(*rptr, value, uint8_t, "%u");
	rptr = nullptr;
	encoder.getRowRepair(2)->repairPayloadStart(&rptr);
	value = ('g' ^ 'h' ^ 'i');
	BC_ASSERT_EQUAL(*rptr, value, uint8_t, "%u");
	rptr = nullptr;
	encoder.getColRepair(0)->repairPayloadStart(&rptr);
	value = ('a' ^ 'd' ^ 'g');
	BC_ASSERT_EQUAL(*rptr, value, uint8_t, "%u");
	rptr = nullptr;
	encoder.getColRepair(1)->repairPayloadStart(&rptr);
	value = ('b' ^ 'e' ^ 'h');
	BC_ASSERT_EQUAL(*rptr, value, uint8_t, "%u");
	rptr = nullptr;
	encoder.getColRepair(2)->repairPayloadStart(&rptr);
	value = ('c' ^ 'f' ^ 'i');
	BC_ASSERT_EQUAL(*rptr, value, uint8_t, "%u");
	rtp_session_destroy(session);
}

static void encoder_reset(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecParamsController params(200000);
	params.updateParams(5);
	FecEncoder encoder(&params);
	encoder.init(session, session);
	mblk_t *expected = encoder.getRowRepairMblk(0);
	mblk_t *packet = NULL;
	encoder.reset(42);
	for (int i = 0; i < 9; i++) {
		packet = newPacketWithLetter(session, 42 + i, i * 60, 'a' + i, 150 + i);
		FecSourcePacket source(packet);
		encoder.add(source);
	}
	BC_ASSERT_FALSE(encoder.isEmpty());
	BC_ASSERT_TRUE(encoder.isFull());
	for (int i = 0; i < 3; i++) {
		auto rowRepair = encoder.getRowRepair(i);
		BC_ASSERT_PTR_NOT_NULL(rowRepair);
		if (rowRepair) {
			BC_ASSERT_EQUAL(rowRepair->getL(), 3, int, "%d");
			BC_ASSERT_EQUAL(rowRepair->getD(), 1, int, "%d");
			BC_ASSERT_EQUAL(rowRepair->getSeqnumBase(), 42 + i * 3, uint16_t, "%u");
		}
		auto colRepair = encoder.getColRepair(i);
		BC_ASSERT_PTR_NOT_NULL(colRepair);
		if (colRepair) {
			BC_ASSERT_EQUAL(colRepair->getL(), 3, int, "%d");
			BC_ASSERT_EQUAL(colRepair->getD(), 3, int, "%d");
			BC_ASSERT_EQUAL(colRepair->getSeqnumBase(), 42 + i, uint16_t, "%u");
		}
	}
	encoder.reset(0);
	auto actual = encoder.getRowRepairMblk(0);
	BC_ASSERT_TRUE(packets_are_equals(expected, actual));
	BC_ASSERT_TRUE(encoder.isEmpty());
	BC_ASSERT_FALSE(encoder.isFull());
	for (int i = 0; i < 3; i++) {
		auto rowRepair = encoder.getRowRepair(i);
		BC_ASSERT_PTR_NOT_NULL(rowRepair);
		if (rowRepair) {
			BC_ASSERT_EQUAL(rowRepair->getL(), 3, int, "%d");
			BC_ASSERT_EQUAL(rowRepair->getD(), 1, int, "%d");
			BC_ASSERT_EQUAL(rowRepair->getSeqnumBase(), i * 3, uint16_t, "%u");
		}
		auto colRepair = encoder.getColRepair(i);
		BC_ASSERT_PTR_NOT_NULL(colRepair);
		if (colRepair) {
			BC_ASSERT_EQUAL(colRepair->getL(), 3, int, "%d");
			BC_ASSERT_EQUAL(colRepair->getD(), 3, int, "%d");
			BC_ASSERT_EQUAL(colRepair->getSeqnumBase(), i, uint16_t, "%u");
		}
	}
	rtp_session_destroy(session);
	freemsg(expected);
	freemsg(actual);
}

static void encoder_clear(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecParamsController params(200000);
	params.updateParams(5);
	FecEncoder encoder(&params);
	encoder.init(session, session);
	mblk_t *packet = NULL;
	encoder.reset(42);
	for (int i = 0; i < 4; i++) {
		packet = newPacketWithLetter(session, 42 + i, i * 60, 'a' + i, 150 + i);
		FecSourcePacket source(packet);
		encoder.add(source);
	}
	BC_ASSERT_FALSE(encoder.isEmpty());
	BC_ASSERT_FALSE(encoder.isFull());
	for (int i = 0; i < 3; i++) {
		auto rowRepair = encoder.getRowRepair(i);
		BC_ASSERT_PTR_NOT_NULL(rowRepair);
		if (rowRepair) {
			BC_ASSERT_EQUAL(rowRepair->getL(), 3, int, "%d");
			BC_ASSERT_EQUAL(rowRepair->getD(), 1, int, "%d");
			BC_ASSERT_EQUAL(rowRepair->getSeqnumBase(), 42 + i * 3, uint16_t, "%u");
		}
		auto colRepair = encoder.getColRepair(i);
		BC_ASSERT_PTR_NOT_NULL(colRepair);
		if (colRepair) {
			BC_ASSERT_EQUAL(colRepair->getL(), 3, int, "%d");
			BC_ASSERT_EQUAL(colRepair->getD(), 3, int, "%d");
			BC_ASSERT_EQUAL(colRepair->getSeqnumBase(), 42 + i, uint16_t, "%u");
		}
	}
	encoder.clear();
	BC_ASSERT_TRUE(encoder.isEmpty());
	BC_ASSERT_FALSE(encoder.isFull());
	auto rowRepair = encoder.getRowRepair(0);
	BC_ASSERT_PTR_NULL(rowRepair);
	auto colRepair = encoder.getColRepair(0);
	BC_ASSERT_PTR_NULL(colRepair);
	rtp_session_destroy(session);
}

static void overhead_estimation_test(void) {
	Overhead overhead;
	BC_ASSERT_EQUAL(overhead.computeOverheadEstimator(), 0., float, "%f");
	size_t source_packets_size = 200.;
	size_t repair_packets_size = source_packets_size + 64;
	float repair_size_sum = 0.;
	float source_size_sum = 0.;
	std::vector<float> overheads;
	float overhead_measured = 0.;
	float check_overhead = 0.;
	int block_nb = 50;
	float eps = 0.000001;

	// check for fec param (3, 3)
	overhead.reset(1);
	BC_ASSERT_EQUAL(overhead.computeOverheadEstimator(), 0., float, "%f");
	for (int i = 0; i < block_nb + 2; i++) {
		for (int j = 1; j <= 9; j++) {
			overhead.sendSourcePacket(source_packets_size + j + i, 0);
		}
		overhead.sendRepairPacket(repair_packets_size + 3 + i, 0);
		overhead.sendRepairPacket(repair_packets_size + 6 + i, 0);
		overhead.sendRepairPacket(repair_packets_size + 7 + i, 0);
		overhead.sendRepairPacket(repair_packets_size + 8 + i, 0);
		overhead.sendRepairPacket(repair_packets_size + 9 + i, 0);
		overhead.sendRepairPacket(repair_packets_size + 9 + i, 0);
		overhead.encoderFull();
		overhead_measured = overhead.computeOverheadEstimator();
		repair_size_sum = static_cast<float>(6 * (repair_packets_size + i) + 42);
		source_size_sum = static_cast<float>(9 * (source_packets_size + i) + 45);
		overheads.push_back(repair_size_sum / source_size_sum);
		while (static_cast<int>(overheads.size()) > block_nb) {
			overheads.erase(overheads.begin());
		}
		if (overheads.size() < 5) {
			check_overhead = 0.;
		} else {
			check_overhead =
			    std::accumulate(overheads.begin(), overheads.end(), 0.) / static_cast<float>(overheads.size());
		}
		BC_ASSERT_LOWER(overhead_measured, check_overhead + eps, float, "%f");
		BC_ASSERT_GREATER(overhead_measured, check_overhead - eps, float, "%f");
	}

	overhead.sendSourcePacket(source_packets_size + 42, 0);
	overhead.sendRepairPacket(repair_packets_size + 42, 0);
	overhead.resetEncoder();
	overhead_measured = overhead.computeOverheadEstimator();
	BC_ASSERT_LOWER(overhead_measured, check_overhead + eps, float, "%f");
	BC_ASSERT_GREATER(overhead_measured, check_overhead - eps, float, "%f");

	// check for fec param (5, 0), 1D non interleaved
	overhead.reset(1);
	overhead_measured = overhead.computeOverheadEstimator();
	BC_ASSERT_EQUAL(overhead_measured, 0., float, "%f");
	overheads.clear();
	for (int i = 0; i < block_nb + 2; i++) {
		for (int j = 1; j <= 5; j++) {
			overhead.sendSourcePacket(source_packets_size + j + i, 0);
		}
		overhead.sendRepairPacket(repair_packets_size + 5 + i, 0);
		overhead.encoderFull();
		overhead_measured = overhead.computeOverheadEstimator();
		repair_size_sum = static_cast<float>(repair_packets_size + i + 5);
		source_size_sum = static_cast<float>(5 * (source_packets_size + i) + 15);
		overheads.push_back(repair_size_sum / source_size_sum);
		while (static_cast<int>(overheads.size()) > block_nb) {
			overheads.erase(overheads.begin());
		}
		if (overheads.size() < 5) {
			check_overhead = 0.;
		} else {
			check_overhead =
			    std::accumulate(overheads.begin(), overheads.end(), 0.) / static_cast<float>(overheads.size());
		}
		BC_ASSERT_LOWER(overhead_measured, check_overhead + eps, float, "%f");
		BC_ASSERT_GREATER(overhead_measured, check_overhead - eps, float, "%f");
	}

	// check for fec param (0, 3), 1D interleaved
	overhead.reset(3);
	overhead_measured = overhead.computeOverheadEstimator();
	BC_ASSERT_EQUAL(overhead_measured, 0., float, "%f");
	overheads.clear();
	for (int i = 0; i < block_nb + 1; i++) {
		for (int j = 0; j < 3; j++) {
			for (int k = 0; k < 3; k++) {
				overhead.sendSourcePacket(source_packets_size + 1 + j * 3 + k + i, k);
			}
		}
		overhead.sendRepairPacket(repair_packets_size + 7 + i, 0);
		overhead.sendRepairPacket(repair_packets_size + 8 + i, 1);
		overhead.sendRepairPacket(repair_packets_size + 9 + i, 2);
		overhead.encoderFull();
		overhead_measured = overhead.computeOverheadEstimator();
		float repair_size_sum_0 = static_cast<float>(repair_packets_size + i + 7);
		float source_size_sum_0 = static_cast<float>(3 * (source_packets_size + i) + 12);
		overheads.push_back(repair_size_sum_0 / source_size_sum_0);
		float repair_size_sum_1 = static_cast<float>(repair_packets_size + i + 8);
		float source_size_sum_1 = static_cast<float>(3 * (source_packets_size + i) + 15);
		overheads.push_back(repair_size_sum_1 / source_size_sum_1);
		float repair_size_sum_2 = static_cast<float>(repair_packets_size + i + 9);
		float source_size_sum_2 = static_cast<float>(3 * (source_packets_size + i) + 18);
		overheads.push_back(repair_size_sum_2 / source_size_sum_2);
		while (static_cast<int>(overheads.size()) > block_nb) {
			overheads.erase(overheads.begin());
		}
		if (overheads.size() < 5) {
			check_overhead = 0.;
		} else {
			check_overhead =
			    std::accumulate(overheads.begin(), overheads.end(), 0.) / static_cast<float>(overheads.size());
		}
		BC_ASSERT_LOWER(overhead_measured, check_overhead + eps, float, "%f");
		BC_ASSERT_GREATER(overhead_measured, check_overhead - eps, float, "%f");
	}

	// check for fec param (10, 0)
	overhead.reset(1);
	overhead_measured = overhead.computeOverheadEstimator();
	BC_ASSERT_EQUAL(overhead_measured, 0., float, "%f");
	overheads.clear();
	for (int i = 0; i < block_nb + 1; i++) {
		for (int j = 1; j <= 10; j++) {
			overhead.sendSourcePacket(source_packets_size + j + i, 0);
		}
		overhead.sendRepairPacket(repair_packets_size + 10 + i, 0);
		overhead.encoderFull();
		overhead_measured = overhead.computeOverheadEstimator();
		repair_size_sum = static_cast<float>(repair_packets_size + i + 10);
		source_size_sum = static_cast<float>(10 * (source_packets_size + i) + 55);
		overheads.push_back(repair_size_sum / source_size_sum);
		while (static_cast<int>(overheads.size()) > block_nb) {
			overheads.erase(overheads.begin());
		}
		if (overheads.size() < 5) {
			check_overhead = 0.;
		} else {
			check_overhead =
			    std::accumulate(overheads.begin(), overheads.end(), 0.) / static_cast<float>(overheads.size());
		}
		BC_ASSERT_LOWER(overhead_measured, check_overhead + eps, float, "%f");
		BC_ASSERT_GREATER(overhead_measured, check_overhead - eps, float, "%f");
	}

	// check for fec param (5, 5)
	overhead.reset(1);
	overhead_measured = overhead.computeOverheadEstimator();
	BC_ASSERT_EQUAL(overhead_measured, 0., float, "%f");
	overheads.clear();
	for (int i = 0; i < block_nb + 1; i++) {
		for (int j = 1; j <= 25; j++) {
			overhead.sendSourcePacket(source_packets_size + j + i, 0);
		}
		overhead.sendRepairPacket(repair_packets_size + 5 + i, 0);
		overhead.sendRepairPacket(repair_packets_size + 10 + i, 0);
		overhead.sendRepairPacket(repair_packets_size + 15 + i, 0);
		overhead.sendRepairPacket(repair_packets_size + 20 + i, 0);
		overhead.sendRepairPacket(repair_packets_size + 25 + i, 0);
		overhead.sendRepairPacket(repair_packets_size + 21 + i, 0);
		overhead.sendRepairPacket(repair_packets_size + 22 + i, 0);
		overhead.sendRepairPacket(repair_packets_size + 23 + i, 0);
		overhead.sendRepairPacket(repair_packets_size + 24 + i, 0);
		overhead.sendRepairPacket(repair_packets_size + 25 + i, 0);
		overhead.encoderFull();
		overhead_measured = overhead.computeOverheadEstimator();
		repair_size_sum = static_cast<float>(10 * (repair_packets_size + i) + 190);
		source_size_sum = static_cast<float>(25 * (source_packets_size + i) + 325);
		overheads.push_back(repair_size_sum / source_size_sum);
		while (static_cast<int>(overheads.size()) > block_nb) {
			overheads.erase(overheads.begin());
		}
		if (overheads.size() < 5) {
			check_overhead = 0.;
		} else {
			check_overhead =
			    std::accumulate(overheads.begin(), overheads.end(), 0.) / static_cast<float>(overheads.size());
		}
		BC_ASSERT_LOWER(overhead_measured, check_overhead + eps, float, "%f");
		BC_ASSERT_GREATER(overhead_measured, check_overhead - eps, float, "%f");
	}
}

static void graph_source_node_test(void) {
	uint16_t seqNum = 42;
	FecSourceNode sourceNode(seqNum);
	std::set<uint16_t> rowRepairCheck = {0, 10, 20, 30, 40};
	std::set<uint16_t> colRepairCheck = {10, 11, 12, 13, 14};
	BC_ASSERT_EQUAL(sourceNode.getSeqNum(), seqNum, uint16_t, "%u");
	for (uint16_t i = 0; i < 5; i++) {
		sourceNode.addRowRepair(i * 10);
		sourceNode.addColRepair(i + 10);
	}
	sourceNode.addRowRepair(20);
	auto rowRepair = sourceNode.getRowRepair();
	auto colRepair = sourceNode.getColRepair();
	BC_ASSERT_TRUE(rowRepair == rowRepairCheck);
	BC_ASSERT_TRUE(colRepair == colRepairCheck);
}

static void graph_repair_node_test(void) {
	std::vector<uint16_t> sourceSeqNum = {0, 10, 20, 30, 40};
	FecRepairNode repairNode(sourceSeqNum);
	auto sourceSeqNumTest = repairNode.getProtectedSources();
	int i = 0;
	BC_ASSERT_EQUAL(sourceSeqNumTest.size(), 5, size_t, "%zu");
	for (auto it = sourceSeqNumTest.begin(); it != sourceSeqNumTest.end(); ++it) {
		BC_ASSERT_EQUAL(*it, sourceSeqNum.at(i), uint16_t, "%u");
		i++;
	}
}

static void graph_packet_connection_test(void) {
	FecPacketsConnection packetConnection;

	// disjoint FEC blocks
	packetConnection.addRowRepair(0, std::vector<uint16_t>{0, 1, 2});
	packetConnection.addColRepair(1, std::vector<uint16_t>{1, 4, 7});
	packetConnection.addRowRepair(3, std::vector<uint16_t>{3, 4, 5});
	packetConnection.addColRepair(16, std::vector<uint16_t>{16, 18});
	packetConnection.addRowRepair(6, std::vector<uint16_t>{6, 7, 8});
	packetConnection.addRowRepair(9, std::vector<uint16_t>{9, 10, 11});
	packetConnection.addRowRepair(12, std::vector<uint16_t>{12, 13, 14});
	packetConnection.addRowRepair(17, std::vector<uint16_t>{17, 18});
	packetConnection.addColRepair(0, std::vector<uint16_t>{0, 3, 6});
	packetConnection.addColRepair(2, std::vector<uint16_t>{2, 5, 8});
	packetConnection.addColRepair(15, std::vector<uint16_t>{15, 17});
	packetConnection.addColRepair(19, std::vector<uint16_t>{19, 21});
	packetConnection.addRowRepair(15, std::vector<uint16_t>{15, 16});
	packetConnection.addColRepair(2000, std::vector<uint16_t>{20, 22});

	std::set<uint16_t> repairRowTest;
	std::set<uint16_t> repairColTest;
	packetConnection.getRepairPacketsToRecoverSource(2, repairRowTest, repairColTest);
	BC_ASSERT_TRUE(repairRowTest == std::set<uint16_t>({0, 3, 6}));
	BC_ASSERT_TRUE(repairColTest == std::set<uint16_t>({0, 1, 2}));

	packetConnection.getRepairPacketsToRecoverSource(9, repairRowTest, repairColTest);
	BC_ASSERT_TRUE(repairRowTest == std::set<uint16_t>({9}));
	BC_ASSERT_TRUE(repairColTest.empty());

	packetConnection.getRepairPacketsToRecoverSource(20, repairRowTest, repairColTest);
	BC_ASSERT_TRUE(repairRowTest.empty());
	BC_ASSERT_TRUE(repairColTest == std::set<uint16_t>({2000}));

	// overlapped FEC blocks
	for (uint16_t i = 23; i < 42; i++) {
		uint16_t j = i + 1;
		packetConnection.addColRepair(i, std::vector<uint16_t>{i, j});
	}
	packetConnection.getRepairPacketsToRecoverSource(23, repairRowTest, repairColTest);
	BC_ASSERT_TRUE(repairRowTest.empty());
	BC_ASSERT_TRUE(repairColTest == std::set<uint16_t>({23, 24, 25, 26, 27, 28, 29, 30, 31, 32}));

	packetConnection.getRepairPacketsToRecoverSource(29, repairRowTest, repairColTest);
	BC_ASSERT_TRUE(repairRowTest.empty());
	BC_ASSERT_TRUE(repairColTest ==
	               std::set<uint16_t>({23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38}));

	packetConnection.getRepairPacketsToRecoverSource(36, repairRowTest, repairColTest);
	BC_ASSERT_TRUE(repairRowTest.empty());
	BC_ASSERT_TRUE(repairColTest ==
	               std::set<uint16_t>({26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41}));

	// clean
	packetConnection.cleanRowRepair(3);
	packetConnection.cleanRowRepair(9);
	packetConnection.cleanRowRepair(15);
	packetConnection.cleanRowRepair(17);
	packetConnection.cleanRowRepair(17);
	packetConnection.cleanColRepair(0);
	packetConnection.cleanColRepair(15);
	packetConnection.cleanColRepair(2000);
	packetConnection.cleanColRepair(35);
	packetConnection.cleanColRepair(35);

	packetConnection.getRepairPacketsToRecoverSource(2, repairRowTest, repairColTest);
	BC_ASSERT_TRUE(repairRowTest == std::set<uint16_t>({0, 6}));
	BC_ASSERT_TRUE(repairColTest == std::set<uint16_t>({1, 2}));

	packetConnection.getRepairPacketsToRecoverSource(18, repairRowTest, repairColTest);
	BC_ASSERT_TRUE(repairRowTest.empty());
	BC_ASSERT_TRUE(repairColTest == std::set<uint16_t>({16}));

	packetConnection.getRepairPacketsToRecoverSource(23, repairRowTest, repairColTest);
	BC_ASSERT_TRUE(repairRowTest.empty());
	BC_ASSERT_TRUE(repairColTest == std::set<uint16_t>({23, 24, 25, 26, 27, 28, 29, 30, 31, 32}));

	packetConnection.getRepairPacketsToRecoverSource(29, repairRowTest, repairColTest);
	BC_ASSERT_TRUE(repairRowTest.empty());
	BC_ASSERT_TRUE(repairColTest == std::set<uint16_t>({23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34}));

	packetConnection.getRepairPacketsToRecoverSource(36, repairRowTest, repairColTest);
	BC_ASSERT_TRUE(repairRowTest.empty());
	BC_ASSERT_TRUE(repairColTest == std::set<uint16_t>({36, 37, 38, 39, 40, 41}));

	// those source packets don't exist any more in FEC graph
	for (auto sourceToRepair : std::vector<uint16_t>{3, 9, 10, 11, 15, 17, 20, 22}) {
		packetConnection.getRepairPacketsToRecoverSource(sourceToRepair, repairRowTest, repairColTest);
		BC_ASSERT_TRUE(repairRowTest.empty());
		BC_ASSERT_TRUE(repairColTest.empty());
	}

	// reset
	packetConnection.reset();
	for (uint16_t i = 0; i < 42; i++) {
		packetConnection.getRepairPacketsToRecoverSource(i, repairRowTest, repairColTest);
		BC_ASSERT_TRUE(repairRowTest.empty());
		BC_ASSERT_TRUE(repairColTest.empty());
	}
}

static void generate_packets_for_fec_block(std::map<uint16_t, std::shared_ptr<FecSourcePacket>> &generatedSources,
                                           std::map<uint16_t, std::shared_ptr<FecRepairPacket>> &generatedRepair,
                                           int L,
                                           int D,
                                           bool is2D,
                                           uint16_t seqNumStartSource,
                                           uint16_t seqNumStartRepair,
                                           FecEncoder &encoder,
                                           RtpSession *session) {

	encoder.update(L, D, is2D);
	encoder.reset(seqNumStartSource);
	int nbCol = L;
	int nbRow = (!is2D && D == 0) ? 1 : D;
	for (int i = 0; i < nbRow; i++) {
		for (int j = 0; j < nbCol; j++) {
			uint16_t seqNum = static_cast<uint16_t>(seqNumStartSource + i * L + j);
			if (generatedSources.count(seqNum) == 1) {
				encoder.add(*generatedSources.at(seqNum));
			} else {
				mblk_t *packet = newPacketWithLetter(session, seqNum, seqNum * 10, 'a', 100 + i * L + j);
				auto source = std::make_shared<FecSourcePacket>(packet);
				generatedSources.emplace(seqNum, source);
				encoder.add(*source);
			}
		}
	}
	if (encoder.isRowFull()) {
		for (int i = 0; i < nbRow; i++) {
			auto repair = encoder.getRowRepair(i);
			rtp_set_seqnumber(repair->getRepairPacket(), seqNumStartRepair);
			rtp_set_timestamp(repair->getRepairPacket(),
			                  static_cast<uint32_t>(repair->createSequenceNumberList().back()) * 10);
			generatedRepair.emplace(repair->getSeqnum(), repair);
			seqNumStartRepair++;
		}
	}
	if (encoder.isColFull()) {
		for (int i = 0; i < nbCol; i++) {
			auto repair = encoder.getColRepair(i);
			rtp_set_seqnumber(repair->getRepairPacket(), seqNumStartRepair);
			rtp_set_timestamp(repair->getRepairPacket(),
			                  static_cast<uint32_t>(repair->createSequenceNumberList().back()) * 10);
			generatedRepair.emplace(repair->getSeqnum(), repair);
			seqNumStartRepair++;
		}
	}
}

static void receive_cluster_add_source_test(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	auto cluster = ReceiveCluster(session, 40);
	mblk_t *packet = NULL;

	// packets received in chronological order
	for (int k = 0; k < 15; k++) {
		packet = newPacketWithLetter(session, k, k * 10, 'a' + k, 150 + k);
		cluster.add(packet);
		auto sourceAdded = cluster.getSourcePacket(k);
		BC_ASSERT_PTR_NOT_NULL(sourceAdded);
		if (sourceAdded) {
			BC_ASSERT_TRUE(packets_are_equals(packet, sourceAdded->getPacket()));
		}
	}
	for (uint16_t i = 0; i < 11; i++) {
		auto source = cluster.getSourcePacket(i);
		BC_ASSERT_PTR_NULL(source);
	}
	for (uint16_t i = 11; i < 15; i++) {
		auto source = cluster.getSourcePacket(i);
		BC_ASSERT_PTR_NOT_NULL(source);
	}

	// packets not received in chronological order
	for (uint16_t i : std::vector<uint16_t>{15, 17, 19, 21, 23}) {
		packet = newPacketWithLetter(session, i, i * 10, 'a' + i, 150 + i);
		cluster.add(packet);
		auto sourceAdded = cluster.getSourcePacket(i);
		BC_ASSERT_PTR_NOT_NULL(sourceAdded);
		if (sourceAdded) {
			BC_ASSERT_TRUE(packets_are_equals(packet, sourceAdded->getPacket()));
		}
	}
	for (uint16_t i : std::vector<uint16_t>{21, 23}) {
		auto source = cluster.getSourcePacket(i);
		BC_ASSERT_PTR_NOT_NULL(source);
	}
	for (uint16_t i : std::vector<uint16_t>{14, 15, 17, 19}) {
		auto source = cluster.getSourcePacket(i);
		BC_ASSERT_PTR_NULL(source);
	}
	for (uint16_t i : std::vector<uint16_t>{16, 18, 20, 22, 24}) {
		packet = newPacketWithLetter(session, i, i * 10, 'a' + i, 150 + i);
		cluster.add(packet);
		auto sourceAdded = cluster.getSourcePacket(i);
		if (i == 16 or i == 18) {
			BC_ASSERT_PTR_NULL(sourceAdded);
		} else {
			BC_ASSERT_PTR_NOT_NULL(sourceAdded);
		}
		if (sourceAdded) {
			BC_ASSERT_TRUE(packets_are_equals(packet, sourceAdded->getPacket()));
		}
	}
	for (uint16_t i : std::vector<uint16_t>{21, 22, 23, 24}) {
		auto source = cluster.getSourcePacket(i);
		BC_ASSERT_PTR_NOT_NULL(source);
	}
	for (uint16_t i : std::vector<uint16_t>{16, 18, 20}) {
		auto source = cluster.getSourcePacket(i);
		BC_ASSERT_PTR_NULL(source);
	}

	// receive too old packet
	packet = newPacketWithLetter(session, 25, 199, 'a', 150);
	cluster.add(packet);
	auto sourceAdded = cluster.getSourcePacket(25);
	BC_ASSERT_PTR_NULL(sourceAdded);

	rtp_session_destroy(session);
}

static void receive_cluster_add_repair_test(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	uint16_t seqNumStart = 0;
	uint32_t repairWindow = 101;
	FecParamsController params(repairWindow);
	params.updateParams(1);
	FecEncoder encoder(&params);
	encoder.init(session, session);
	ReceiveCluster cluster = ReceiveCluster(session, repairWindow);

	// generate source and repair packets
	std::map<uint16_t, std::shared_ptr<FecSourcePacket>> receivedSource;
	std::map<uint16_t, std::shared_ptr<FecRepairPacket>> receivedRepair;
	generate_packets_for_fec_block(receivedSource, receivedRepair, 5, 3, true, seqNumStart, seqNumStart, encoder,
	                               session);
	generate_packets_for_fec_block(receivedSource, receivedRepair, 5, 0, false, seqNumStart + 15, 8, encoder, session);
	generate_packets_for_fec_block(receivedSource, receivedRepair, 5, 0, false, seqNumStart + 20, 9, encoder, session);

	// receive repair packets out of order
	for (uint16_t i : std::vector<uint16_t>{8, 2, 4, 5, 0, 1, 6, 7, 3, 9}) {
		cluster.add(receivedRepair.at(i));
	}
	BC_ASSERT_EQUAL(static_cast<int>(cluster.getRowRepairCpt()), 5, int, "%d");
	BC_ASSERT_EQUAL(static_cast<int>(cluster.getColRepairCpt()), 5, int, "%d");

	// check which source packet can be repaired
	for (uint16_t i : std::vector<uint16_t>{0, 1, 2, 5, 6, 7, 4, 9, 10, 12, 13}) {
		cluster.add(receivedSource.at(i)->getPacketCopy());
		auto source = cluster.getSourcePacket(i);
		BC_ASSERT_PTR_NOT_NULL(source);
	}
	std::set<uint16_t> irrepairableSourceSeqNum = {3, 8};
	for (uint16_t seqNum : std::vector<uint16_t>{3, 8, 11, 14}) {
		cluster.repair(seqNum);
		auto repairedSource = cluster.getSourcePacket(seqNum);
		if (irrepairableSourceSeqNum.count(seqNum) == 1) {
			BC_ASSERT_PTR_NULL(repairedSource);
		} else {
			BC_ASSERT_PTR_NOT_NULL(repairedSource);
			if (repairedSource) {
				auto refSource = receivedSource.at(seqNum);
				BC_ASSERT_TRUE(packets_are_equals(repairedSource->getPacket(), refSource->getPacket()));
			}
		}
	}

	for (uint16_t i : std::vector<uint16_t>{15, 16, 17}) {
		cluster.add(receivedSource.at(i)->getPacketCopy());
		auto source = cluster.getSourcePacket(i);
		BC_ASSERT_PTR_NOT_NULL(source);
	}
	for (uint16_t i = 19; i <= 24; i++) {
		cluster.add(receivedSource.at(i)->getPacketCopy());
		auto source = cluster.getSourcePacket(i);
		BC_ASSERT_PTR_NOT_NULL(source);
	}
	{
		uint16_t seqNum = 18;
		cluster.repair(seqNum);
		auto repairedSource = cluster.getSourcePacket(seqNum);
		BC_ASSERT_PTR_NOT_NULL(repairedSource);
		if (repairedSource) {
			auto refSource = receivedSource.at(seqNum);
			BC_ASSERT_TRUE(packets_are_equals(repairedSource->getPacket(), refSource->getPacket()));
		}
	}
	{
		uint16_t seqNum = 13;
		cluster.repair(seqNum);
		auto repairedSource = cluster.getSourcePacket(seqNum);
		BC_ASSERT_PTR_NULL(repairedSource);
	}
	BC_ASSERT_EQUAL(static_cast<int>(cluster.getRowRepairCpt()), 5, int, "%d");
	BC_ASSERT_EQUAL(static_cast<int>(cluster.getColRepairCpt()), 5, int, "%d");

	rtp_session_destroy(session);
}

static void receive_cluster_repair_test(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	uint16_t seqNumStart = 5;
	FecParamsController params(200000);
	params.updateParams(1);
	FecEncoder encoder(&params);
	encoder.init(session, session);

	// generate source and repair packets
	std::map<uint16_t, std::shared_ptr<FecSourcePacket>> receivedSource;
	std::map<uint16_t, std::shared_ptr<FecRepairPacket>> receivedRepair;
	generate_packets_for_fec_block(receivedSource, receivedRepair, 5, 3, true, seqNumStart, 0, encoder, session);
	generate_packets_for_fec_block(receivedSource, receivedRepair, 3, 0, false, 20, 8, encoder, session);
	generate_packets_for_fec_block(receivedSource, receivedRepair, 3, 0, false, 23, 9, encoder, session);
	generate_packets_for_fec_block(receivedSource, receivedRepair, 3, 3, false, 26, 10, encoder, session);
	generate_packets_for_fec_block(receivedSource, receivedRepair, 3, 3, true, 35, 13, encoder, session);
	for (int i = 0; i < 5; i++) {
		generate_packets_for_fec_block(receivedSource, receivedRepair, 1, 2, false, 44 + i, 19 + i, encoder, session);
	}

	// lost packets
	std::map<uint16_t, std::shared_ptr<FecSourcePacket>> missingSource;
	std::set<uint16_t> missingSourceSeqNum = {10, 19, 21, 26, 29, 31, 39, 40, 42, 43, 45, 46};
	for (uint16_t seqNum : missingSourceSeqNum) {
		missingSource.emplace(seqNum, receivedSource.at(seqNum));
		receivedSource.erase(seqNum);
	}
	std::map<uint16_t, std::shared_ptr<FecRepairPacket>> missingRepair;
	std::set<uint16_t> missingRepairSeqNum = {1, 9, 11, 16};
	for (uint16_t seqNum : missingRepairSeqNum) {
		missingRepair.emplace(seqNum, receivedRepair.at(seqNum));
		receivedRepair.erase(seqNum);
	}

	// receive packets
	auto cluster = ReceiveCluster(session, 200000);
	for (auto sp : receivedSource) {
		cluster.add(sp.second->getPacketCopy());
	}
	for (auto rp : receivedRepair) {
		cluster.add(rp.second);
	}

	// repair missing packets
	std::set<uint16_t> irrepairableSourceSeqNum = {26, 29, 39, 40, 42, 43};
	for (uint16_t seqNum : missingSourceSeqNum) {
		cluster.repair(seqNum);
		auto repairedSource = cluster.getSourcePacket(seqNum);
		if (irrepairableSourceSeqNum.count(seqNum) == 1) {
			BC_ASSERT_PTR_NULL(repairedSource);
		} else {
			BC_ASSERT_PTR_NOT_NULL(repairedSource);
			if (repairedSource) {
				auto refSource = missingSource.at(seqNum);
				BC_ASSERT_TRUE(packets_are_equals(repairedSource->getPacket(), refSource->getPacket()));
			}
		}
	}

	// repair out-of-scope packet
	cluster.repair(2000);
	auto notRepairedSource = cluster.getSourcePacket(2000);
	BC_ASSERT_PTR_NULL(notRepairedSource);

	// repair non lost packet
	cluster.repair(17);
	auto notMissingSource = cluster.getSourcePacket(17);
	BC_ASSERT_PTR_NOT_NULL(notMissingSource);
	if (notMissingSource) {
		auto refSource = receivedSource.at(17);
		BC_ASSERT_TRUE(packets_are_equals(notMissingSource->getPacket(), refSource->getPacket()));
	}

	// add a row repair packet that overlaps another FEC block and make irrepairable packets 39 to 43 repairable
	// again
	generate_packets_for_fec_block(receivedSource, receivedRepair, 5, 0, false, 35, 24, encoder, session);
	// receive packets
	for (auto rp : receivedRepair) {
		cluster.add(rp.second);
	}
	// repair
	std::set<uint16_t> newRepairableSourceSeqNum = {39, 40, 42, 43};
	for (uint16_t seqNum : newRepairableSourceSeqNum) {
		cluster.repair(seqNum);
		auto repairedSource = cluster.getSourcePacket(seqNum);
		BC_ASSERT_PTR_NOT_NULL(repairedSource);
		if (repairedSource) {
			auto refSource = missingSource.at(seqNum);
			BC_ASSERT_TRUE(packets_are_equals(repairedSource->getPacket(), refSource->getPacket()));
		}
	}

	rtp_session_destroy(session);
}

static void receive_cluster_reset_test(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecParamsController params(200000);
	params.updateParams(1);
	FecEncoder encoder(&params);
	encoder.init(session, session);

	std::map<uint16_t, std::shared_ptr<FecSourcePacket>> receivedSource;
	std::map<uint16_t, std::shared_ptr<FecRepairPacket>> receivedRepair;
	for (int i = 0; i < 5; i++) {
		generate_packets_for_fec_block(receivedSource, receivedRepair, 3, 3, true, i * 9, i * 6, encoder, session);
	}

	auto cluster = ReceiveCluster(session, 200000);
	for (auto sp : receivedSource) {
		cluster.add(sp.second->getPacketCopy());
	}
	for (auto rp : receivedRepair) {
		cluster.add(rp.second);
	}

	cluster.reset();
	BC_ASSERT_EQUAL(static_cast<int>(cluster.getRowRepairCpt()), 5 * 3, int, "%d");
	BC_ASSERT_EQUAL(static_cast<int>(cluster.getColRepairCpt()), 5 * 3, int, "%d");
	for (auto sp : receivedSource) {
		BC_ASSERT_PTR_NULL(cluster.getSourcePacket(sp.first));
		cluster.repair(sp.first);
		BC_ASSERT_PTR_NULL(cluster.getSourcePacket(sp.first));
	}

	rtp_session_destroy(session);
}

static void stats_sent_packets(void) {
	FecStreamStats stats;
	BC_ASSERT_EQUAL(static_cast<int>(stats.getFecStats()->row_repair_sent), 0, int, "%d");
	BC_ASSERT_EQUAL(static_cast<int>(stats.getFecStats()->col_repair_sent), 0, int, "%d");

	int rowNum = 12;
	int colNum = 27;
	for (int i = 0; i < rowNum; i++)
		stats.rowRepairSent();
	for (int i = 0; i < colNum; i++)
		stats.colRepairSent();
	BC_ASSERT_EQUAL(static_cast<int>(stats.getFecStats()->row_repair_sent), rowNum, int, "%d");
	BC_ASSERT_EQUAL(static_cast<int>(stats.getFecStats()->col_repair_sent), colNum, int, "%d");
}

static void stats_received_packets(void) {
	FecStreamStats stats;
	BC_ASSERT_EQUAL(static_cast<int>(stats.getFecStats()->row_repair_received), 0, int, "%d");
	BC_ASSERT_EQUAL(static_cast<int>(stats.getFecStats()->col_repair_received), 0, int, "%d");

	stats.rowRepairReceived(2);
	stats.colRepairReceived(3);
	BC_ASSERT_EQUAL(static_cast<int>(stats.getFecStats()->row_repair_received), 2, int, "%d");
	BC_ASSERT_EQUAL(static_cast<int>(stats.getFecStats()->col_repair_received), 3, int, "%d");
	stats.rowRepairReceived(7);
	stats.colRepairReceived(4);
	BC_ASSERT_EQUAL(static_cast<int>(stats.getFecStats()->row_repair_received), 7, int, "%d");
	BC_ASSERT_EQUAL(static_cast<int>(stats.getFecStats()->col_repair_received), 4, int, "%d");
}

static void stats_count_packets(void) {
	FecStreamStats stats;
	BC_ASSERT_EQUAL(static_cast<int>(stats.getPacketsLost()), 0, int, "%d");
	BC_ASSERT_EQUAL(static_cast<int>(stats.getPacketsRecovered()), 0, int, "%d");
	BC_ASSERT_EQUAL(static_cast<int>(stats.getPacketsNotRecovered()), 0, int, "%d");

	int16_t diff = 0;
	uint16_t new_seqnum_received = 0;
	int last_seqnum = 0;

	// packets 0-18: missing, try to repair
	for (uint16_t i = 0; i < 19; i++) {
		stats.askedPacket(i);
	}
	// packets 0-9: missing and repaired at the second try
	for (uint16_t i = 0; i < 10; i++) {
		stats.askedPacket(i);
		stats.repairedPacket(i);
	}
	// packets 10-14: arrive in the jitter buffer
	// -> not asked any more
	// -> not counted as recovered nor lost
	// 10-14
	// packets 15-19: definitely lost
	// packet 20: read from jitter buffer, oldest missing packets are lost forever
	new_seqnum_received = 20;
	last_seqnum = 14;
	diff = new_seqnum_received - last_seqnum - 1;
	last_seqnum = (int)new_seqnum_received - (int)diff - 1;
	stats.definitelyLostPacket(new_seqnum_received, diff);
	// packets 21-29: missing, try to repair
	for (uint16_t i = 21; i < 30; i++) {
		stats.askedPacket(i);
	}
	// packets 30-39: missing and repaired
	for (uint16_t i = 30; i < 40; i++) {
		stats.askedPacket(i);
		stats.repairedPacket(i);
	}
	BC_ASSERT_EQUAL(static_cast<int>(stats.getPacketsLost()), 25, int, "%d");
	BC_ASSERT_EQUAL(static_cast<int>(stats.getPacketsRecovered()), 20, int, "%d");
	BC_ASSERT_EQUAL(static_cast<int>(stats.getPacketsNotRecovered()), 5, int, "%d");
	// packets 40-69: missing, try to repair
	for (uint16_t i = 40; i < 70; i++) {
		stats.askedPacket(i);
	}
	// packets 70-199 skipped, never asked
	// packets 201-204: missing, try to repair
	for (uint16_t i = 201; i < 205; i++) {
		stats.askedPacket(i);
	}
	// packet 200: read from jitter buffer, oldest missing packets (21-29 and 40-199) are lost forever
	new_seqnum_received = 200;
	last_seqnum = 39;
	diff = new_seqnum_received - last_seqnum - 1;
	last_seqnum = (int)new_seqnum_received - (int)diff - 1;
	stats.definitelyLostPacket(new_seqnum_received, diff);

	BC_ASSERT_EQUAL(static_cast<int>(stats.getPacketsLost()), 55, int, "%d");
	BC_ASSERT_EQUAL(static_cast<int>(stats.getPacketsRecovered()), 20, int, "%d");
	BC_ASSERT_EQUAL(static_cast<int>(stats.getPacketsNotRecovered()), 35, int, "%d");
}

static test_t tests[] = {

    TEST_NO_TAG("fec parameters update", fec_params_update_test),
    TEST_NO_TAG("fec parameters level", fec_params_level_test),

    TEST_NO_TAG("bitstring add", bitstring_add_test),
    TEST_NO_TAG("source_packet_get_payload", source_packet_get_payload_test),
    TEST_NO_TAG("source_packet_add_payload same size", source_packet_add_payload_test1),
    TEST_NO_TAG("source_packet_add_payload bigger", source_packet_add_payload_test2),
    TEST_NO_TAG("source_packet_add_payload smaller", source_packet_add_payload_test3),
    TEST_NO_TAG("repair_packet_bitstring", repair_packet_bitstring_test),
    TEST_NO_TAG("repair_packet_add Payload", repair_packet_add_payload1),
    TEST_NO_TAG("repair packet seqnum list non interleaved", repair_packet_seqnumListNonInterleaved_test),
    TEST_NO_TAG("repair packet seqnum list interleaved", repair_packet_seqnumListInterleaved_test),

    TEST_NO_TAG("encoder init 1D non interleaved", encoder_init_1D_non_interleaved_test),
    TEST_NO_TAG("encoder init 1D interleaved", encoder_init_1D_interleaved_test),
    TEST_NO_TAG("encoder init_2D", encoder_init_2D_test),
    TEST_NO_TAG("encoder update", encoder_update_test),
    TEST_NO_TAG("encoder add 1D", encoder_add_1D_test),
    TEST_NO_TAG("encoder add 1D interleaved", encoder_add_1D_interleaved_test),
    TEST_NO_TAG("encoder add 2D", encoder_add_2D_test),
    TEST_NO_TAG("encoder full", encoder_full_test),
    TEST_NO_TAG("encoder fill", encoder_fill_test),
    TEST_NO_TAG("encoder reset", encoder_reset),
    TEST_NO_TAG("encoder clear", encoder_clear),

    TEST_NO_TAG("overhead estimation", overhead_estimation_test),

    TEST_NO_TAG("graph source node", graph_source_node_test),
    TEST_NO_TAG("graph repair node", graph_repair_node_test),
    TEST_NO_TAG("graph packet connection", graph_packet_connection_test),

    TEST_NO_TAG("receive cluster add source", receive_cluster_add_source_test),
    TEST_NO_TAG("receive cluster add repair", receive_cluster_add_repair_test),
    TEST_NO_TAG("receive cluster repair", receive_cluster_repair_test),
    TEST_NO_TAG("receive cluster reset", receive_cluster_reset_test),

    TEST_NO_TAG("stats sent packets", stats_sent_packets),
    TEST_NO_TAG("stats received packets", stats_received_packets),
    TEST_NO_TAG("stats count packets", stats_count_packets),
};

test_suite_t fec_test_suite = {
    "FEC",                            // Name of test suite
    NULL,                             // Before all callback
    NULL,                             // After all callback
    NULL,                             // Before each callback
    NULL,                             // After each callback
    sizeof(tests) / sizeof(tests[0]), // Size of test table
    tests,                            // Table of test suite
    0                                 // Average execution time
};
