
#include "fecstream.h"
#include "ortp/payloadtype.h"
#include "ortp_tester.h"

using namespace ortp;

static FecParameters *newFecParams(int L, int D, int repairWindow) {
	FecParameters *params = new FecParameters;
	params->L = L;
	params->D = D;
	params->repairWindow = repairWindow;
	return params;
} /*
 static void fillEncoder(FecEncoder &encoder) {
	 for (int i = 0; i < encoder.getSize(); i++) {
		 Bitstring bs = generateBitstring(160 * i, 150 + i, 'a' + i);
		 encoder.add(bs);
	 }
 }
 static mblk_t *new_packet(struct _RtpSession *session, int seqnum, uint32_t timestamp, uint8_t *payload, size_t
 packet_size) { mblk_t *packet = NULL;

	 packet = rtp_session_create_packet(session, RTP_FIXED_HEADER_SIZE, payload, packet_size);
	 rtp_set_seqnumber(packet, seqnum);
	 rtp_set_timestamp(packet, timestamp);
	 return packet;
 }*/

static mblk_t *newPacketWithLetter(struct _RtpSession *session, int seqnum, uint32_t timestamp, uint8_t car,
								   size_t packet_size) {
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
		   (rtp_get_ssrc(ma) == rtp_get_ssrc(ma));
}
static bool_t compare_csrc_fields(mblk_t *ma, mblk_t *mb) {
	uint16_t cc = rtp_get_cc(ma);
	if (cc != rtp_get_cc(mb))
		return FALSE;
	for (uint8_t i = 0; i < cc; i++) {
		if (rtp_get_csrc(ma, i) != rtp_get_csrc(mb, i))
			return FALSE;
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

		if (ext != rtp_get_extbit(mb))
			return FALSE;

		size_ext_a = rtp_get_extheader(ma, &profile_ext_a, &data_ext_a);
		size_ext_b = rtp_get_extheader(mb, &profile_ext_b, &data_ext_b);
		if (size_ext_a != size_ext_b)
			return FALSE;
		if (!((profile_ext_a == profile_ext_b) && (memcmp(data_ext_a, data_ext_b, size_ext_a) == 0)))
			return FALSE;
	}
	return TRUE;
}
static bool_t compare_payloads(mblk_t *ma, mblk_t *mb) {
	uint8_t *payload_a = NULL;
	uint8_t *payload_b = NULL;
	int size_payload_a, size_payload_b;

	size_payload_a = rtp_get_payload(ma, &payload_a);
	size_payload_b = rtp_get_payload(mb, &payload_b);
	if (size_payload_a != size_payload_b)
		return FALSE;
	if (memcmp(payload_a, payload_b, size_payload_a) != 0)
		return FALSE;
	return TRUE;
}
static bool_t packets_are_equals(mblk_t *ma, mblk_t *mb) {

	if (!compare_sizes(ma, mb))
		return FALSE;
	if (!compare_header_fields(ma, mb))
		return FALSE;
	if (!compare_csrc_fields(ma, mb))
		return FALSE;
	if (!compare_ext_headers(ma, mb))
		return FALSE;
	if (!compare_payloads(ma, mb))
		return FALSE;
	return TRUE;
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

	freemsg(packetA);
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
	freemsg(packetA);
	freemsg(packetB);

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

	freemsg(packetA);
	freemsg(packetB);

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
		if (i < 120)
			expectedPayload[i] = 'a' ^ 'b';
		else
			expectedPayload[i] = 'a';
	}

	size_t sizeA = pA.getPayloadBuffer(&rptr);
	BC_ASSERT_EQUAL(sizeA, 150, size_t, "%zu");
	BC_ASSERT_TRUE(memcmp(rptr, expectedPayload, sizeA) == 0);

	freemsg(packetA);
	freemsg(packetB);

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

	freemsg(packetA);
	rtp_session_destroy(session);
}
static void repair_packet_add_payload1(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	rtp_session_set_payload_type(session, 98);

	mblk_t *packetA = newPacketWithLetter(session, 0, 123456, 'a', 150);
	FecSourcePacket sourceA(packetA);
	FecRepairPacket repair(session,session, 0, 5, 1);

	repair.addPayload(sourceA);
	uint8_t *expectedBuffer = NULL;
	uint8_t *buffer = NULL;
	size_t expectedSize = sourceA.getPayloadBuffer(&expectedBuffer);
	size_t size = repair.repairPayloadStart(&buffer);

	BC_ASSERT_EQUAL(size, expectedSize, size_t, "%zu");
	BC_ASSERT_TRUE(memcmp(buffer, expectedBuffer, size) == 0);

	freemsg(packetA);
	rtp_session_destroy(session);
}
static void repair_packet_seqnumListNonInterleaved_test(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecRepairPacket repair(session, session, 0, 3, 0);
	auto liste = repair.createSequenceNumberList();
	BC_ASSERT_EQUAL(liste.size(), 3, size_t, "%zu");
	for (int i = 0; i < 3; i++) {
		BC_ASSERT_EQUAL(liste[i], i, uint16_t, "%u");
	}

	rtp_session_destroy(session);
}
static void repair_packet_seqnumListInterleaved_test(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecRepairPacket repair(session, session, 0, 3, 3);
	auto liste = repair.createSequenceNumberList();
	BC_ASSERT_EQUAL(liste.size(), 3, size_t, "%zu");
	int seqnum = 0;
	for (int i = 0; i < 3; i++) {
		BC_ASSERT_EQUAL(liste[i], seqnum, uint16_t, "%u");
		seqnum += 3;
	}

	rtp_session_destroy(session);
}

static void encoder_init1D_test(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecParameters *params = newFecParams(10, 0, 200000);
	FecEncoder cluster(params);
	cluster.init(session,session);

	auto rowRepair = cluster.getRowRepair();
	auto colRepair = cluster.getColRepair();
	auto size = cluster.getSize();
	auto col = cluster.getColumns();
	auto row = cluster.getRows();

	BC_ASSERT_EQUAL(size, 10, int, "%d");
	BC_ASSERT_EQUAL(col, 10, int, "%d");
	BC_ASSERT_EQUAL(row, 1, int, "%d");
	BC_ASSERT_EQUAL(rowRepair.size(), 1, size_t, "%zu");
	BC_ASSERT_EQUAL(colRepair.size(), 0, size_t, "%zu");

	delete params;
	rtp_session_destroy(session);
}
static void encoder_init2D_test(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecParameters *params = newFecParams(10, 10, 200000);
	FecEncoder cluster(params);
	cluster.init(session,session);

	auto rowRepair = cluster.getRowRepair();
	auto colRepair = cluster.getColRepair();
	auto size = cluster.getSize();
	auto col = cluster.getColumns();
	auto row = cluster.getRows();

	BC_ASSERT_EQUAL(size, 100, int, "%d");
	BC_ASSERT_EQUAL(col, 10, int, "%d");
	BC_ASSERT_EQUAL(row, 10, int, "%d");
	BC_ASSERT_EQUAL(rowRepair.size(), 10, size_t, "%zu");
	BC_ASSERT_EQUAL(colRepair.size(), 10, size_t, "%zu");

	delete params;
	rtp_session_destroy(session);
}
static void encoder_add1D_test(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecParameters *params = newFecParams(5, 0, 200000);
	FecEncoder cluster(params);
	cluster.init(session, session);
	uint8_t *sourcePayload = NULL;
	uint8_t *repairPayload = NULL;

	mblk_t *packet = newPacketWithLetter(session, 0, 123456, 'a', 150);
	FecSourcePacket source(packet);
	cluster.add(source);

	auto repair = cluster.getRowRepair(0);

	size_t repairSize = repair->repairPayloadStart(&repairPayload);
	size_t sourceSize = source.getPayloadBuffer(&sourcePayload);

	BC_ASSERT_TRUE(repair->extractBitstring().equals(source.getBitstring()));
	BC_ASSERT_EQUAL(repairSize, sourceSize, size_t, "%zu");
	BC_ASSERT_TRUE(memcmp(sourcePayload, repairPayload, sourceSize) == 0);

	delete params;
	freemsg(packet);
	rtp_session_destroy(session);
}
static void encoder_add2D_test(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecParameters *params = newFecParams(5, 5, 200000);
	FecEncoder cluster(params);
	cluster.init(session,session);

	uint8_t *sourcePayload = NULL;
	uint8_t *rowRepairPayload = NULL;
	uint8_t *colRepairPayload = NULL;

	mblk_t *packet = newPacketWithLetter(session, 0, 123456, 'a', 150);
	FecSourcePacket source(packet);
	cluster.add(source);

	auto row = cluster.getRowRepair(0);
	auto col = cluster.getColRepair(0);

	size_t rowRepairSize = row->repairPayloadStart(&rowRepairPayload);
	size_t colRepairSize = col->repairPayloadStart(&colRepairPayload);

	size_t sourceSize = source.getPayloadBuffer(&sourcePayload);

	BC_ASSERT_TRUE(row->extractBitstring().equals(source.getBitstring()));
	BC_ASSERT_EQUAL(rowRepairSize, sourceSize, size_t, "%zu");
	BC_ASSERT_TRUE(memcmp(sourcePayload, rowRepairPayload, sourceSize) == 0);
	BC_ASSERT_TRUE(col->extractBitstring().equals(source.getBitstring()));
	BC_ASSERT_EQUAL(colRepairSize, sourceSize, size_t, "%zu");
	BC_ASSERT_TRUE(memcmp(sourcePayload, colRepairPayload, sourceSize) == 0);

	delete params;
	freemsg(packet);
	rtp_session_destroy(session);
}

static void encoder_areFull_test(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecParameters *params = newFecParams(5, 5, 200000);
	FecEncoder cluster(params);
	cluster.init(session,session);
	mblk_t *packet = NULL;
	for (int i = 0; i < cluster.getSize(); i++) {
		packet = newPacketWithLetter(session, i, i * 60, 'a' + i, 150 + i);
		FecSourcePacket source(packet);
		cluster.add(source);
		if (((i % cluster.getColumns()) == (cluster.getColumns())))
			BC_ASSERT_TRUE(cluster.isRowFull());
		if (i >= 20 && i < 25)
			BC_ASSERT_TRUE(cluster.isColFull());
		freemsg(packet);
	}
	BC_ASSERT_TRUE(cluster.isFull());
	delete params;

	rtp_session_destroy(session);
}

static void encoder_fill_test(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecParameters *params = newFecParams(5, 3, 200000);
	FecEncoder encoder(params);
	encoder.init(session,session);

	for (int i = 0; i < 15; i++) {

		mblk_t *packet = newPacketWithLetter(session, i, i * 20, 'a' + i, 10);
		FecSourcePacket source(packet);
		if (encoder.isFull()) {
			encoder.reset(i);
		}
		encoder.add(source);
		freemsg(packet);
	}
	uint8_t *rptr = NULL;
	encoder.getColRepair(0)->repairPayloadStart(&rptr);
	uint8_t value = ('a' ^ 'f' ^ 'k');

	for (int i = 0; i < 10; i++) {
		BC_ASSERT_EQUAL(*rptr, value, uint8_t, "%u");
	}

	delete params;
	rtp_session_destroy(session);
}

static void encoder_reset(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecParameters *params = newFecParams(5, 0, 200000);
	FecEncoder encoder(params);
	encoder.init(session,session);

	mblk_t *expected = encoder.getRowRepairMblk(0);

	mblk_t *packet = NULL;
	for (int i = 0; i < 5; i++) {
		packet = newPacketWithLetter(session, i, i * 60, 'a' + i, 150 + i);
		FecSourcePacket source(packet);
		encoder.add(source);
		freemsg(packet);
	}
	encoder.reset(0);

	auto actual = encoder.getRowRepairMblk(0);
	BC_ASSERT_TRUE(packets_are_equals(expected, actual));
	rtp_session_destroy(session);
	freemsg(expected);
	freemsg(actual);

	delete params;
}

static void recieve_cluster_add_test(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	auto cluster = RecieveCluster(session, 200);
	mblk_t *packet = NULL;
	for (int i = 0; i <= 10; i++) {
		packet = newPacketWithLetter(session, i, i * 20, 'a' + i, 150 + i);
		std::shared_ptr<FecSourcePacket> source(new FecSourcePacket(packet));
		cluster.add(i, source);
		freemsg(packet);
	}

	BC_ASSERT_TRUE(cluster.isFull());
	packet = newPacketWithLetter(session, 11, 220, 'z', 150);
	std::shared_ptr<FecSourcePacket> next(new FecSourcePacket(packet));
	cluster.add(11, next);
	BC_ASSERT_TRUE(cluster.isFull());
	auto source = cluster.getSource();
	auto notFound = source.find(0);
	BC_ASSERT_TRUE((notFound == source.end()));
	rtp_session_destroy(session);
	freemsg(packet);
}

static void recieve_cluster_repairOne_test(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	int L = 5;
	int missing = 1;
	auto cluster = RecieveCluster(session, 200);
	std::shared_ptr<FecRepairPacket> repair(new FecRepairPacket(session,session, 0, L, 0));
	std::vector<std::shared_ptr<FecSourcePacket>> base;
	mblk_t *packet = NULL;

	for (int i = 0; i < L; i++) {
		packet = newPacketWithLetter(session, i, i * 20, 'a' + i, 150 + i);
		std::shared_ptr<FecSourcePacket> source(new FecSourcePacket(packet));
		base.push_back(source);
		repair->add(*source);
		if (i != missing)
			cluster.add(i, source);
		freemsg(packet);
	}
	cluster.repairOne(*repair);
	auto missingSource = cluster.getSourcePacket(missing);
	BC_ASSERT_PTR_NOT_NULL(missingSource);
	BC_ASSERT_TRUE(packets_are_equals(base[missing]->getPacket(), missingSource->getPacket()));

	rtp_session_destroy(session);
}

static void recieve_cluster_repair1DNonInterleaved_test(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	int L = 5;
	int missing = 1;
	RecieveCluster cluster = RecieveCluster(session, 200);
	std::shared_ptr<FecRepairPacket> repair(new FecRepairPacket(session, session, 0, L, 0));
	std::vector<std::shared_ptr<FecSourcePacket>> base;
	mblk_t *packet = NULL;

	for (int i = 0; i < L; i++) {
		packet = newPacketWithLetter(session, i, i * 20, 'a' + i, 150 + i);
		std::shared_ptr<FecSourcePacket> source(new FecSourcePacket(packet));
		base.push_back(source);
		repair->add(*source);
		if (i != missing)
			cluster.add(i, source);
		freemsg(packet);
	}
	cluster.add(repair);
	cluster.repair1D(false);

	auto source = cluster.getSourcePacket(missing);
	BC_ASSERT_PTR_NOT_NULL(source);
	BC_ASSERT_TRUE(packets_are_equals(base[missing]->getPacket(), source->getPacket()));

	rtp_session_destroy(session);
}

static void recieve_cluster_repair1DInterleaved_test(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	int L = 5;
	int D = 5;
	int missing = 5;
	auto cluster = RecieveCluster(session, 400);
	std::shared_ptr<FecRepairPacket> repair(new FecRepairPacket(session, session, 0, L, D));
	std::vector<std::shared_ptr<FecSourcePacket>> base;
	mblk_t *packet = NULL;

	for (int i = 0; i < L * D; i += L) {
		packet = newPacketWithLetter(session, i, 20 * i, 'a' + i, 150);
		std::shared_ptr<FecSourcePacket> source(new FecSourcePacket(packet));
		base.push_back(source);
		repair->add(*source);
		if (i != missing)
			cluster.add(i, source);
		freemsg(packet);
	}
	cluster.add(repair);
	cluster.repair1D(true);

	auto source = cluster.getSourcePacket(missing);
	BC_ASSERT_PTR_NOT_NULL(source);
	BC_ASSERT_TRUE(packets_are_equals(base[1]->getPacket(), source->getPacket()));

	rtp_session_destroy(session);
}

static void encode_decode_test(void) {

	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecParameters *params = newFecParams(5, 5, 200000);
	FecEncoder encoder(params);
	encoder.init(session,session);
	RecieveCluster cluster(session, 500);
	mblk_t *packet = NULL;
	int missing = 12;
	std::shared_ptr<FecSourcePacket> p;

	for (int i = 0; i < 25; i++) {
		packet = newPacketWithLetter(session, i, i * 5, ('a' + i) % 26, 1000);
		if (encoder.isFull()) {
			encoder.reset(i);
		}
		std::shared_ptr<FecSourcePacket> source(new FecSourcePacket(packet));
		encoder.add(*source);
		if (encoder.isRowFull()) {
			int row = encoder.getCurrentRow();
			auto rowRepair = encoder.getRowRepair(row);
			cluster.add(rowRepair);
		}
		if (encoder.isColFull()) {
			int col = encoder.getCurrentRow();
			auto colRepair = encoder.getColRepair(col);
			cluster.add(colRepair);
		}

		if (i != missing) {
			cluster.add(i, source);
		} else {
			p = source;
		}
		freemsg(packet);
	}
	auto find = cluster.getSourcePacket(missing);
	BC_ASSERT_PTR_NULL(find);
	cluster.repair1D(false);
	find = cluster.getSourcePacket(missing);
	BC_ASSERT_PTR_NOT_NULL(find);
	BC_ASSERT_TRUE(packets_are_equals(p->getPacket(), find->getPacket()));
	rtp_session_destroy(session);
	delete params;
}

static void encode_decode_2D_test(void) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	FecParameters *params = newFecParams(5, 5, 200000);
	FecEncoder encoder(params);
	encoder.init(session,session);
	RecieveCluster cluster(session, 500);
	mblk_t *packet = NULL;
	int missing[25] = {1,0,1,0,0,0,0,0,0,0,0,1,0,1,0,0,0,0,0,0,0,0,1,1,1};
	std::vector <std::shared_ptr<FecSourcePacket> > missed;

	for (int i = 0; i < 25; i++) {
		packet = newPacketWithLetter(session, i, i * 5, ('a' + i) % 26, 1000);
		if (encoder.isFull()) {
			encoder.reset(i);
		}
		std::shared_ptr<FecSourcePacket> source(new FecSourcePacket(packet));
		encoder.add(*source);
		if (encoder.isRowFull()) {
			int row = encoder.getCurrentRow();
			auto rowRepair = encoder.getRowRepair(row);
			cluster.add(rowRepair);
		}
		if (encoder.isColFull()) {
			int col = encoder.getCurrentColumn();
			auto colRepair = encoder.getColRepair(col);
			cluster.add(colRepair);
		}

		if (!missing[i]) {
			cluster.add(i, source);
		} else {
			missed.emplace_back(source);
		}
		freemsg(packet);
	}
	for(int i = 0; i<25; i++){
		
		if(!missing[i]) continue;		
		auto find = cluster.getSourcePacket(i);
		BC_ASSERT_PTR_NULL(find);
		
	}
	cluster.repair2D();
	int miss = 0;
	for(int i = 0; i<25; i++){
		if(!missing[i]) continue;		
		auto find = cluster.getSourcePacket(i);
		BC_ASSERT_PTR_NOT_NULL(find);
		if(find)
			BC_ASSERT_TRUE(packets_are_equals(missed[miss]->getPacket(), find->getPacket()));
		miss++;
	}
	rtp_session_destroy(session);
	delete params;
}

static test_t tests[] = {

	TEST_NO_TAG("bitstring add", bitstring_add_test),
	TEST_NO_TAG("source_packet_get_payload", source_packet_get_payload_test),
	TEST_NO_TAG("source_packet_add_payload same size", source_packet_add_payload_test1),
	TEST_NO_TAG("source_packet_add_payload bigger", source_packet_add_payload_test2),
	TEST_NO_TAG("source_packet_add_payload smaller", source_packet_add_payload_test3),
	TEST_NO_TAG("repair_packet_bitstring", repair_packet_bitstring_test),
	TEST_NO_TAG("repair_packet_add Payload", repair_packet_add_payload1),
	TEST_NO_TAG("repair packet seqnum list non interleaved", repair_packet_seqnumListNonInterleaved_test),
	TEST_NO_TAG("repair packet seqnum list interleaved", repair_packet_seqnumListInterleaved_test),

	TEST_NO_TAG("encoder init1D", encoder_init1D_test),
	TEST_NO_TAG("encoder init2D", encoder_init2D_test),
	TEST_NO_TAG("encoder add1D", encoder_add1D_test),
	TEST_NO_TAG("encoder add2D", encoder_add2D_test),
	TEST_NO_TAG("encoder fill", encoder_fill_test),

	TEST_NO_TAG("encoder reset", encoder_reset),
	TEST_NO_TAG("encoder are full", encoder_areFull_test),
	TEST_NO_TAG("recieve cluster add", recieve_cluster_add_test),

	TEST_NO_TAG("recieve cluster repair one", recieve_cluster_repairOne_test),
	TEST_NO_TAG("recieve cluster repair 1D non interleaved", recieve_cluster_repair1DNonInterleaved_test),
	TEST_NO_TAG("recieve cluster repair 1D interleaved", recieve_cluster_repair1DInterleaved_test),
	TEST_NO_TAG("encode decode", encode_decode_test),
	TEST_NO_TAG("encode decode 2D", encode_decode_2D_test),
};

test_suite_t fec_test_suite = {
	"FEC",							  // Name of test suite
	NULL,							  // Before all callback
	NULL,							  // After all callback
	NULL,							  // Before each callback
	NULL,							  // After each callback
	sizeof(tests) / sizeof(tests[0]), // Size of test table
	tests							  // Table of test suite
};
