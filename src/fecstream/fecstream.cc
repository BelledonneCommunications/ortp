
#include "fecstream.h"

#define HEADER_1 '\x80'
#define HEADER_2 '\0'

using namespace ortp;

extern "C" FecStream *fec_stream_new(struct _RtpSession *source, struct _RtpSession *fec, FecParams *fecParams) {
	return (FecStream *)new FecStreamCxx(source, fec, (FecParamsController *)fecParams);
}
extern "C" void fec_stream_destroy(FecStream *fec_stream) {
	delete (FecStreamCxx *)fec_stream;
}
extern "C" void fec_stream_receive_repair_packet(FecStream *fec_stream, uint32_t timestamp) {
	((FecStreamCxx *)fec_stream)->receiveRepairPacket(timestamp);
}
extern "C" mblk_t *fec_stream_find_missing_packet(FecStream *fec_stream, uint16_t seqnum) {
	return ((FecStreamCxx *)fec_stream)->findMissingPacket(seqnum);
}
extern "C" RtpSession *fec_stream_get_fec_session(FecStream *fec_stream) {
	return ((FecStreamCxx *)fec_stream)->getFecSession();
}
extern "C" void fec_stream_print_stats(FecStream *fec_stream) {
	((FecStreamCxx *)fec_stream)->printStats();
}
extern "C" void fec_stream_init(FecStream *fec_stream) {
	((FecStreamCxx *)fec_stream)->init();
}
extern "C" fec_stats *fec_stream_get_stats(FecStream *fec_stream) {
	return ((FecStreamCxx *)fec_stream)->getStats();
}
extern "C" bool_t fec_stream_enabled(FecStream *fec_stream) {
	return ((FecStreamCxx *)fec_stream)->isEnabled();
}

FecStreamCxx::FecStreamCxx(struct _RtpSession *source, struct _RtpSession *fec, FecParamsController *fecParams)
    : mEncoder(fecParams), mCluster(source), mIsEnabled(true) {

	mSourceSession = source;
	mFecSession = fec;
	rtp_session_enable_jitter_buffer(mFecSession, FALSE);
	mSourceSession->fec_stream = (FecStream *)this;
	mFecSession->fec_stream = NULL;
	memset(&mStats, 0, sizeof(fec_stats));
	fecParams->addSubscriber(this);
}
void FecStreamCxx::init() {
	RtpTransport *transport = NULL;
	RtpBundle *bundle = (RtpBundle *)mSourceSession->bundle;
	RtpSession *session = rtp_bundle_get_primary_session(bundle);
	rtp_session_get_transports(session, &transport, NULL);

	mModifier = ortp_new0(RtpTransportModifier, 1);
	mModifier->level = RtpTransportModifierLevelForwardErrorCorrection;
	mModifier->data = this;
	mModifier->t_process_on_send = FecStreamCxx::processOnSend;
	mModifier->t_process_on_receive = FecStreamCxx::processOnReceive;
	mModifier->t_process_on_schedule = NULL;
	mModifier->t_destroy = modifierFree;
	meta_rtp_transport_append_modifier(transport, mModifier);

	mCluster.setModifier(mModifier);
	mEncoder.init(mFecSession, mSourceSession, 0U);
}
int FecStreamCxx::processOnSend(struct _RtpTransportModifier *m, mblk_t *packet) {

	FecStreamCxx *fecStream = (FecStreamCxx *)m->data;
	RtpSession *sourceSession = fecStream->getSourceSession();
	size_t ret = msgdsize(packet);
	uint32_t ssrc = rtp_get_ssrc(packet);
	if (!fecStream->isEnabled()) return (int)ret;
	if (ssrc == rtp_session_get_send_ssrc(sourceSession)) {
		fecStream->onNewSourcePacketSent(packet);
	}
	return (int)ret;
}

int FecStreamCxx::processOnReceive(struct _RtpTransportModifier *m, mblk_t *packet) {

	FecStreamCxx *fecStream = (FecStreamCxx *)m->data;
	RtpSession *sourceSession = fecStream->getSourceSession();
	uint32_t ssrc = rtp_get_ssrc(packet);
	size_t ret = msgdsize(packet);
	if (!fecStream->isEnabled()) return (int)ret;
	if (ssrc == rtp_session_get_recv_ssrc(sourceSession)) {
		fecStream->onNewSourcePacketReceived(packet);
	}
	return (int)ret;
}
void ortp::modifierFree(struct _RtpTransportModifier *m) {
	ortp_free(m);
}
void FecStreamCxx::onNewSourcePacketSent(mblk_t *packet) {

	uint16_t seqnum = rtp_get_seqnumber(packet);
	uint32_t timestamp = rtp_get_timestamp(packet);

	msgpullup(packet, -1);
	if (rtp_get_version(packet) != 2) return;

	auto source = std::make_shared<FecSourcePacket>(packet);

	if (mEncoder.isFull()) {
		mEncoder.reset(seqnum);
	}

	mEncoder.add(*source);
	if (mEncoder.isRowFull()) {
		int i = mEncoder.getCurrentRow();
		mblk_t *rowRepair = mEncoder.getRowRepairMblk(i);
		rtp_set_timestamp(rowRepair, timestamp);
		rtp_set_seqnumber(rowRepair, rtp_session_get_seq_number(mFecSession));
		// ortp_message("row repair sended [%u] | %u", timestamp, rtp_get_seqnumber(rowRepair));
		rtp_session_sendm_with_ts(mFecSession, rowRepair, timestamp);
		mStats.row_repair_sent++;
	}
	if (mEncoder.is2D() && mEncoder.isColFull()) {
		int i = mEncoder.getCurrentColumn();
		mblk_t *colRepair = mEncoder.getColRepairMblk(i);
		rtp_set_timestamp(colRepair, timestamp);
		rtp_set_seqnumber(colRepair, rtp_session_get_seq_number(mFecSession));
		// ortp_message("col repair sended  [%u] | %u", timestamp, rtp_get_seqnumber(colRepair));
		rtp_session_sendm_with_ts(mFecSession, colRepair, timestamp);
		mStats.col_repair_sent++;
	}
}

void FecStreamCxx::onNewSourcePacketReceived(mblk_t *packet) {

	uint16_t seqnum;

	msgpullup(packet, -1);
	if (rtp_get_version(packet) != 2) return;

	seqnum = rtp_get_seqnumber(packet);
	auto source = std::make_shared<FecSourcePacket>(packet);
	mCluster.add(seqnum, source);
}

void FecStreamCxx::receiveRepairPacket(uint32_t timestamp) {

	mblk_t *repair_packet = rtp_session_recvm_with_ts(mFecSession, timestamp);
	if (repair_packet == NULL) return;
	if (!mIsEnabled) return;
	auto repair = std::make_shared<FecRepairPacket>(repair_packet);
	mCluster.add(repair);
}
void FecStreamCxx::printStats() {

	double initialLossRate = (double)mStats.packets_lost / (double)mSourceSession->stats.packet_recv;
	double residualLossRate =
	    ((double)(mStats.packets_lost - mStats.packets_recovered) / (double)mSourceSession->stats.packet_recv);
	double recoveringRate = (double)mStats.packets_recovered / (double)mStats.packets_lost;

	ortp_log(ORTP_MESSAGE, "===========================================================");
	ortp_log(ORTP_MESSAGE, "               Forward Error Correction Stats              ");
	ortp_log(ORTP_MESSAGE, "-----------------------------------------------------------");
	ortp_log(ORTP_MESSAGE, "	row repair sended           %d packets", mStats.row_repair_sent);
	ortp_log(ORTP_MESSAGE, "	row repair received         %d packets", mStats.row_repair_received);
	ortp_log(ORTP_MESSAGE, "	col repair sended           %d packets", mStats.col_repair_sent);
	ortp_log(ORTP_MESSAGE, "	col repair received         %d packets", mStats.col_repair_received);
	ortp_log(ORTP_MESSAGE, "	packets lost                %d packets", mStats.packets_lost);
	ortp_log(ORTP_MESSAGE, "	packets recovered           %d packets", mStats.packets_recovered);
	ortp_log(ORTP_MESSAGE, "	initial loss rate           %f", initialLossRate);
	ortp_log(ORTP_MESSAGE, "	recovering rate             %f", recoveringRate);
	ortp_log(ORTP_MESSAGE, "	residual loss rate          %f", residualLossRate);
	ortp_log(ORTP_MESSAGE, "===========================================================");
}

mblk_t *FecStreamCxx::findMissingPacket(uint16_t seqnum) {

	mCluster.repair2D();
	auto packet = mCluster.getSourcePacket(seqnum);
	mStats.packets_lost++;
	if (!packet) return nullptr;

	mblk_t *mp = packet->getPacketCopy();
	RtpTransport *transport = NULL;
	RtpBundle *bundle = (RtpBundle *)mSourceSession->bundle;
	RtpSession *session = rtp_bundle_get_primary_session(bundle);
	rtp_session_get_transports(session, &transport, NULL);
	if (meta_rtp_transport_apply_all_except_one_on_receive(transport, mModifier, mp) >= 0) {
		ortp_message("Source packet reconstructed : SeqNum = %d;", (int)rtp_get_seqnumber(mp));
		mStats.packets_recovered++;
	}
	return mp;
}
RtpSession *FecStreamCxx::getFecSession() const {
	return mFecSession;
}
RtpSession *FecStreamCxx::getSourceSession() const {
	return mSourceSession;
}
fec_stats *FecStreamCxx::getStats() {
	return &mStats;
}
bool FecStreamCxx::isEnabled() {
	return mIsEnabled;
}
void FecStreamCxx::enable(FecParamsController *params) {
	mIsEnabled = true;
	mEncoder.update(params);
}
void FecStreamCxx::disable() {
	mIsEnabled = false;
	mEncoder.clear();
	mCluster.clear();
}
void FecStreamCxx::update(FecParamsController *params) {
	if (params->getEnabled()) enable(params);
	else disable();
}