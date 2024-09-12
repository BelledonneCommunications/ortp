/*
 * Copyright (c) 2010-2024 Belledonne Communications SARL.
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

#include <inttypes.h>

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
extern "C" void fec_stream_unsubscribe(FecStream *fec_stream, FecParams *fecParams) {
	((FecStreamCxx *)fec_stream)->removeFromParamSubscribers((FecParamsController *)fecParams);
}
extern "C" void fec_stream_reset_cluster(FecStream *fec_stream) {
	((FecStreamCxx *)fec_stream)->resetCluster();
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
extern "C" void fec_stream_count_lost_packets(FecStream *fec_stream, uint16_t new_seqnum_received, int16_t diff) {
	((FecStreamCxx *)fec_stream)->countLostPackets(new_seqnum_received, diff);
}
extern "C" void fec_stream_print_stats(FecStream *fec_stream) {
	((FecStreamCxx *)fec_stream)->printStats();
}
extern "C" fec_stats *fec_stream_get_stats(FecStream *fec_stream) {
	return ((FecStreamCxx *)fec_stream)->getStats();
}
extern "C" bool_t fec_stream_enabled(FecStream *fec_stream) {
	return ((FecStreamCxx *)fec_stream)->isEnabled();
}
extern "C" float fec_stream_get_overhead(FecStream *fec_stream) {
	return ((FecStreamCxx *)fec_stream)->getMeasuredOverhead();
}
extern "C" void fec_stream_reset_overhead_measure(FecStream *fec_stream) {
	((FecStreamCxx *)fec_stream)->resetMeasuredOverhead();
}

FecStreamCxx::FecStreamCxx(struct _RtpSession *source, struct _RtpSession *fec, FecParamsController *fecParams)
    : mEncoder(fecParams), mCluster(source, fecParams->getRepairWindow()), mIsEnabled(false) {
	mSourceSession = source;
	mFecSession = fec;
	rtp_session_enable_jitter_buffer(mFecSession, FALSE);
	mSourceSession->fec_stream = (FecStream *)this;
	mFecSession->fec_stream = NULL;
	qinit(&mSourcePackets);
	RtpBundle *bundle = mSourceSession->bundle;
	RtpSession *session = rtp_bundle_get_primary_session(bundle);
	rtp_session_get_transports(session, &mTransport, NULL);
	mModifier = ortp_new0(RtpTransportModifier, 1);
	mModifier->level = RtpTransportModifierLevelForwardErrorCorrection;
	mModifier->data = this;
	mModifier->t_process_on_send = FecStreamCxx::processOnSend;
	mModifier->t_process_on_receive = FecStreamCxx::processOnReceive;
	mModifier->t_process_on_schedule = NULL;
	mModifier->t_destroy = modifierFree;
	meta_rtp_transport_append_modifier(mTransport, mModifier);

	mEncoderUpdate.L = fecParams->getL();
	mEncoderUpdate.D = fecParams->getD();
	mEncoderUpdate.is2D = fecParams->is2D();
	mEncoderUpdate.isUpdated = false;
	fecParams->addSubscriber(this);
	mEncoder.init(mFecSession, mSourceSession);
	mMeasuredOverhead.reset(0);
	mEncoderUpdate.isUpdated = true;
}

FecStreamCxx::~FecStreamCxx() {
	std::lock_guard<std::mutex> guard(mQueueMutex);
	flushq(&mSourcePackets, FLUSHALL);

	meta_rtp_transport_remove_modifier(mTransport, mModifier);
	modifierFree(mModifier);
	mModifier = nullptr;
	mTransport = nullptr;
}

void FecStreamCxx::removeFromParamSubscribers(FecParamsController *fecParams) {
	fecParams->removeSubscriber(this);
}

int FecStreamCxx::processOnSend(struct _RtpTransportModifier *m, mblk_t *packet) {

	FecStreamCxx *fecStream = (FecStreamCxx *)m->data;
	RtpSession *sourceSession = fecStream->getSourceSession();
	size_t ret = msgdsize(packet);
	uint32_t ssrc = rtp_get_ssrc(packet);

	if (!fecStream->isEnabled()) return (int)ret;

	if (ssrc == rtp_session_get_send_ssrc(sourceSession)) {
		fecStream->onNewSourcePacketSent(copymsg(packet));
	}
	return (int)ret;
}

int FecStreamCxx::processOnReceive(struct _RtpTransportModifier *m, mblk_t *packet) {
	FecStreamCxx *fecStream = (FecStreamCxx *)m->data;
	RtpSession *sourceSession = fecStream->getSourceSession();
	uint32_t ssrc = rtp_get_ssrc(packet);
	size_t ret = msgdsize(packet);
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

	std::lock_guard<std::recursive_mutex> guard(mSendMutex);
	if (!mEncoderUpdate.isUpdated) updateEncoder();
	if (!mIsEnabled) return;
	if (mEncoder.isFull() || mEncoder.isEmpty()) {
		mEncoder.reset(seqnum);
		mMeasuredOverhead.resetEncoder();
	}

	auto source = std::make_shared<FecSourcePacket>(packet);
	mEncoder.add(*source);
	size_t msgSizeSource = msgdsize(packet);

	mMeasuredOverhead.sendSourcePacket(msgSizeSource, mEncoder.getCurrentColumn());

	if (mEncoder.isRowFull()) {
		int i = mEncoder.getCurrentRow();
		mblk_t *rowRepair = mEncoder.getRowRepairMblk(i);
		if (rowRepair) {
			rtp_set_timestamp(rowRepair, timestamp);
			rtp_set_seqnumber(rowRepair, rtp_session_get_seq_number(mFecSession));
			ortp_debug("row repair sent [%u] | %u | seqNumBase %u", timestamp, rtp_get_seqnumber(rowRepair),
			           mEncoder.getRowRepair(i)->getSeqnumBase());
			size_t msgSizeRepair = msgdsize(rowRepair);
			mMeasuredOverhead.sendRepairPacket(msgSizeRepair, mEncoder.getCurrentColumn());
			rtp_session_sendm_with_ts(mFecSession, rowRepair, timestamp);
			mStats.rowRepairSent();
		}
	}
	if (mEncoder.isColFull()) {
		int i = mEncoder.getCurrentColumn();
		mblk_t *colRepair = mEncoder.getColRepairMblk(i);
		if (colRepair) {
			rtp_set_timestamp(colRepair, timestamp);
			rtp_set_seqnumber(colRepair, rtp_session_get_seq_number(mFecSession));
			ortp_debug("col repair sent  [%u] | %u | seqNumBase %u", timestamp, rtp_get_seqnumber(colRepair),
			           mEncoder.getColRepair(i)->getSeqnumBase());
			size_t msgSizeRepair = msgdsize(colRepair);
			mMeasuredOverhead.sendRepairPacket(msgSizeRepair, mEncoder.getCurrentColumn());
			rtp_session_sendm_with_ts(mFecSession, colRepair, timestamp);
			mStats.colRepairSent();
		}
	}

	if (mEncoder.isFull()) {
		mMeasuredOverhead.encoderFull();
	}
}

void FecStreamCxx::onNewSourcePacketReceived(mblk_t *packet) {
	msgpullup(packet, -1);
	if (rtp_get_version(packet) != 2) return;
	mblk_t *packet_copy = copymsg(packet);

	// To avoid thread contention between the audio thread that receives the source packets and the video stream that
	// uses them for lost packet recovery with flexible FEC, the source packets received are copied into a queue by the
	// audio thread and transferred to the receive cluster by the video thread for the FEC processings.
	std::lock_guard<std::mutex> guard(mQueueMutex);
	putq(&mSourcePackets, packet_copy);

	// The size of the queue is controlled because if no repair packet is received (for example when the FEC is
	// disabled) and any source packet is lost, the source packets are never transferred to the receive cluster
	if (mSourcePackets.q_mcount > 100) {
		mblk_t *erase = qbegin(&mSourcePackets);
		remq(&mSourcePackets, erase);
		if (erase != NULL) freemsg(erase);
	}
}

void FecStreamCxx::receiveRepairPacket(uint32_t timestamp) {

	mblk_t *repair_packet = rtp_session_recvm_with_ts(mFecSession, timestamp);
	if (repair_packet == NULL) return;

	// add last source packets
	updateReceivedSourcePackets();

	// add new repair packet
	auto repair = std::make_shared<FecRepairPacket>(repair_packet);
	std::lock_guard<std::recursive_mutex> guard(mReceiveMutex);
	mCluster.add(repair);
	mStats.rowRepairReceived(mCluster.getRowRepairCpt());
	mStats.colRepairReceived(mCluster.getColRepairCpt());
	freemsg(repair_packet);
}

void FecStreamCxx::resetCluster() {
	std::lock_guard<std::recursive_mutex> guard(mReceiveMutex);
	mCluster.reset();
	mStats.clearAll();
}

void FecStreamCxx::updateReceivedSourcePackets() {
	std::lock_guard<std::mutex> guard(mQueueMutex);
	while (mSourcePackets.q_mcount > 0) {
		mblk_t *mp = getq(&mSourcePackets);
		mCluster.add(mp);
	}
}

void FecStreamCxx::countLostPackets(uint16_t newSeqnumReceived, int16_t diff) {
	mStats.definitelyLostPacket(newSeqnumReceived, diff);
}

void FecStreamCxx::printStats() {
	mStats.printStats(mSourceSession, mFecSession);
}

mblk_t *FecStreamCxx::findMissingPacket(uint16_t seqnum) {

	mStats.askedPacket(seqnum);
	std::shared_ptr<FecSourcePacket> packet;

	// recover
	updateReceivedSourcePackets();
	{
		std::lock_guard<std::recursive_mutex> guard(mReceiveMutex);
		mCluster.repair(seqnum);
		packet = mCluster.getSourcePacket(seqnum);
	}
	if (!packet) {
		return nullptr;
	}

	// apply modifier
	mblk_t *mp = packet->getPacketCopy();
	RtpTransport *transport = NULL;
	ortp_mutex_lock(&mSourceSession->main_mutex);
	RtpBundle *bundle = mSourceSession->bundle;
	RtpSession *session = bundle ? rtp_bundle_get_primary_session(bundle) : nullptr;
	ortp_mutex_unlock(&mSourceSession->main_mutex);
	if (session) {
		rtp_session_get_transports(session, &transport, NULL);
		if (meta_rtp_transport_apply_all_except_one_on_receive(transport, mModifier, mp) >= 0) {
			mStats.repairedPacket(seqnum);
			ortp_debug("fecstream[%p] Source packet recovered : SeqNum = %u, current stats : %u lost, %u recovered, %u "
			           "not repaired",
			           this, rtp_get_seqnumber(mp), static_cast<unsigned int>(mStats.getPacketsLost()),
			           static_cast<unsigned int>(mStats.getPacketsRecovered()),
			           static_cast<unsigned int>(mStats.getPacketsNotRecovered()));
			return mp;
		}
	}
	freemsg(mp);
	return nullptr;
}

RtpSession *FecStreamCxx::getFecSession() const {
	return mFecSession;
}

RtpSession *FecStreamCxx::getSourceSession() const {
	return mSourceSession;
}

fec_stats *FecStreamCxx::getStats() {
	return mStats.getFecStats();
}

bool FecStreamCxx::isEnabled() {
	std::lock_guard<std::recursive_mutex> guard(mSendMutex);
	return mIsEnabled;
}

void FecStreamCxx::updateEncoder() {
	if (mIsEnabled) {
		mEncoder.update(mEncoderUpdate.L, mEncoderUpdate.D, mEncoderUpdate.is2D);
	} else {
		mEncoder.clear();
	}
	mEncoderUpdate.isUpdated = true;
}

void FecStreamCxx::update(FecParamsController *params) {
	std::lock_guard<std::recursive_mutex> guard(mSendMutex);
	mEncoderUpdate.isUpdated = false;
	size_t overheadColNb = 1;
	if (params->getEnabled()) {
		mIsEnabled = true;
		mEncoderUpdate.L = params->getL();
		mEncoderUpdate.D = params->getD();
		mEncoderUpdate.is2D = params->is2D();
		if (!mEncoderUpdate.is2D && mEncoderUpdate.D > 0) {
			overheadColNb = static_cast<size_t>(mEncoderUpdate.L);
		}
	} else {
		mIsEnabled = false;
	};
	resetMeasuredOverhead(overheadColNb);
}

void FecStreamCxx::resetMeasuredOverhead() {
	std::lock_guard<std::recursive_mutex> guard(mSendMutex);
	mMeasuredOverhead.reset(1);
}

void FecStreamCxx::resetMeasuredOverhead(size_t columnNumber) {
	std::lock_guard<std::recursive_mutex> guard(mSendMutex);
	mMeasuredOverhead.reset(columnNumber);
}

float FecStreamCxx::getMeasuredOverhead() {
	std::lock_guard<std::recursive_mutex> guard(mSendMutex);
	return mMeasuredOverhead.computeOverheadEstimator();
};
