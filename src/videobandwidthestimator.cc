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

#include "videobandwidthestimator.h"
#include <math.h>
#include <ortp/logging.h>
#include <ortp/rtpsession.h>

#include <algorithm>
#include <deque>

#define MIN_DIFFTIME 0.00001f

namespace ortp {

struct VBEInProgressMeasurement {
	void reset() {
		mRtpTimestamp = 0;
		mFirstTimestamp = {0, 0};
		mLastTimestamp = {0, 0};
		mBytes = 0;
		mPackets = 0;
	}
	uint32_t mRtpTimestamp;
	struct timeval mFirstTimestamp;
	struct timeval mLastTimestamp;
	unsigned int mBytes;
	unsigned int mPackets;
};

struct VBEMeasurement {
	float mBitrate;
};

struct VBEMeasurementGreater {
	constexpr bool operator()(const VBEMeasurement &m1, const VBEMeasurement &m2) const {
		return m1.mBitrate > m2.mBitrate;
	}
};

class VideoBandwidthEstimator {
public:
	VideoBandwidthEstimator(RtpSession *session) : mSession(session) {
		reset();
	}
	void reset() {
		mCurrentMeasurement.reset();
		mMeasurements.clear();
	}
	void setMinPacketCount(unsigned int count) {
		mPacketCountMin = count;
	}
	unsigned int getMinPacketCount() const {
		return mPacketCountMin;
	}
	void setTrustPercentage(unsigned int trust) {
		mTrustPercetage = trust;
	}
	unsigned int getTrustPercentage() const {
		return mTrustPercetage;
	}
	void setMinMeasurements(unsigned int count) {
		mMinMeasurements = (size_t)count;
	}
	unsigned int getMinMeasurements() const {
		return mMinMeasurements;
	}
	float makeAvailableBandwidthEstimate();
	void processPacket(uint32_t sent_timestamp, const struct timeval *recv_timestamp, int msgsize, bool_t is_last);
	static VideoBandwidthEstimator *toCpp(OrtpVideoBandwidthEstimator *vbe) {
		return reinterpret_cast<VideoBandwidthEstimator *>(vbe);
	}
	static const VideoBandwidthEstimator *toCpp(const OrtpVideoBandwidthEstimator *vbe) {
		return reinterpret_cast<const VideoBandwidthEstimator *>(vbe);
	}

private:
	void initializeMeasurement(uint32_t sent_timestamp, const struct timeval *recv_timestamp);
	void processMeasurement();
	void endMeasurement();
	bool periodElapsed(const struct timeval &now) {
		float duration =
		    (now.tv_sec - mAquisitionBegin.tv_sec) + ((float)(now.tv_usec - mAquisitionBegin.tv_usec)) / 1000000.0f;
		return duration >= (float)mMinInterval;
	}
	RtpSession *mSession = nullptr;
	unsigned int mPacketCountMin = 5;
	unsigned int mTrustPercetage = 90;
	size_t mMinMeasurements = 50;
	int mMinInterval = 5; // in seconds
	struct timeval mAquisitionBegin;
	VBEInProgressMeasurement mCurrentMeasurement;
	std::deque<VBEMeasurement> mMeasurements;
};

float VideoBandwidthEstimator::makeAvailableBandwidthEstimate() {
	size_t index = (mTrustPercetage * mMeasurements.size()) / 100;
	std::sort(mMeasurements.begin(), mMeasurements.end(), VBEMeasurementGreater());
	float estimate = mMeasurements[index].mBitrate;
	ortp_message("[VBE]: front: %f  back: %f, index: %i, size: %i, new estimate: %f bit/s",
	             mMeasurements.front().mBitrate, mMeasurements.back().mBitrate, (int)index, (int)mMeasurements.size(),
	             estimate);
	mMeasurements.clear();
	return estimate;
}

void VideoBandwidthEstimator::processMeasurement() {
	float difftime = (float)(mCurrentMeasurement.mLastTimestamp.tv_sec - mCurrentMeasurement.mFirstTimestamp.tv_sec) +
	                 1e-6f * (mCurrentMeasurement.mLastTimestamp.tv_usec - mCurrentMeasurement.mFirstTimestamp.tv_usec);

	if (difftime > MIN_DIFFTIME) {
		if (mMeasurements.empty()) {
			mAquisitionBegin = mCurrentMeasurement.mLastTimestamp;
		}

		float bitrate = (mCurrentMeasurement.mBytes * 8 / difftime);
		mMeasurements.emplace_front(VBEMeasurement{bitrate});

		// ortp_message("VBE: added measure of %f bit/s", bitrate);

		/* if the observed volume of data exceeds our threshold, make an estimate */
		if (mMeasurements.size() > mMinMeasurements && periodElapsed(mCurrentMeasurement.mLastTimestamp)) {
			OrtpEvent *ev = ortp_event_new(ORTP_EVENT_NEW_VIDEO_BANDWIDTH_ESTIMATION_AVAILABLE);
			OrtpEventData *ed = ortp_event_get_data(ev);
			ed->info.video_bandwidth_available = makeAvailableBandwidthEstimate();
			ortp_debug(
			    "[VBE] Dispatching event ORTP_EVENT_NEW_VIDEO_BANDWIDTH_ESTIMATION_AVAILABLE with value %f kbits/s",
			    ed->info.video_bandwidth_available / 1000);
			rtp_session_dispatch_event(mSession, ev);
		}
	} else {
		// The mesaurement cannot be used.
	}
}

void VideoBandwidthEstimator::initializeMeasurement(uint32_t sent_timestamp, const struct timeval *recv_timestamp) {
	mCurrentMeasurement.mRtpTimestamp = sent_timestamp;
	mCurrentMeasurement.mFirstTimestamp = *recv_timestamp;
	mCurrentMeasurement.mPackets = 1;
	// ignore bytes received: this is the first packet
}

void VideoBandwidthEstimator::endMeasurement() {
	if (mCurrentMeasurement.mPackets >= mPacketCountMin) {
		processMeasurement();
	} // else not enough packets for this measurement, drop it.
	mCurrentMeasurement.reset();
}

void VideoBandwidthEstimator::processPacket(uint32_t sent_timestamp,
                                            const struct timeval *recv_timestamp,
                                            int msgsize,
                                            bool_t is_last) {
	if (mCurrentMeasurement.mPackets == 0) {
		initializeMeasurement(sent_timestamp, recv_timestamp);
	} else if (mCurrentMeasurement.mRtpTimestamp == sent_timestamp) {
		mCurrentMeasurement.mBytes += msgsize;
		mCurrentMeasurement.mPackets++;
		mCurrentMeasurement.mLastTimestamp = *recv_timestamp;
	} else {
		// Special case where the timestamp is discontinued. The current measurement may be used.
		endMeasurement();
		// And restart a new one.
		initializeMeasurement(sent_timestamp, recv_timestamp);
	}
	if (is_last) {
		endMeasurement();
	}
}

} // namespace ortp

using namespace ortp;

OrtpVideoBandwidthEstimator *ortp_video_bandwidth_estimator_new(RtpSession *session) {
	auto vbe = new VideoBandwidthEstimator(session);
	return (OrtpVideoBandwidthEstimator *)vbe;
}

void ortp_video_bandwidth_estimator_destroy(OrtpVideoBandwidthEstimator *vbe) {
	delete VideoBandwidthEstimator::toCpp(vbe);
}

void ortp_video_bandwidth_estimator_reset(OrtpVideoBandwidthEstimator *vbe) {
	VideoBandwidthEstimator::toCpp(vbe)->reset();
}

void ortp_video_bandwidth_estimator_set_packets_count_min(OrtpVideoBandwidthEstimator *vbe, unsigned int value) {
	VideoBandwidthEstimator::toCpp(vbe)->setMinPacketCount(value);
}

void ortp_video_bandwidth_estimator_set_trust(OrtpVideoBandwidthEstimator *vbe, unsigned int value) {
	VideoBandwidthEstimator::toCpp(vbe)->setTrustPercentage(value);
}

void ortp_video_bandwidth_estimator_set_min_measurements_count(OrtpVideoBandwidthEstimator *vbe, unsigned int value) {
	VideoBandwidthEstimator::toCpp(vbe)->setMinMeasurements(value);
}

unsigned int ortp_video_bandwidth_estimator_get_packets_count_min(OrtpVideoBandwidthEstimator *vbe) {
	return VideoBandwidthEstimator::toCpp(vbe)->getMinPacketCount();
}

unsigned int ortp_video_bandwidth_estimator_get_min_measurements_count(const OrtpVideoBandwidthEstimator *vbe) {
	return VideoBandwidthEstimator::toCpp(vbe)->getMinMeasurements();
}

unsigned int ortp_video_bandwidth_estimator_get_trust(OrtpVideoBandwidthEstimator *vbe) {
	return VideoBandwidthEstimator::toCpp(vbe)->getTrustPercentage();
}

float ortp_video_bandwidth_estimator_get_estimated_available_bandwidth(OrtpVideoBandwidthEstimator *vbe) {
	return VideoBandwidthEstimator::toCpp(vbe)->makeAvailableBandwidthEstimate();
}

void ortp_video_bandwidth_estimator_process_packet(OrtpVideoBandwidthEstimator *vbe,
                                                   uint32_t sent_timestamp,
                                                   const struct timeval *recv_timestamp,
                                                   int msgsize,
                                                   bool_t is_last) {
	VideoBandwidthEstimator::toCpp(vbe)->processPacket(sent_timestamp, recv_timestamp, msgsize, is_last);
}
