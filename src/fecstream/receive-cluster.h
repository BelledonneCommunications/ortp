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

#ifndef RECIEVE_CLUSTER_H
#define RECIEVE_CLUSTER_H

#include <map>
#include <set>
#include <unordered_map>
#include <vector>

#include "fec-packets-connection.h"
#include "fec-params.h"
#include "packet-api.h"

namespace ortp {

#ifdef _WIN32
// Disable C4251 triggered by need to export all stl template classes
#pragma warning(disable : 4251)
#endif // ifdef _WIN32

class FecParamsController;

/** @class ReceiveCluster
 * @brief Class to recover lost RTP packets by applying the flexible FEC.
 *
 * This class receive the source and repair packets, store them for a limited time and trys to recover the
 * missing source packets if asked. The links between the repair packets and the source packets that they protect is
 * made by a FecPacketsConnection object. The repair window defines the maximal time interval where a packet can
 * be kept.
 */
class ORTP_PUBLIC ReceiveCluster {
public:
	/**
	 * This constructor initializes the object with the RTP session and the repair window.
	 *
	 * @param session RTP session of the source and repair packets.
	 * @param repairWindow Duration of the repair window in microseconds.
	 */
	ReceiveCluster(struct _RtpSession *session, uint32_t repairWindow);

	/**
	 * Add a new source packet to the cluster. Erase the oldest source packets that are out the repair window. Warning:
	 * the input source packet is not copied.
	 *
	 * @param mp Source packet.
	 */
	void add(mblk_t *mp);

	/**
	 * Add a new repair packet to the cluster, either on the map of row repair packets or on the map of column repair
	 * packets. Erase the oldest repair packets that are out the repair window. The FEC graph is updated: the erased
	 * repair packets are removed and the new one is added.
	 *
	 * @param packet Repair packet.
	 */
	void add(const std::shared_ptr<FecRepairPacket> &packet);

	/**
	 * Return a source packet identified by its sequence number seqnum if it exists in the map mSource, otherwise return
	 * a null pointer.
	 *
	 * @param seqnum Sequence number of the source packet.
	 */
	std::shared_ptr<FecSourcePacket> getSourcePacket(uint16_t seqnum) const;

	/**
	 * Search the source packet with sequence number seqNum. If it doesn't exists in the map of source packet, try to
	 * recover it with the help of a set of repair packets and the recovering method of flexible FEC. The set of repair
	 * packets that are related to the missing source packet is identified by the FEC graph. Then the decoding algorithm
	 * is applied. Each source packet that is recovered then is added to the map of source packets.
	 *
	 * @param seqnum Sequence number of the source packet.
	 */
	void repair(uint16_t seqNum);

	/**
	 * Counter of row repair packets received.
	 */
	uint64_t getRowRepairCpt() const {
		return mRowRepairCpt;
	};

	/**
	 * Counter of column repair packets received.
	 */
	uint64_t getColRepairCpt() const {
		return mColRepairCpt;
	};

	/**
	 * Clear all packets and reset the FEC graph.
	 */
	void reset();

	~ReceiveCluster(){};

private:
	/**
	 * Apply the 2D iterative decoding algorithm described in RFC 8627 section 6.3.4 to try to recover the missing
	 * source packets protceted by the repair packets in mRowRepairForDecoding and mColRepairForDecoding.
	 */
	void repair2D();

	/**
	 * Apply the 1D decoding algorithms described in RFC 8627 sections 6.3.2 and 6.3.3, on row or columns repair
	 * packets, given the value of interleaved.
	 *
	 * @param interleaved True to apply the interleaved recovery on the column repair packets in mColRepairForDecoding,
	 * false to apply the non interleaved recovery on the row repair packets in mRowRepairForDecoding.
	 * @return Number of missing packets that have been recovered.
	 */
	int repair1D(bool interleaved);

	/**
	 * Apply the decoding algorithms described in RFC 8627 sections 6.3.2 and 6.3.3, on the repair packet repairPacket.
	 * If one (and only one) source packet protected by the repair packet misses, its header and payload are recovered.
	 * The algorithm consists in combining the protceted source and the repair packets with a XOR.
	 *
	 * @param interleaved True to apply the interleaved recovery on the column repair packets in mColRepairForDecoding,
	 * false to apply the non interleaved recovery on the row repair packets in mRowRepairForDecoding.
	 * @return 1 if a missing packet has been recovered, 0 otherwise.
	 */
	int repairOne(FecRepairPacket const &repairPacket);

	/**
	 * Apply the XOR operation between the repair packet and a source packets containing the result of the XOR operation
	 * between all other source packets protceted by the repair packet.
	 *
	 * @param source All other source packets combined with a XOR.
	 * @param repair Repair packet that protects them.
	 */
	void repairAddPacket(FecSourcePacket &source, FecRepairPacket const &repair);

	/**
	 * Erase the source packets that are out of the repair window.
	 */
	void cleanSource();

	/**
	 * Erase the repair packets that are out of the repair window, and update the FEC graph.
	 */
	void cleanRepair();

	RtpSession *mSession;         /**< RTP session containing the streams that receives the source and repair packets.*/
	const uint32_t mRepairWindow; /**< Maximal time interval between the time stamps of the last and the first source
	                                 packet received, in microsecond.*/
	std::multimap<uint32_t, uint16_t> mSourceTimeStamp; /**< Sequence numbers of the source packets ordered by their
	                                                       time stamps, to handle the repair window.*/
	std::multimap<uint32_t, uint16_t>
	    mRepairTimeStamp; /**< Sequence numbers of the repair packets ordered by their
	                          time stamps, to handle the repair window. Both row and columns repair packets are added.*/
	std::unordered_map<uint16_t, std::shared_ptr<FecSourcePacket>>
	    mSource; /**< Source packets received, in the repair window.*/
	std::unordered_map<uint16_t, std::shared_ptr<FecRepairPacket>>
	    mRowRepairAll; /**< Row repair packets received that protect the source packets in mSource.*/
	std::unordered_map<uint16_t, std::shared_ptr<FecRepairPacket>>
	    mColRepairAll;      /**< Column repair packets received that protect the source packets in mSource.*/
	uint64_t mRowRepairCpt; /**< Counter of the row repair packets received*/
	uint64_t mColRepairCpt; /**< Counter of the column repair packets received*/
	std::vector<std::shared_ptr<FecRepairPacket>>
	    mRowRepairForDecoding; /**< Row repair packets identified for the recovery of a given source packet.*/
	std::vector<std::shared_ptr<FecRepairPacket>>
	    mColRepairForDecoding; /**< Column repair packets identified for the recovery of a given source packet.*/
	FecPacketsConnection
	    mFecGraph; /**< FEC graph of the connections between the repair packets and the protected source packets*/
};
} // namespace ortp
#endif // RECIEVE_CLUSTER_H