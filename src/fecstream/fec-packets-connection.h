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

#ifndef FEC_PACKETS_CONNECTION_H
#define FEC_PACKETS_CONNECTION_H

#include <map>
#include <memory>
#include <set>

#include "packet-api.h"

namespace ortp {

#ifdef _WIN32
// Disable C4251 triggered by need to export all stl template classes
#pragma warning(disable : 4251)
#endif // ifdef _WIN32

/** @class FecSourceNode
 * @brief Class to connect a single source packet with the repair packets that protect it.
 *
 * The source packet is identified by its sequence number mSeqNum. The repair packets are identified by their sequence
 * number, with two possibilities:
 * - for row repair packets, the sequence number is added to mRowRepairSeqNum,
 * - for column repair packets, the sequence number is added to mColRepairSeqNum.
 */
class ORTP_PUBLIC FecSourceNode {
public:
	/**
	 * This constructor initializes the object with the sequence number of the source packet.
	 *
	 * @param seqNum Sequence number of the source packet.
	 */
	FecSourceNode(const uint16_t seqNum);

	~FecSourceNode(){};

	/**
	 * Connect the source packet with a row repair packet that protects it by adding its sequence number in
	 * mRowRepairSeqNum.
	 *
	 * @param seqNum sequence number of the row repair packet.
	 */
	void addRowRepair(const uint16_t seqNum);

	/**
	 * Connect the source packet with a column repair packet that protects it by adding its sequence number in
	 * mColRepairSeqNum.
	 *
	 * @param seqNum sequence number of the column repair packet.
	 */
	void addColRepair(const uint16_t seqNum);

	/**
	 * Return the set of sequence numbers of the row repair packets that protects the source packet.
	 */
	std::set<uint16_t> getRowRepair() const {
		return mRowRepairSeqNum;
	};

	/**
	 * Return the set of sequence numbers of the column repair packets that protects the source packet.
	 */
	std::set<uint16_t> getColRepair() const {
		return mColRepairSeqNum;
	};

	/**
	 * Return the sequence number of the source packet.
	 */
	uint16_t getSeqNum() const {
		return mSeqNum;
	};

	/**
	 * Remove the connection with the row repair packet identified by repairSeqNum. Return true if the node has no more
	 * connections.
	 *
	 * @param repairSeqNum sequence number of the row repair packet.
	 * @return true if the source packet is no more connected with a repair packet.
	 */
	bool removeRowRepair(const uint16_t repairSeqNum);

	/**
	 * Remove the connection with the column repair packet identified by repairSeqNum. Return true if the node has no
	 * more connections.
	 *
	 * @param repairSeqNum sequence number of the column repair packet.
	 * @return true if the source packet is no more connected with a repair packet.
	 */
	bool removeColRepair(const uint16_t repairSeqNum);

private:
	const uint16_t mSeqNum; /**< Sequence number of the source packet. */

	std::set<uint16_t> mRowRepairSeqNum =
	    {}; /**< Set of sequence numbers of the row repair packets that protect the source packet. */

	std::set<uint16_t> mColRepairSeqNum =
	    {}; /**< Set of sequence numbers of the column repair packets that protect the source packet. */
};

/** @class FecRepairNode
 * @brief Class to connect a single repair packet with the source packets that it protects.
 *
 * The packets are identified by their unique sequence numbers.
 */
class ORTP_PUBLIC FecRepairNode {
public:
	/**
	 * This constructor initializes the object with the sequence number of the repair packet and the list of the
	 * source packets that it protects, given by their sequence numbers.
	 *
	 * @param sequenceNumberProtected List of the sequence numbers of the protected source packets.
	 */
	FecRepairNode(const std::vector<uint16_t> sequenceNumberProtected);

	~FecRepairNode(){};

	/**
	 * Return the set of sequence numbers of the source packets that are protected by the repair packet.
	 */
	std::set<uint16_t> getProtectedSources() const {
		return mSourceSeqNum;
	};

private:
	const std::set<uint16_t> mSourceSeqNum; /**< Set of sequence numbers of the source packets protected. */
};

/** @class FecPacketsConnection
 * @brief Class to connect the repair packets with the source packets that they protect.
 *
 * This class aims to establish the connections between the source and repair packets received when there is a
 * protection, in order to find the subset of repair packets needed to repair a given source packet. It can be
 * represented by a bipartite graph, whose nodes are the set of source packets on one side and the set of repair packets
 * of the other side. When a repair packet protects a source packet, both are connected. A FEC block can be fully
 * represented by such graph. If there is no overlap between two FEC blocks (no source packet in common), their graphs
 * are disjoint.
 *
 * The packets are identified by their sequence numbers. The row and column repair packets are distinguished. A source
 * packet has at least one connection. If the FEC blocks are disjoint, they can have at most two connections: one with a
 * row repair packet and the other with a column repair packet. The repair packets can protects several source packets.
 * The sets of packets are populated only when a repair packet is added, with the list of source packets that it
 * protects.
 *
 * To find the repair packets that protects the source packet i :
 *  1. the sets of row and columns repair packets connected to i are found
 *  2. then for each repair packet in those sets the source packets connected are found.
 * These steps are repeated until no more packets are found. This way any configuration of parity protection of the
 * flexible FEC can be handled, even with repair packet losses or when they are not received in chronological order.
 *
 * The sets are cleaned by removing a given repair packet and the connections that it had with the source packets.
 */
class ORTP_PUBLIC FecPacketsConnection {
public:
	/**
	 * This constructor initializes the object.
	 */
	FecPacketsConnection();

	~FecPacketsConnection(){};

	/**
	 * @brief Add a row repair packet and the source packets that it protects.
	 *
	 * A FecRepairNode is created for the row repair packet and the sources packets that it protects. It is added to
	 * the map mRowRepairNodes. A FecSourceNode is created for each protected source packet and added to the map
	 * mSourceNodes. If the packets are already in the maps, the new connections are added.
	 *
	 * @param repairSeqNum Sequence number of the row repair packet.
	 * @param sequenceNumberProtected List of sequence numbers of the source packets that are protected by the repair
	 * packet.
	 */
	void addRowRepair(const uint16_t repairSeqNum, const std::vector<uint16_t> sequenceNumberProtected);

	/**
	 * @brief Add a column repair packet and the source packets that it protects.
	 *
	 * A FecRepairNode is created for the column repair packet and the sources packets that it protects. It is added to
	 * the map mColRepairNodes. A FecSourceNode is created for each protected source packet and added to the map
	 * mSourceNodes. If the packets are already in the maps, the new connections are added.
	 *
	 * @param repairSeqNum Sequence number of the column repair packet.
	 * @param sequenceNumberProtected List of sequence numbers of the source packets that are protected by the repair
	 * packet.
	 */
	void addColRepair(const uint16_t repairSeqNum, const std::vector<uint16_t> sequenceNumberProtected);

	/**
	 * @brief Identify all repair packets needed to recover the source packet seqNum.
	 *
	 * This function explores the full graph to which the source packet seqNum belongs and selects the row and column
	 * repair packets that are vertices of this graph, as the graph is a representation of a FEC block. The operation
	 * consists in the two steps:
	 *  1. for each source packet of the graph, the sets of row and columns repair packets connected are found
	 *  2. for each repair packet of the graph, the set of the source packets connected are found.
	 * These steps are repeated until no more packets are found. It starts with the set {seqNum}.
	 *
	 * For the case where several FEC blocks overlap, the search could lead to a very large set of repair packetss.
	 * However the source packets far from seqNum are unlikely to be essential to the recovery and the exploring cost
	 * increases. The packet exploration is then limited to a given number of iterations.
	 *
	 * @param seqNum Sequence number of the source packet to recover.
	 * @param rowRepairPackets Set of sequence numbers of the row repair packets needed to recover the source
	 * packet.
	 * @param colRepairPackets Set of sequence numbers of the column repair packets needed to recover the source
	 * packet.
	 */
	void getRepairPacketsToRecoverSource(const uint16_t seqNum,
	                                     std::set<uint16_t> &rowRepairPackets,
	                                     std::set<uint16_t> &colRepairPackets) const;

	/**
	 * @brief Erase a row repair packet and its connections with the source packets.
	 *
	 * For each source packet connected with the row repair packet seqNum, remove the connection with it. If a source
	 * packet has no more connections, erase it. Then erase the row repair packet.
	 *
	 * @param seqNum Sequence number of the row repair packet to remove.
	 */
	void cleanRowRepair(const uint16_t seqNum);

	/**
	 * @brief Erase a column repair packet and its connections with the source packets.
	 *
	 * For each source packet connected with the column repair packet seqNum, remove the connection with it. If a source
	 * packet has no more connections, erase it. Then erase the column repair packet.
	 *
	 * @param seqNum Sequence number of the column repair packet to remove.
	 */
	void cleanColRepair(const uint16_t seqNum);

	/**
	 * Clear all packets and connections.
	 */
	void reset();

private:
	std::map<uint16_t, FecSourceNode> mSourceNodes =
	    {}; /**< All source packets, identified by the sequence numbers, and their connections with repair packets. */

	std::map<uint16_t, FecRepairNode> mRowRepairNodes = {}; /**< All row repair packets, identified by a unique sequence
	                                                           number, and their connections with source packets. */

	std::map<uint16_t, FecRepairNode> mColRepairNodes = {}; /**< All column repair packets, identified by a unique
	           sequence number, and their connections with source packets. */
};

} // namespace ortp
#endif // FEC_PACKETS_CONNECTION_H