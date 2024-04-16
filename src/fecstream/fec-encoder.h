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

#ifndef FEC_ENCODER_H
#define FEC_ENCODER_H

#include <memory>
#include <vector>

#include "fec-params.h"
#include "packet-api.h"

namespace ortp {

#ifdef _WIN32
// Disable C4251 triggered by need to export all stl template classes
#pragma warning(disable : 4251)
#endif // ifdef _WIN32

class FecParamsController;

/** @class FecEncoder
 * @brief Class to apply parity codes on source packets to generate the flexible FEC repair packets.
 *
 *  This class combines the source packets that are sent to the encoder, following a given FEC protection configuration
 * represented as a FEC block with D rows and L colmuns, as described in RFC 8627. The combination can be:
 * - 1D non interleaved parity protection or row protection: L successive source packets are combined together on the
 * same row, and 1 row repair packet is generated.
 * - 1D interleaved parity protection, or column protection: D source packets are combined together every L packet, on
 * the same column, and 1 column repair packet is generated per column. It leads to L column repair packets for L
 * independent columns, for a set of L*D source packets, managed by the same FecEncoder.
 * - 2D parity protection : both row and column protection are applied, and D row repair packets and L column repair
 * packets are generated.
 * The source packets are objects of the FecSourcePacket class, and repair packets are objects of the FecRepairPacket
 * class. When all repair packets have been generated, the encoder is full and can be reset to receive the next set of
 * source packets. This set is identified by the sequence number of the first source packet. The encoder can be updated
 * to a new protection configuration, by changing the values of L and D and switching between 1D and 2D.
 */
class ORTP_PUBLIC FecEncoder {

public:
	FecEncoder(){};
	FecEncoder(FecParamsController *parameters);

	/**
	 * @brief Initialize the FEC encoder.
	 *
	 * Set the source and FEC RTP sessions and create empty repair packets.
	 *
	 * @param fecSession RTP session to which the stream where the FEC repair packets are sent belongs.
	 * @param sourceSession RTP session to which the stream where the source packets are sent belongs.
	 */
	void init(struct _RtpSession *fecSession, struct _RtpSession *sourceSession);

	/**
	 * @brief Update and initialize the encoder with given parameters.
	 *
	 * Update of the encoder to a new protection configuration. The repair packet lists are cleared and new empty repair
	 * packets are generated following the new encoder protection.
	 *
	 * @param L uint8_t Number of columns in row protection, must be strictly positive.
	 * @param D uint8_t Number of rows in columns protection.
	 */
	void update(uint8_t L, uint8_t D, bool is2D);

	/**
	 * Clear the vectors of repair packets and set the position of the last source packet to 0.
	 *
	 */
	void clear();

	/**
	 * Reset the encoder: the repair packets are reset to initial values, with empty payload. The sequence
	 * number base of the FEC block is set to nextSequenceNumber. The current value of mLoading is set to 0. The
	 * protection parameters L and D and the FEC block dimension remain the same.
	 *
	 * @param nextSequenceNumber uint16_t Sequence number of the first source packet that will be protected by the
	 * FEC block.
	 */
	void reset(uint16_t nextSequenceNumber);

	/**
	 * @brief Add a source packet to the FEC encoder.
	 *
	 * The add() method of the FecRepairPacket class is called to compute the payload and the bitstring. The repair
	 * packets that protect this packet in the FEC block are updated:
	 *  - the row repair packet of the current row in 1D non interleaved protection
	 *  - the column repair packet of the current column in the 1D interleaved protection
	 *  - both row and column repair packets in 2D protection.
	 * The mLoading value is incremented by 1.
	 *
	 * @param packet source packet to add.
	 */
	void add(FecSourcePacket const &packet);

	/**
	 * Check if all source packets of the FEC block have been added.
	 *
	 * @return true if the encoder is full, false otherwise.
	 */
	bool isFull() const;

	/**
	 * @brief Determine if the encoder is empty.
	 *
	 * This function checks if no source packet has been added yet.
	 *
	 * @return true if the encoder is empty, false otherwise.
	 */
	bool isEmpty() const;

	/**
	 * Return the index of the row in the FEC block where the last source packet has been added.
	 *
	 * @return index of the last row filled.
	 */
	int getCurrentRow() const;

	/**
	 * Return the index of the column in the FEC block where the last source packet has been added.
	 *
	 * @return index of the last column filled.
	 */
	int getCurrentColumn() const;

	/**
	 * Check if L source packets have been added in the current row of the FEC block. In 1D interleaved parity
	 * protection, return false.
	 *
	 * @return true if all source packets have been added in the current row, false otherwise.
	 */
	bool isRowFull() const;

	/**
	 * Check if D source packets have been added in the current column of the FEC block. In 1D non interleaved
	 * case, return false.
	 *
	 * @return true if all source packets have been added in the current column, false otherwise.
	 */
	bool isColFull() const;

	/**
	 * Return a the row repair packet that protects the row i.
	 *
	 * @param i index of the row repair packet.
	 * @return row repair packet or nullptr if the packet doesn't exist.
	 */
	std::shared_ptr<FecRepairPacket> getRowRepair(int i) const;

	/**
	 * Return a the column repair packet that protects the column i.
	 *
	 * @param i index of the column repair packet.
	 * @return column repair packet or nullptr if the packet doesn't exist.
	 */
	std::shared_ptr<FecRepairPacket> getColRepair(int i) const;

	/**
	 * Return a copy of the mblkt of the repair packet that protects the row i.
	 *
	 * @param i index of the repair packet.
	 * @return copy of the mblkt of the repair packet or nullptr if the packet doesn't exist.
	 */
	mblk_t *getRowRepairMblk(int i) const;

	/**
	 * Return a copy of the mblkt of the repair packet that protects the column i.
	 *
	 * @param i index of the repair packet.
	 * @return copy of the mblkt of the repair packet or nullptr if the packet doesn't exist.
	 */
	mblk_t *getColRepairMblk(int i) const;

private:
	/**
	 * @brief Update encoder protection configuration.
	 *
	 * Change the parameters mL, mD, mColumns, mRows, mRowRepairNb, mColRepairNb and mIs2D to set a new parity
	 * protection configuration, following the values of L, D and is2D.
	 *
	 * @param L number of rows of the FEC block. L must be stricly positive. If D <= 1, or if D > 1 and is2D is true,
	 * the row protection is applied and L row repair packets are generated.
	 * @param D number of columns of the FEC block. If D = 0, the 1D row protection is always applied, no column
	 * repair packet is generated.
	 * @param is2D boolean, true for 2D parity protection, false otherwise.
	 */
	void updateProtectionParam(uint8_t L, uint8_t D, bool is2D);

	/**
	 * Initialize the vector of row repair packets: generate mRowRepairNb empty row repair packets, with the sequence
	 * base numbers 0, ... i*L, ... (D-1)*L.
	 */
	void initRowRepairPackets();

	/**
	 * Initialize the vector of column repair packets: generate mColRepairNb empty column repair packets, with the
	 * sequence base numbers 0, ... i, ... (L-1).
	 */
	void initColRepairPackets();

	/**
	 * Reset the row repair packets and their sequence base numbers of the row repair packets, to make the FEC block
	 * starts at seqnumBase. Then the mRowRepairNb row repair packets protect the rows for source packets starting with
	 * the sequence numbers seqnumBase, ... seqnumBase + i*L, ... seqnumBase + (D-1)*L.
	 *
	 * @param seqnumBase sequence number base: sequence number of the first source packet protected by a repair
	 * packet.
	 */
	void resetRowRepairPackets(uint16_t seqnumBase);

	/**
	 * Reset the column repair packets and their the sequence base number, to make the FEC block starts at seqnumBase.
	 * Then the mRowRepairNb column repair packets protect the columns for source packets starting with the sequence
	 * numbers seqnumBase, ... seqnumBase + i, ... seqnumBase + L - 1.
	 *
	 * @param seqnumBase sequence number base: sequence number of the first source packet protected by a repair
	 * packet.
	 */
	void resetColRepairPackets(uint16_t seqnumBase);

	std::vector<std::shared_ptr<FecRepairPacket>> mRowRepair; /**< The repair packets that protects the rows, in
	                                                         increasing order of base sequence number. */
	std::vector<std::shared_ptr<FecRepairPacket>> mColRepair; /**< The repair packets that
	                   protects the columns, in increasing order of base sequence number. */
	RtpSession *mFecSession;    /**< RTP session to which the source and FEC streams belongs. */
	RtpSession *mSourceSession; /**< RTP source session. */
	int mLoading;               /**< Current position of the last source packet received in the FEC block. */
	uint8_t mL;                 /**< Number of columns of the FEC block (length of each row).*/
	uint8_t mD;   /**< Number of rows of the FEC block (depth of the FEC protection). For 1D non interleaved protection,
	                 mD = 0.*/
	int mColumns; /**< Number of columns of the FEC block.*/
	int mRows;    /**< Number of rows of the FEC block. */
	int mRowRepairNb; /**< Number of repair packets that protects rows. */
	int mColRepairNb; /**< Number of repair packets that protects columns. */
	bool mIs2D;       /**< True for a 2D parity protection, false otherwise. */
};
} // namespace ortp
#endif // FEC_ENCODER_H