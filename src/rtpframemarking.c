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

#include "ortp/logging.h"
#include "ortp/rtp.h"

/**
 * Add the frame marking header extension.
 * See https://datatracker.ietf.org/doc/html/draft-ietf-avtext-framemarking-13
 * @param packet the RTP packet.
 * @param id the identifier of the frame marking extension.
 * @param marker the frame marker to add.
 **/
void rtp_add_frame_marker(mblk_t *packet, int id, uint8_t marker) {
	rtp_add_extension_header(packet, id, 1, &marker);
}

/**
 * Obtain the frame marker through the header extension.
 * See https://datatracker.ietf.org/doc/html/draft-ietf-avtext-framemarking-13
 * @param packet the RTP packet.
 * @param id the identifier of the frame marking extension.
 * @param marker the frame marker to set.
 * @return 1 if the frame marker if present, 0 otherwise.
 **/
int rtp_get_frame_marker(mblk_t *packet, int id, uint8_t *marker) {
	uint8_t *data;

	int ret = rtp_get_extension_header(packet, id, &data);
	if (ret != -1) {
		*marker = *data;

		return 1;
	}

	return 0;
}