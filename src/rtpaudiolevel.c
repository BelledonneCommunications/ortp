/*
 * Copyright (c) 2010-2021 Belledonne Communications SARL.
 *
 * This file is part of oRTP.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have dispatchd a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "ortp/logging.h"
#include "ortp/rtp.h"

/**
 * Add the client to mixer audio level header extension.
 * See https://tools.ietf.org/html/rfc6464
 * @param packet the RTP packet.
 * @param id the identifier of the client to mixer audio level extension.
 * @param voice_activity TRUE if there is voice activity, FALSE otherwise.
 * @param audio_level the audio level to set expressed in dBov.
**/
void rtp_add_client_to_mixer_audio_level(mblk_t *packet, int id, bool_t voice_activity, int audio_level) {
	uint8_t data = (voice_activity ? 0x1 : 0x0) << 7 | (audio_level * -1);
	rtp_add_extension_header(packet, id, sizeof(data), &data);
}

/**
 * Obtain the client to mixer audio level through the header extension.
 * See https://tools.ietf.org/html/rfc6464
 * @param packet the RTP packet.
 * @param id the identifier of the client to mixer audio level extension.
 * @param voice_activity set to TRUE if there is voice activity, FALSE otherwise
 * @return the client to mixer audio level in dBov, -1 if there is no extension header or the extension was not found.
**/
int rtp_get_client_to_mixer_audio_level(mblk_t *packet, int id, bool_t *voice_activity) {
	uint8_t *data;
	int ret;

	ret = rtp_get_extension_header(packet, id, &data);
	if (ret != -1) {
		*voice_activity = (int)(*data) >> 7 & 0x1 ? TRUE : FALSE;

		return (int)(*data & 0x7F) * -1; // Audio level is stored as a 7-bit number expressed in -dBov
	}

	return -1;
}

/**
 * Add the mixer to client audio level header extension.
 * See https://tools.ietf.org/html/rfc6465
 * @param packet the RTP packet.
 * @param id the identifier of the client to mixer audio level extension.
 * @param size the size of the audio_levels list.
 * @param audio_levels the list if audio levels to set.
**/
void rtp_add_mixer_to_client_audio_level(mblk_t *packet, int id, size_t size, rtp_audio_level_t *audio_levels) {
	uint8_t *data;
	int i;

	if (audio_levels == NULL || size <= 0) return;

	// Increase packet size to have enough space to add csrc
	msgpullup(packet, msgdsize(packet) + size * sizeof(uint32_t));
	packet->b_wptr += size * sizeof(uint32_t);

	data = ortp_new0(uint8_t, size);
	for (i = 0; i < (int)size; i++) {
		rtp_add_csrc(packet, audio_levels[i].csrc);
		data[i] = 0x0 << 7 | (audio_levels[i].dbov * -1);
	}
	rtp_add_extension_header(packet, id, size, data);

	ortp_free(data);
}

/**
 * Obtain the mixer to client audio level through the header extension.
 * See https://tools.ietf.org/html/rfc6465
 * @param packet the RTP packet.
 * @param id the identifier of the mixer to client audio level extension.
 * @param audio_levels the list of mixer to client audio levels, this array must be allocated before calling this function.
 * @return the size of the mixer to client audio levels list, -1 in case of error.
**/
int rtp_get_mixer_to_client_audio_level(mblk_t *packet, int id, rtp_audio_level_t* audio_levels) {
	int ret, i;
	uint8_t *data;

	ret = rtp_get_extension_header(packet, id, &data);
	if (ret != -1) {
		rtp_header_t *header = (rtp_header_t*) packet->b_rptr;

		if (ret != header->cc) {
			ortp_error("Error while retrieving mixer to client audio levels [%p]: number of audio level and csrc do not match", packet);
			return -1;
		}

		for (i = 0; i < ret; i++) {
			audio_levels[i].csrc = header->csrc[i];
			audio_levels[i].dbov = (int)(data[i] & 0x7F) * -1;
		}
	}

	return ret;
}
