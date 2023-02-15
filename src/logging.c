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
#include "ortp/utils.h"

void ortp_set_log_handler(OrtpLogFunc func) {
	bctbx_set_log_handler(func);
}

OrtpLogFunc ortp_get_log_handler(void) {
	return NULL;
}
/**
 *@param file a FILE pointer where to output the ortp logs.
 *
 **/
void ortp_set_log_file(FILE *file) {
	bctbx_set_log_file(file);
}
