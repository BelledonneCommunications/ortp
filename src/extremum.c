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

#include <bctoolbox/defs.h>

#include "ortp/logging.h"
#include "ortp/utils.h"

void ortp_extremum_reset(OrtpExtremum *obj) {
	obj->current_extremum = 0;
	obj->extremum_time = (uint64_t)-1;
	obj->last_stable = 0;
}

void ortp_extremum_init(OrtpExtremum *obj, int period) {
	ortp_extremum_reset(obj);
	obj->period = period;
}

static bool_t extremum_check_init(OrtpExtremum *obj, uint64_t curtime, float value, BCTBX_UNUSED(const char *kind)) {
	if (obj->extremum_time != (uint64_t)-1) {
		if (((int)(curtime - obj->extremum_time)) > obj->period) {
			obj->last_stable = obj->current_extremum;
			/*last extremum is too old, drop it and replace it with current value*/
			obj->current_extremum = value;
			obj->extremum_time = curtime;
			return TRUE;
		}
	} else {
		obj->last_stable = value;
		obj->current_extremum = value;
		obj->extremum_time = curtime;
		return TRUE;
	}
	return FALSE;
}

bool_t ortp_extremum_record_min(OrtpExtremum *obj, uint64_t curtime, float value) {
	bool_t ret = extremum_check_init(obj, curtime, value, "min");
	if (value < obj->current_extremum) {
		obj->last_stable = obj->current_extremum;
		obj->current_extremum = value;
		obj->extremum_time = curtime;
		return TRUE;
	}
	return ret;
}

bool_t ortp_extremum_record_max(OrtpExtremum *obj, uint64_t curtime, float value) {
	bool_t ret = extremum_check_init(obj, curtime, value, "max");
	if (value > obj->current_extremum) {
		obj->last_stable = obj->current_extremum;
		obj->current_extremum = value;
		obj->extremum_time = curtime;
		ret = TRUE;
	}
	return ret;
}

float ortp_extremum_get_current(OrtpExtremum *obj) {
	return obj->current_extremum;
}

float ortp_extremum_get_previous(OrtpExtremum *obj) {
	return obj->last_stable;
}
