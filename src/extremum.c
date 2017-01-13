/*
 * The oRTP library is an RTP (Realtime Transport Protocol - rfc3550) implementation with additional features.
 * Copyright (C) 2017 Belledonne Communications SARL
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "ortp/utils.h"
#include "ortp/logging.h"

void ortp_extremum_reset(OrtpExtremum *obj){
	obj->current_extremum=0;
	obj->extremum_time=(uint64_t)-1;
	obj->last_stable=0;
}

void ortp_extremum_init(OrtpExtremum *obj, int period){
	ortp_extremum_reset(obj);
	obj->period=period;
}


static bool_t extremum_check_init(OrtpExtremum *obj, uint64_t curtime, float value, const char *kind){
	if (obj->extremum_time!=(uint64_t)-1){
		if (((int)(curtime-obj->extremum_time))>obj->period){
			obj->last_stable=obj->current_extremum;
			/*last extremum is too old, drop it and replace it with current value*/
			obj->current_extremum=value;
			obj->extremum_time=curtime;
			return TRUE;
		}
	}else {
		obj->last_stable=value;
		obj->current_extremum=value;
		obj->extremum_time=curtime;
		return TRUE;
	}
	return FALSE;
}

bool_t ortp_extremum_record_min(OrtpExtremum *obj, uint64_t curtime, float value){
	bool_t ret = extremum_check_init(obj,curtime,value,"min");
	if (value<obj->current_extremum){
		obj->last_stable=obj->current_extremum;
		obj->current_extremum=value;
		obj->extremum_time=curtime;
		return TRUE;
	}
	return ret;
}

bool_t ortp_extremum_record_max(OrtpExtremum *obj, uint64_t curtime, float value){
	bool_t ret = extremum_check_init(obj,curtime,value,"max");
	if (value>obj->current_extremum){
		obj->last_stable=obj->current_extremum;
		obj->current_extremum=value;
		obj->extremum_time=curtime;
		ret = TRUE;
	}
	return ret;
}

float ortp_extremum_get_current(OrtpExtremum *obj){
	return obj->current_extremum;
}

float ortp_extremum_get_previous(OrtpExtremum *obj){
	return obj->last_stable;
}

