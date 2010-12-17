##
## Android.mk -Android build script-
##
##
## Copyright (C) 2010  Belledonne Communications, Grenoble, France
##
##  This program is free software; you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation; either version 2 of the License, or
##  (at your option) any later version.
##
##  This program is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU Library General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with this program; if not, write to the Free Software
##  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
##


LOCAL_PATH:= $(call my-dir)/../../
include $(CLEAR_VARS)

LOCAL_MODULE := libortp


LOCAL_SRC_FILES := \
	src/str_utils.c	\
	src/port.c \
	src/rtpparse.c \
	src/rtpsession.c \
	src/rtpsession_inet.c \
	src/jitterctl.c \
	src/rtpsignaltable.c  \
	src/rtptimer.c \
	src/posixtimer.c \
	src/ortp.c \
	src/scheduler.c \
	src/avprofile.c \
	src/sessionset.c \
	src/telephonyevents.c \
	src/payloadtype.c \
	src/rtcp.c \
	src/utils.c \
	src/rtcpparse.c \
	src/event.c \
	src/stun.c \
	src/stun_udp.c \
	src/srtp.c \
	src/b64.c 

LOCAL_CFLAGS += \
	-UHAVE_CONFIG_H \
	-include $(LOCAL_PATH)/build/android/ortp_AndroidConfig.h
LOCAL_C_INCLUDES += \
	$(LOCAL_PATH) \
	$(LOCAL_PATH)/include

LOCAL_LDLIBS += -lpthread

include $(BUILD_STATIC_LIBRARY)
