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
	src/logging.c \
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
	src/rtpprofile.c \
	src/rtcp.c \
	src/utils.c \
	src/rtcpparse.c \
	src/event.c \
	src/stun.c \
	src/stun_udp.c \
	src/ortp_srtp.c \
	src/b64.c \
	src/netsim.c \
	src/zrtp.c

LOCAL_CFLAGS += \
	-DORTP_INET6 \
	-UHAVE_CONFIG_H \
	-include ortp_AndroidConfig.h


ifeq ($(BUILD_GPLV3_ZRTP), 1)
ifeq ($(TARGET_ARCH_ABI),armeabi-v7a)
LOCAL_SHARED_LIBRARIES += libzrtpcpp
else
LOCAL_STATIC_LIBRARIES += libzrtpcpp-static
endif
LOCAL_CFLAGS += -DHAVE_zrtp
LOCAL_C_INCLUDES += $(ZRTP_C_INCLUDE)
endif #ZRTP

ifeq ($(BUILD_SRTP), 1)
ifeq ($(TARGET_ARCH_ABI),armeabi-v7a)
LOCAL_SHARED_LIBRARIES += libsrtp
else
LOCAL_STATIC_LIBRARIES += libsrtp-static
endif
LOCAL_C_INCLUDES += $(SRTP_C_INCLUDE)
LOCAL_CFLAGS += -DHAVE_SRTP -DHAVE_SRTP_SHUTDOWN
endif #SRTP

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH) \
	$(LOCAL_PATH)/include \
	$(LOCAL_PATH)/build/android

LOCAL_LDLIBS += -lpthread

include $(BUILD_STATIC_LIBRARY)
