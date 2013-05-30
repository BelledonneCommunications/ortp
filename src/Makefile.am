
EXTRA_DIST=ortp-config-win32.h dll_entry.c master system winrttimer.cpp winrttimer.h

AM_CPPFLAGS=\
	-I$(top_srcdir)/include/ \
	-I$(top_srcdir) 

AM_CFLAGS=\
	$(PTHREAD_CFLAGS) \
	$(TRUESPEECH_CFLAGS) \
	$(SRTP_CFLAGS)

AM_LDFLAGS=$(PTHREAD_LDFLAGS)

lib_LTLIBRARIES = libortp.la

libortp_la_SOURCES=	str_utils.c 	\
			port.c \
			logging.c \
			rtpparse.c  \
			rtpsession.c \
			rtpsession_inet.c \
			rtpsession_priv.h \
			jitterctl.c jitterctl.h \
			rtpsignaltable.c  \
			rtptimer.c	rtptimer.h \
			posixtimer.c \
			ortp.c \
			scheduler.c scheduler.h \
			avprofile.c  \
			sessionset.c  \
			telephonyevents.c  \
			payloadtype.c \
			rtpprofile.c \
			rtcp.c  \
			utils.c utils.h \
			rtcpparse.c \
			event.c \
			stun.c stun_udp.c \
			ortp_srtp.c \
			b64.c \
			zrtp.c \
			netsim.c

if LIBZRTPCPP
AM_CFLAGS+= $(LIBZRTPCPP_CFLAGS)
AM_LDFLAGS+= $(LIBZRTPCPP_LDFLAGS)
endif

libortp_la_LIBADD= $(PTHREAD_LIBS) $(RT_LIBS) -lm $(SRTP_LIBS) $(SSL_LIBS) $(LIBZRTPCPP_LIBS)

libortp_la_LDFLAGS= -version-info $(LIBORTP_SO_VERSION) -no-undefined


SUBDIRS= . tests
