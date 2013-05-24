dnl Process this file with autoconf to produce a configure script.
AC_INIT([ortp],[0.22.0])
AC_CANONICAL_SYSTEM

dnl Source packaging numbers
ORTP_MAJOR_VERSION=$(echo $PACKAGE_VERSION | cut -d. -f1)
ORTP_MINOR_VERSION=$(echo $PACKAGE_VERSION | cut -d. -f2)
ORTP_MICRO_VERSION=$(echo $PACKAGE_VERSION | cut -d. -f3)
ORTP_EXTRA_VERSION=$(echo $PACKAGE_VERSION | cut -d. -f4)

LIBORTP_SO_CURRENT=9 dnl increment this number when you add/change/remove an interface
LIBORTP_SO_REVISION=0 dnl increment this number when you change source code, without changing interfaces; set to 0 when incrementing CURRENT
LIBORTP_SO_AGE=0 dnl increment this number when you add an interface, set to 0 if you remove an interface

LIBORTP_SO_VERSION=$LIBORTP_SO_CURRENT:$LIBORTP_SO_REVISION:$LIBORTP_SO_AGE
ORTP_VERSION=${ORTP_MAJOR_VERSION}.${ORTP_MINOR_VERSION}.${ORTP_MICRO_VERSION}

if test -n "$ORTP_EXTRA_VERSION" ; then
	ORTP_VERSION="${ORTP_VERSION}.${ORTP_EXTRA_VERSION}"
fi

ORTP_PKGCONFIG_VERSION=${ORTP_VERSION}

AC_SUBST(LIBORTP_SO_VERSION)
AC_SUBST(ORTP_VERSION)
AC_SUBST(ORTP_PKGCONFIG_VERSION)


PACKAGE=ortp

AM_INIT_AUTOMAKE([tar-ustar])
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],)
AC_SUBST([docdir], [${datadir}/doc])
AC_CONFIG_HEADERS(ortp-config.h)
AC_CONFIG_MACRO_DIR([m4])
AC_DEFINE_UNQUOTED(ORTP_MAJOR_VERSION,$ORTP_MAJOR_VERSION, [major version])
AC_DEFINE_UNQUOTED(ORTP_MINOR_VERSION,$ORTP_MINOR_VERSION, [minor version])
AC_DEFINE_UNQUOTED(ORTP_MICRO_VERSION,$ORTP_MICRO_VERSION, [micro version])
AC_DEFINE_UNQUOTED(ORTP_VERSION,"$ORTP_VERSION",[ortp version number])

dnl Checks for programs.
AC_PROG_CC
LT_INIT([win32-dll shared disable-static])

AC_MSG_CHECKING([warning make an error on compilation])
AC_ARG_ENABLE(strict,
	[AS_HELP_STRING([--enable-strict], [Enable error on compilation warning (default=yes)])],
	[wall_werror=$enableval],
	[wall_werror=yes]
)

AC_ARG_ENABLE(perf,
	[AS_HELP_STRING([--enable-perf], [Disable costly features to reduce cpu consumtion (default=no)])],
	[perf=$enableval],
	[perf=no]
)

ORTP_DEFS=

dnl enable ipv6 support
AC_ARG_ENABLE(ipv6,
	[AS_HELP_STRING([--enable-ipv6], [Turn on ipv6 support (default=yes)])],
	[case "${enableval}" in
		yes)	ipv6=true;;
		no)	ipv6=false;;
		*)	AC_MSG_ERROR(bad value ${enableval} for --enable-ipv6) ;;
	esac],
	[ipv6=true]
)
if test x$ipv6 = xtrue ; then
	ORTP_DEFS="$ORTP_DEFS -DORTP_INET6"
	AC_DEFINE(__APPLE_USE_RFC_2292, 1, [ Apple wants you to declare what behavior you want by defining either __APPLE_USE_RFC_2292])
fi

dnl enable timestamp support
AC_ARG_ENABLE(ntp-timestamp,
	[AS_HELP_STRING([--enable-ntp-timestamp], [Turn on NTP timestamping on received packet (default=no)])],
	[case "${enableval}" in
		yes)	ntptimestamp=true;;
		no)	ntptimestamp=false;;
		*)	AC_MSG_ERROR(bad value ${enableval} for --enable-ntp-timestamp) ;;
	esac],
	[ntptimestamp=false]
)
if test x$ntptimestamp = xtrue ; then
	ORTP_DEFS="$ORTP_DEFS -DORTP_TIMESTAMP"
fi

AC_ARG_ENABLE(mode64bit,
	[AS_HELP_STRING([--enable-mode64bit], [Produce a 64-bit library (default=no)])],
	[case "${enableval}" in
		yes)	mode64bit_enabled=yes;;
		no)	mode64bit_enabled=no;;
		*)	AC_MSG_ERROR("Bad value for --enable-mode64bit");;
	esac],
	[mode64bit_enabled=no]
)

AC_ARG_ENABLE(debug,
	[AS_HELP_STRING([--enable-debug], [Enable the display of traces showing the execution of the library (default=yes)])],
	[case "${enableval}" in
		yes)	debug_enabled=yes;;
		no)	debug_enabled=no;;
		*)	AC_MSG_ERROR("Bad value for --enable-debug");;
	esac],
	[debug_enabled=no]
)

hpux_host=no
posixtimer_interval=10000
PTHREAD_LDFLAGS=

case "$target_os" in
	*hpux*) 
		hpux_host=yes
		AC_DEFINE(NOCONNECT,1,[Defined if we should not use connect() on udp sockets])
		CFLAGS="$CFLAGS -D_HPUX_SOURCE -D_XOPEN_SOURCE_EXTENDED -D_XOPEN_SOURCE=500 -D_POSIX_C_SOURCE=199506L"
		LIBS="$LIBS -lxnet"
	;;
	*freebsd*)
		AC_DEFINE(NOCONNECT,1,[Defined if we should not use connect() on udp sockets])
		PTHREAD_LDFLAGS="-pthread"
	;;
	*mingw32ce)
		CFLAGS="$CFLAGS -D_WIN32_WCE -D_WIN32_WINNT=0x0501 -DORTP_STATIC"
		LIBS="$LIBS -lws2 -liphlpapi"
		mingw_found=yes
	;;
	*mingw*)
		CFLAGS="$CFLAGS -D_WIN32_WINNT=0x0501 -DORTP_STATIC"
		LIBS="$LIBS -lws2_32 -liphlpapi -lwinmm"
		mingw_found=yes
	;;
esac

AC_CONFIG_COMMANDS([libtool-hacking],
	[if test "$mingw_found" = "yes" ; then
		echo "Hacking libtool to work with mingw..."
		sed -e 's/\*\" \$a_deplib \"\*/\*/' < ./libtool > libtool.tmp
		cp -f ./libtool.tmp ./libtool
		rm -f ./libtool.tmp
	fi],
	[mingw_found=$mingw_found]
)

if test "$GCC" != "yes" ; then
	if test "$hpux_host" = "yes" ; then
		dnl we are probably using HPUX cc compiler, so add a +O2 to CFLAGS
			CFLAGS="$CFLAGS +O2 -g "
		if test x$mode64bit_enabled = xyes ; then
			CFLAGS="$CFLAGS +DA2.0W +DS2.0"
		fi
	fi
else
	CFLAGS="$CFLAGS -Wall"	
fi

build_scheduler=yes

dnl Check if we have seteuid system call
AC_CHECK_FUNCS(seteuid)


dnl check if we can use the pthread_library
AC_CHECK_LIB(pthread, pthread_mutex_init, [pthread_enabled=yes], [pthread_enabled=no])
if test $pthread_enabled = "no" ; then
	build_scheduler=no
else
	PTHREAD_LIBS="-lpthread"
	PTHREAD_CFLAGS="-D_REENTRANT"
	AC_SUBST(PTHREAD_CFLAGS)
	AC_SUBST(PTHREAD_LIBS)
	AC_SUBST(PTHREAD_LDFLAGS)
fi
AC_ARG_WITH(thread-stack-size,
	AC_HELP_STRING([--with-thread-stack-size=SIZE-IN-BYTES],[Set thread stack size [[default=os-default]]]),
	[thread_stack_size=$withval],
	[thread_stack_size=0]
)
AC_DEFINE_UNQUOTED(ORTP_DEFAULT_THREAD_STACK_SIZE, $thread_stack_size, [Default thread stack size (0 = let uperating system decide)])


dnl check if we can use the rt library
AC_CHECK_LIB(rt, clock_gettime, [rt_enabled=yes])
if test "$rt_enabled" = "yes" ; then
	RT_LIBS="-lrt"
	AC_SUBST(RT_LIBS)
fi


dnl check for libsrtp support (secure rtp)
AC_ARG_WITH(srtp,
	AC_HELP_STRING([--with-srtp], [Set prefix where libsrtp can be found or "none" to disable (ex:/usr or /usr/local) [[default=/usr]]]),
	[srtp_prefix=$withval],
	[srtp_prefix=/usr]
)
if test "${srtp_prefix}" != "none" ; then
	if test "${srtp_prefix}" != "/usr" || test "$mingw_found" = "yes" ; then
		SRTP_CFLAGS="-I${srtp_prefix}/include -I${srtp_prefix}/include/srtp"
		SRTP_LIBS="-L${srtp_prefix}/lib"
	fi
	SRTP_LIBS="$SRTP_LIBS -lsrtp"

	dnl check srtp headers
	have_srtp=no
	CPPFLAGS_save=$CPPFLAGS
	CPPFLAGS="$CPPFLAGS $SRTP_CFLAGS"
	AC_CHECK_HEADER([srtp/srtp.h],have_srtp_headers=yes)
	CPPFLAGS=$CPPFLAGS_save

	dnl check for srtp lib
	LDFLAGS_save=$LDFLAGS
	LDFLAGS="$LDFLAGS $SRTP_LIBS"
	LIBS_save=$LIBS
	AC_CHECK_LIB(srtp,srtp_init,have_srtp_lib=yes)
	AC_CHECK_LIB(srtp,srtp_shutdown,[AC_DEFINE([HAVE_SRTP_SHUTDOWN],1,[Defined when srtp_shutdown() exists.])])
	LDFLAGS=$LDFLAGS_save
	LIBS=$LIBS_save

	if test "$have_srtp_headers$have_srtp_lib" = "yesyes" ; then
		have_srtp=yes
		AC_CHECK_LIB(srtp,sha1_update,[
			AC_MSG_ERROR([This libsrtp version exports symbols conflicting with other libraries. Please use the one from git://git.linphone.org/srtp.git])], have_srtp=yes)
		AC_DEFINE(HAVE_SRTP, 1, [Defined when srtp support is compiled])
	else
		AC_MSG_NOTICE([Could not find libsrtp headers or lib, cryto transport disabled.])
		SRTP_CFLAGS=
		SRTP_LIBS=
	fi

	AC_SUBST(SRTP_CFLAGS)
	AC_SUBST(SRTP_LIBS)
else
	have_srtp=no
	SRTP_CFLAGS=
	SRTP_LIBS=
fi



dnl check for libzrtp support (RFC 6189: Media Path Key Agreement for Unicast Secure RTP)
dnl zrtp is GPLv3+
AC_ARG_ENABLE(zrtp,
	[AS_HELP_STRING([--enable-zrtp], [Turn on or off compilation of zrtp (GPLv3+ only) (default=no)])],
	[case "${enableval}" in
		yes)	zrtp=true ;;
		no)	zrtp=false ;;
		*)	AC_MSG_ERROR(bad value ${enableval} for --enable-zrtp) ;;
	esac],
	[zrtp=false]
)

if test "$zrtp" = "true" ; then
	PKG_CHECK_MODULES(LIBZRTPCPP, libzrtpcpp >= 2.0.0)
	if test "$have_srtp" = "no" ; then
		AC_MSG_ERROR("ZRTP requires SRTP")
	fi
	AC_DEFINE(HAVE_zrtp, 1, [Defined when zrtp support is compiled])
else
	echo "ZRTP compilation is disabled."
fi
AM_CONDITIONAL(LIBZRTPCPP,test x$zrtp != xfalse)


if test $debug_enabled = "yes"; then
	ORTP_DEFS="$ORTP_DEFS -DORTP_DEBUG_MODE -g"
	CFLAGS=`echo $CFLAGS | sed 's/-O.//'`
fi


AC_ARG_ENABLE(memcheck,
	[AS_HELP_STRING([--enable-memcheck], [Enable memory leak detection (HPUX only)])],
	[case "${enableval}" in
		yes)	memcheck_enabled=yes;;
		no)	memcheck_enabled=no;;
		*)	AC_MSG_ERROR("Bad value for --enable-memcheck");;
	esac],
	[memcheck_enabled=no]
)
				
if test "$memcheck_enabled" = "yes" ; then
	if test "$hpux_host" = "yes" ; then
		AC_DEFINE(ENABLE_MEMCHECK,1,[Defined when memory leak checking if enabled])
	else
		echo "WARNING ************ : the memory check option is only available for HPUX."
	fi
fi


dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(poll.h sys/poll.h sys/uio.h fcntl.h sys/time.h unistd.h sys/audio.h linux/soundcard.h sys/shm.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_HEADER_TIME
AC_WORDS_BIGENDIAN
if test x$ac_cv_c_bigendian = xyes ; then
	ORTP_DEFS="$ORTP_DEFS -DORTP_BIGENDIAN"
fi

dnl Checks for library functions.
AC_CHECK_FUNCS(select socket strerror)

if test $hpux_host = "yes" ; then
dnl it seems 10 ms is too fast on hpux and it causes trouble 
		posixtimer_interval=20000
fi

AC_DEFINE_UNQUOTED(POSIXTIMER_INTERVAL,$posixtimer_interval,[Defines the periodicity of the rtp scheduler in microseconds])

if test "$perf" = "yes" ; then
	CFLAGS="$CFLAGS -DPERF"
fi

if test $GCC = yes && test $wall_werror = yes;  then
	CFLAGS="$CFLAGS -Werror "
fi

AC_ARG_ENABLE(ssl-hmac,
	[AS_HELP_STRING([--enable-ssl-hmac], [Enable use of ssl/hmac for stun (default=no)])],
	[case "${enableval}" in
		yes)	ssl_hmac_enabled=yes;;
		no)	ssl_hmac_enabled=no;;
		*)	AC_MSG_ERROR("Bad value for --enable-ssl-hmac");;
	esac],
	[ssl_hmac_enabled=no]
)
				
if test "$ssl_hmac_enabled" = "yes" ; then
	AC_CHECK_HEADERS(openssl/hmac.h openssl/md5.h)
	AC_CHECK_LIB(ssl,SSL_CTX_new,[SSL_LIBS="-lssl"])
	AC_CHECK_LIB(crypto,MD5,[SSL_LIBS="$SSL_LIBS -lcrypto"])
fi



AC_SUBST(SSL_LIBS)

ORTPDEPS_LIBS="$ORTPDEPS_LIBS $PTHREAD_LIBS $PTHREAD_LDFLAGS $RT_LIBS $SRTP_LIBS $SSL_LIBS $LIBZRTPCPP_LIBS"
ORTPDEPS_CFLAGS="$ORTPDEPS_CFLAGS $PTHREAD_CFLAGS $ORTP_DEFS $SRTP_CFLAGS $LIBZRTPCPP_CFLAGS"
CFLAGS="$CFLAGS $ORTP_DEFS"
echo "$ORTPDEPS_CFLAGS" > ortp.defs


AC_ARG_ENABLE(tests_enabled,
	[AS_HELP_STRING([--disable-tests], [Disable compilation of tests])],
	[case "${enableval}" in
		yes)	tests_enabled=true ;;
		no)	tests_enabled=false ;;
		*)	AC_MSG_ERROR(bad value ${enableval} for --disable-tests) ;;
	esac],
	[tests_enabled=false]
)
AM_CONDITIONAL(ENABLE_TESTS, test x$tests_enabled = xyes)

dnl ##################################################
dnl # Check for doxygen
dnl ##################################################

AC_PATH_PROG(DOXYGEN,doxygen,false)
AM_CONDITIONAL(HAVE_DOXYGEN, test $DOXYGEN != false)


dnl ##################################################
dnl # Check for ESP Packager
dnl ##################################################

AC_PATH_PROG(EPM,epm,false)
AC_PATH_PROG(MKEPMLIST,mkepmlist,false)
AC_PATH_PROG(EPMINSTALL,epminstall,false)
AM_CONDITIONAL(WITH_EPM,test $EPM != false && test $MKEPMLIST != false && test $EPMINSTALL != false)

# Preferred packaging system, as per EPM terminology
case $target in
	*-*-linux*)
		if test -f /etc/debian_version ; then
			EPM_PKG_EXT=deb
		else
			EPM_PKG_EXT=rpm
		fi
	;;
	*-hp-hpux*)
		EPM_PKG_EXT=depot.gz
	;;
	*-dec-osf*)
		EPM_PKG_EXT=setld
	;;
esac
AC_SUBST(EPM_PKG_EXT)

# System software User & Group names
case $target in
	*-*-linux*)
		SYS_USER=root
		SYS_GROUP=root
	;;
	*-*-hpux*|*-dec-osf*)
		SYS_USER=bin
		SYS_GROUP=bin
	;;
esac
AC_SUBST(SYS_USER)
AC_SUBST(SYS_GROUP)

# CPU Architecture
case $target_cpu in
	i?86)
		ARCH=i386
	;;
	*)	ARCH=$target_cpu
	;;
esac
AC_SUBST(ARCH)

# Various other packaging variables, that can be over-ridden ad `make
# package' time
SUMMARY="An LGPL implementation of RTP - RFC3550"
AC_SUBST(SUMMARY)
PACKAGER=anonymous
AC_SUBST(PACKAGER)
LICENSE=LGPL
AC_SUBST(LICENSE)
VENDOR=Linphone
AC_SUBST(VENDOR)
RELEASE=1
AC_SUBST(RELEASE)

AC_SUBST(ORTPDEPS_CFLAGS)
AC_SUBST(ORTPDEPS_LIBS)
AC_SUBST(ORTPDEPS_LDFLAGS)

AC_OUTPUT(
	Makefile
	include/Makefile
	include/ortp/Makefile
	m4/Makefile
	src/Makefile
	src/tests/Makefile
	src/tests/win_receiver/Makefile
	src/tests/win_sender/Makefile
	build/Makefile
	build/win32native/Makefile
	build/wince/Makefile
	build/winmob/Makefile
	ortp.pc
	ortp.spec
	ortp.doxygen
)

if test "$zrtp" = "true" ; then
	AC_MSG_WARN([Compiled with ZRTP support thus license is now GPLv3+])
fi
