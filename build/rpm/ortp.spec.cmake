# -*- rpm-spec -*-
#
# ortp -- Real-time Transport Protocol Stack
#
# Default is optimized for Pentium IV but will execute on Pentium II &
# later (i686).

%define _prefix    @CMAKE_INSTALL_PREFIX@
%define pkg_prefix @BC_PACKAGE_NAME_PREFIX@
%define package_name @CPACK_PACKAGE_NAME@-${FULL_VERSION}

# re-define some directories for older RPMBuild versions which don't. This messes up the doc/ dir
# taken from https://fedoraproject.org/wiki/Packaging:RPMMacros?rd=Packaging/RPMMacros
%define _datarootdir       %{_prefix}/share
%define _datadir           %{_datarootdir}
%define _docdir            %{_datadir}/doc

%ifarch %ix86
%define		ortp_cpu	pentium4
%endif
Summary:	Real-time Transport Protocol Stack
Name:		@CPACK_PACKAGE_NAME@
Version:	${RPM_VERSION}
Release:	${RPM_RELEASE}%{?dist}
#to be alined with redhat which changed epoc to 1 for an unknown reason
Epoch:		1
License:	GPL
Group:		Applications/Communications
URL:		http://linphone.org/ortp/
Source0:	%{package_name}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-buildroot
%ifarch %ix86
BuildArch:	i686
%endif

Requires:	%{pkg_prefix}bctoolbox

%if 0%{?rhel} && 0%{?rhel} <= 7
%global cmake_name cmake3
%define ctest_name ctest3
%else
%global cmake_name cmake
%define ctest_name ctest
%endif

%description
oRTP is a GPL licensed C library implementing the RTP protocol
(rfc3550). It is available for most unix clones (primilarly Linux and
HP-UX), and Microsoft Windows.

%package        devel
Summary:        Headers, libraries and docs for the oRTP library
Group:          Development/Libraries
BuildRequires:	doxygen
#to be alined with redhat which changed epoc to 1 for an unknown reason
Epoch:		1
Requires:      %{name} = %{epoch}:%{version}-%{release}

%description    devel
oRTP is a GPL licensed C library implementing the RTP protocol
(rfc1889). It is available for most unix clones (primilarly Linux and
HP-UX), and Microsoft Windows.

This package contains header files and development libraries needed to
develop programs using the oRTP library.

%ifarch %ix86
%define	ortp_arch_cflags -malign-double -march=i686 -mtune=%{ortp_cpu}
%else
# Must be non-empty
%define ortp_arch_cflags -Wall
%endif
%define ortp_cflags %ortp_arch_cflags -Wall -g -pipe -pthread -O3 -fomit-frame-pointer -fno-schedule-insns -fschedule-insns2 -fno-strict-aliasing

# This is for debian builds where debug_package has to be manually specified, whereas in centos it does not
%define custom_debug_package %{!?_enable_debug_packages:%debug_package}%{?_enable_debug_package:%{nil}}
%custom_debug_package

%prep
%setup -n %{package_name}

%build
%{expand:%%%cmake_name} . -DCMAKE_BUILD_TYPE=@CMAKE_BUILD_TYPE@ -DCMAKE_PREFIX_PATH:PATH=%{_prefix} @RPM_ALL_CMAKE_OPTIONS@
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}

# Dirty workaround to give exec rights for all shared libraries. Debian packaging needs this
# TODO : set CMAKE_INSTALL_SO_NO_EXE for a cleaner workaround
chmod +x `find %{buildroot} *.so.*`


%check
%{ctest_name} -V %{?_smp_mflags}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc %{_docdir}/ortp-@ORTP_DOC_VERSION@/README.md
%doc %{_docdir}/ortp-@ORTP_DOC_VERSION@/CHANGELOG.md
%doc %{_docdir}/ortp-@ORTP_DOC_VERSION@/LICENSE.txt
%doc %{_docdir}/ortp-@ORTP_DOC_VERSION@/AUTHORS.md
%{_libdir}/*.so.*

%files devel
%defattr(-,root,root,-)
%if @ENABLE_DOC@
%doc %{_docdir}/ortp-%{version}/html/*
%endif
%if @ENABLE_STATIC@
%{_libdir}/*.a
%endif
%if @ENABLE_SHARED@
%{_libdir}/*.so
%endif
%{_libdir}/pkgconfig/*.pc
%{_includedir}/*
%{_libdir}/cmake/ortp/*


%changelog

* Tue Nov 27 2018 ronan.abhamon <ronan.abhamon@belledonne-communications.com>
- Do not set CMAKE_INSTALL_LIBDIR.

* Tue Oct 25 2005 Francois-Xavier Kowalski <fix@hp.com>
- Add to oRTP distribution with "make rpm" target
