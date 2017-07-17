# -*- rpm-spec -*-
#
# ortp -- Real-time Transport Protocol Stack
#
# Default is optimized for Pentium IV but will execute on Pentium II &
# later (i686).

# These 2 lines are here because we can build the RPM for flexisip, in which 
# case we prefix the entire installation so that we don't break compatibility
# with the user's libs.
# To compile with bc prefix, use rpmbuild -ba --with bc [SPEC]
%define 		pkg_name 	%{?_with_bc:bc-ortp}%{!?_with_bc:ortp}
%{?_with_bc: %define 	_prefix		/opt/belledonne-communications}
%define 		srtp 		%{?_without_srtp:0}%{?!_without_srtp:1}

# re-define some directories for older RPMBuild versions which don't. This messes up the doc/ dir
# taken from https://fedoraproject.org/wiki/Packaging:RPMMacros?rd=Packaging/RPMMacros
%define _datarootdir       %{_prefix}/share
%define _datadir           %{_datarootdir}
%define _docdir            %{_datadir}/doc

%ifarch %ix86
%define		ortp_cpu	pentium4
%endif
%define build_number @PROJECT_VERSION_BUILD@
Summary:	Real-time Transport Protocol Stack
Name:		%pkg_name
Version:	@PROJECT_VERSION@
Release:	%build_number%{?dist}
#to be alined with redhat which changed epoc to 1 for an unknown reason
Epoch:		1
License:	GPL
Group:		Applications/Communications
URL:		http://linphone.org/ortp/
Source0:	%{name}-%{version}-%build_number.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-buildroot
%ifarch %ix86
BuildArch:	i686
%endif

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

%prep
%setup -n %{name}-%{version}-%build_number

%build
%{expand:%%%cmake_name} . -DCMAKE_INSTALL_LIBDIR:PATH=%{_libdir} -DCMAKE_PREFIX_PATH:PATH=%{_prefix}
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}

%check
%{ctest_name} -V %{?_smp_mflags}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc %{_docdir}/ortp-%{version}/README.md
%doc %{_docdir}/ortp-%{version}/ChangeLog
%doc %{_docdir}/ortp-%{version}/COPYING
%doc %{_docdir}/ortp-%{version}/AUTHORS
%{_libdir}/*.so.*

%files devel
%defattr(-,root,root,-)
%doc %{_docdir}/ortp-%{version}/html/*
%{_libdir}/*.a
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
%{_includedir}/*
%{_datadir}/oRTP/cmake/ORTPConfig.cmake 
%{_datadir}/oRTP/cmake/ORTPConfigVersion.cmake
%{_datadir}/oRTP/cmake/ORTPTargets-noconfig.cmake
%{_datadir}/oRTP/cmake/ORTPTargets.cmake

%changelog
* Tue Oct 25 2005 Francois-Xavier Kowalski <fix@hp.com>
- Add to oRTP distribution with "make rpm" target
