/***************************************************************************
* config.h.cmake
* Copyright (C) 2014  Belledonne Communications, Grenoble France
*
****************************************************************************
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*
****************************************************************************/

#define ORTP_MAJOR_VERSION ${ORTP_MAJOR_VERSION}
#define ORTP_MINOR_VERSION ${ORTP_MINOR_VERSION}
#define ORTP_MICRO_VERSION ${ORTP_MICRO_VERSION}
#define ORTP_VERSION "${ORTP_VERSION}"

#cmakedefine HAVE_INTTYPES_H
#cmakedefine HAVE_MEMORY_H
#cmakedefine HAVE_STDINT_H
#cmakedefine HAVE_STDLIB_H
#cmakedefine HAVE_STRINGS_H
#cmakedefine HAVE_STRING_H
#cmakedefine HAVE_SYS_STAT_H
#cmakedefine HAVE_SYS_TYPES_H
#cmakedefine HAVE_POLL_H
#cmakedefine HAVE_SYS_POLL_H
#cmakedefine HAVE_SYS_UIO_H
#cmakedefine HAVE_FCNTL_H
#cmakedefine HAVE_SYS_TIME_H
#cmakedefine HAVE_UNISTD_H
#cmakedefine HAVE_SYS_AUDIO_H
#cmakedefine HAVE_LINUX_SOUNDCARD_H
#cmakedefine HAVE_SYS_SHM_H

#cmakedefine HAVE_SELECT
#cmakedefine HAVE_SOCKET
#cmakedefine HAVE_STRERROR

#cmakedefine HAVE_SETEUID
#cmakedefine HAVE_ARC4RANDOM

#cmakedefine ORTP_BIGENDIAN

#cmakedefine PERF
#cmakedefine ORTP_STATIC
#cmakedefine ORTP_TIMESTAMP
#cmakedefine ORTP_DEBUG_MODE
#cmakedefine ORTP_DEFAULT_THREAD_STACK_SIZE ${ORTP_DEFAULT_THREAD_STACK_SIZE}

#cmakedefine HAVE_SRTP
