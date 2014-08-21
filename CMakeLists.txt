############################################################################
# CMakeLists.txt
# Copyright (C) 2014  Belledonne Communications, Grenoble France
#
############################################################################
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
############################################################################

cmake_minimum_required(VERSION 2.6)
project(ORTP C)


set(ORTP_MAJOR_VERSION "0")
set(ORTP_MINOR_VERSION "23")
set(ORTP_MICRO_VERSION "0")
set(ORTP_VERSION "${ORTP_MAJOR_VERSION}.${ORTP_MINOR_VERSION}.${ORTP_MICRO_VERSION}")
set(ORTP_SO_VERSION "9")


option(ENABLE_STATIC "Build static library (default is shared library)." NO)
option(ENABLE_NTP_TIMESTAMP "Turn on NTP timestamping on packet reception." NO)
option(ENABLE_PERF "Disable costly features to reduce cpu consumtion and increase performance." NO)
option(ENABLE_SRTP "Build oRTP with the SRTP transport support." YES)
option(ENABLE_TESTS "Enable compilation of test programs." NO)
option(ENABLE_ZRTP "Build oRTP with the ZRTP transport support." YES)
set(CACHE WITH_THREAD_STACK_SIZE "0" CACHE STRING "Set thread stack size (0 is the OS default).")


list(APPEND CMAKE_MODULE_PATH ${CMAKE_PREFIX_PATH}/share/cmake/Modules)
if(ENABLE_SRTP)
	find_package(SRTP)
	if(NOT SRTP_FOUND)
		message(WARNING "Could not find SRTP library, oRTP will be compiled without SRTP support.")
		set(ENABLE_SRTP OFF CACHE BOOL "Build oRTP with the SRTP transport support." FORCE)
	endif()
endif()
if(ENABLE_ZRTP)
	find_package(BZRTP)
	if(NOT BZRTP_FOUND)
		message(WARNING "Could not find bzrtp library, oRTP will be compiled without ZRTP support.")
		set(ENABLE_ZRTP OFF CACHE BOOL "Build oRTP with the ZRTP transport support." FORCE)
	endif()
endif()
find_package(Doxygen)


include(CheckCSourceCompiles)
include(CheckIncludeFile)
include(CheckLibraryExists)
include(CheckFunctionExists)
if("${CMAKE_VERSION}" VERSION_GREATER "2.8.5")
	include(CMakePushCheckState)
endif()

if(MSVC)
	list(APPEND CMAKE_REQUIRED_INCLUDES ${CMAKE_PREFIX_PATH}/include/MSVC)
endif()

find_package(Threads)

check_include_file(inttypes.h HAVE_INTTYPES_H)
check_include_file(memory.h HAVE_MEMORY_H)
check_include_file(stdint.h HAVE_STDINT_H)
check_include_file(stdlib.h HAVE_STDLIB_H)
check_include_file(strings.h HAVE_STRINGS_H)
check_include_file(string.h HAVE_STRING_H)
check_include_file(sys/stat.h HAVE_SYS_STAT_H)
check_include_file(sys/types.h HAVE_SYS_TYPES_H)
check_include_file(poll.h HAVE_POLL_H)
check_include_file(sys/poll.h HAVE_SYS_POLL_H)
check_include_file(sys/uio.h HAVE_SYS_UIO_H)
check_include_file(fcntl.h HAVE_FCNTL_H)
check_include_file(sys/time.h HAVE_SYS_TIME_H)
check_include_file(unistd.h HAVE_UNISTD_H)
check_include_file(sys/audio.h HAVE_SYS_AUDIO_H)
check_include_file(linux/soundcard.h HAVE_LINUX_SOUNDCARD_H)
check_include_file(sys/shm.h HAVE_SYS_SHM_H)
check_include_file(windows.h HAVE_WINDOWS_H)
if(HAVE_WINDOWS_H)
	check_include_file(winsock2.h HAVE_WINSOCK2_H)
endif()

if(MSVC)
	if("${CMAKE_VERSION}" VERSION_GREATER "2.8.5")
		cmake_push_check_state(RESET)
	else()
		set(SAVE_CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES})
	endif()
	set(CMAKE_REQUIRED_LIBRARIES ws2_32)
	check_c_source_compiles("#include <winsock2.h>
int main(int argc, char *argv[]) {
select(0, 0, 0, 0, 0);
return 0;
}"
	HAVE_SELECT)
	check_c_source_compiles("#include <winsock2.h>
int main(int argc, char *argv[]) {
socket(0, 0, 0);
return 0;
}"
	HAVE_SOCKET)
	check_c_source_compiles("#include <winsock2.h>
int main(int argc, char *argv[]) {
strerror(0);
return 0;
}"
	HAVE_STRERROR)
	if("${CMAKE_VERSION}" VERSION_GREATER "2.8.5")
		cmake_pop_check_state()
	else()
		set(CMAKE_REQUIRED_LIBRARIES ${SAVE_CMAKE_REQUIRED_LIBRARIES})
	endif()
else()
	check_function_exists("select" HAVE_SELECT)
	check_function_exists("socket" HAVE_SOCKET)
	check_function_exists("strerror" HAVE_STRERROR)
endif()
if(NOT HAVE_SELECT)
	message(FATAL_ERROR "select has not been found")
endif()
if(NOT HAVE_SOCKET)
	message(FATAL_ERROR "socket has not been found")
endif()
if(NOT HAVE_STRERROR)
	message(FATAL_ERROR "strerror has not been found")
endif()
check_function_exists(seteuid HAVE_SETEUID)
check_function_exists(arc4random HAVE_ARC4RANDOM)

check_library_exists("rt" "clock_gettime" "" HAVE_LIBRT)

include(TestBigEndian)
test_big_endian(WORDS_BIGENDIAN)
if(WORDS_BIGENDIAN)
	set(ORTP_BIGENDIAN 1)
endif()


include_directories(
	include/
	src/
	${CMAKE_CURRENT_BINARY_DIR}
)
if(SRTP_FOUND)
	include_directories(${SRTP_INCLUDE_DIRS})
endif()
if(BZRTP_FOUND)
	include_directories(${BZRTP_INCLUDE_DIRS})
endif()
if(MSVC)
	include_directories(${CMAKE_PREFIX_PATH}/include/MSVC)
endif()


if(SRTP_FOUND)
	set(HAVE_SRTP 1)
endif()
if(ENABLE_STATIC)
	set(ORTP_STATIC 1)
endif()
if(ENABLE_PERF)
	set(PERF 1)
endif()
if(ENABLE_NTP_TIMESTAMP)
	set(ORTP_TIMESTAMP 1)
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(ORTP_DEBUG_MODE 1)
endif()
if(CMAKE_USE_PTHREADS_INIT)
	set(ORTP_DEFAULT_THREAD_STACK_SIZE ${WITH_THREAD_STACK_SIZE})
endif()
set(POSIXTIMER_INTERVAL 10000)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ortp-config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/ortp-config.h)
set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/ortp-config.h PROPERTIES GENERATED ON)
add_definitions(-DHAVE_CONFIG_H)


add_subdirectory(include)
add_subdirectory(src)


set(ORTP_CPPFLAGS )
if(ORTP_STATIC)
	list(APPEND ORTP_CPPFLAGS "-DORTP_STATIC")
endif()
if(SRTP_FOUND)
	list(APPEND ORTP_CPPFLAGS "-DORTP_HAVE_SRTP")
endif()
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/FindORTP.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/FindORTP.cmake)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/FindORTP.cmake
	DESTINATION share/cmake/Modules
	PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
)


if(DOXYGEN_FOUND)
	set(srcdir ${CMAKE_CURRENT_SOURCE_DIR})
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ortp.doxygen.in ${CMAKE_CURRENT_BINARY_DIR}/ortp.doxygen)
	add_custom_target(html-doc ALL
		${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/ortp.doxygen
		DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/ortp.doxygen)
	install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/doc/html"
		DESTINATION "${CMAKE_INSTALL_PREFIX}/share/doc/oRTP-${ORTP_VERSION}")
endif()
