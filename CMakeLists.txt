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

cmake_minimum_required(VERSION 3.0)
project(ORTP)


set(ORTP_MAJOR_VERSION "0")
set(ORTP_MINOR_VERSION "24")
set(ORTP_MICRO_VERSION "2")
set(ORTP_VERSION "${ORTP_MAJOR_VERSION}.${ORTP_MINOR_VERSION}.${ORTP_MICRO_VERSION}")
set(ORTP_SO_VERSION "9")


option(ENABLE_STATIC "Build static library (default is shared library)." NO)
option(ENABLE_DOC "Enable documentation generation with Doxygen." YES)
option(ENABLE_NTP_TIMESTAMP "Turn on NTP timestamping on packet reception." NO)
option(ENABLE_PERF "Disable costly features to reduce cpu consumtion and increase performance." NO)
option(ENABLE_TESTS "Enable compilation of test programs." NO)
option(ENABLE_DEBUG_LOGS "Turn on or off debug level logs." NO)
set(CACHE WITH_THREAD_STACK_SIZE "0" CACHE STRING "Set thread stack size (0 is the OS default).")


list(APPEND CMAKE_MODULE_PATH ${CMAKE_PREFIX_PATH}/share/cmake/Modules)


include(CheckIncludeFile)
include(CheckFunctionExists)

set(MSVC_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include/MSVC")
if(MSVC)
	list(APPEND CMAKE_REQUIRED_INCLUDES "${MSVC_INCLUDE_DIR}")
endif()

find_package(Threads)

check_include_file(sys/uio.h HAVE_SYS_UIO_H)
check_include_file(sys/audio.h HAVE_SYS_AUDIO_H)
check_include_file(sys/shm.h HAVE_SYS_SHM_H)
check_function_exists(arc4random HAVE_ARC4RANDOM)

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
if(MSVC)
	include_directories(${MSVC_INCLUDE_DIR})
endif()


set(ORTP_CPPFLAGS )
if(ENABLE_STATIC)
	set(ORTP_STATIC 1)
	list(APPEND ORTP_CPPFLAGS "-DORTP_STATIC")
endif()
if(ENABLE_PERF)
	set(PERF 1)
endif()
if(ENABLE_NTP_TIMESTAMP)
	set(ORTP_TIMESTAMP 1)
endif()
if(ENABLE_DEBUG_LOGS)
	set(ORTP_DEBUG_MODE 1)
endif()
if(CMAKE_USE_PTHREADS_INIT)
	set(ORTP_DEFAULT_THREAD_STACK_SIZE ${WITH_THREAD_STACK_SIZE})
endif()
if(APPLE)
	set(__APPLE_USE_RFC_2292 1)
endif()
set(POSIXTIMER_INTERVAL 10000)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ortp-config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/ortp-config.h)
set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/ortp-config.h PROPERTIES GENERATED ON)
add_definitions(-DHAVE_CONFIG_H)
if(NOT MSVC)
	add_definitions(-Wall -Wno-error=unknown-pragmas)
	if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
		add_definitions(-Werror -Wno-error=unknown-warning-option -Qunused-arguments -Wno-tautological-compare)
	elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
		add_definitions(-Werror -Wno-error=pragmas)
	endif()
endif()

add_subdirectory(include)
add_subdirectory(src)


if(ENABLE_DOC)
	find_package(Doxygen)
	if(DOXYGEN_FOUND)
		set(srcdir ${CMAKE_CURRENT_SOURCE_DIR})
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ortp.doxygen.in ${CMAKE_CURRENT_BINARY_DIR}/ortp.doxygen)
		file(GLOB DOC_INPUT_FILES
			include/ortp/[^.]*.h
			src/[^.]*.h
			src/[^.]*.c
		)
		add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/doc/html/index.html"
			COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/ortp.doxygen
			DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/ortp.doxygen ${DOC_INPUT_FILES}
		)
		add_custom_target(html-doc ALL DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/doc/html/index.html")
		install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/doc/html"
			DESTINATION "share/doc/oRTP-${ORTP_VERSION}")
	endif()
endif()




set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix ${prefix}/bin)
set(libdir ${prefix}/lib)
set(includedir ${prefix}/include)
set(ORTP_PKGCONFIG_VERSION "${ORTP_VERSION}")
set(ORTPDEPS_LIBS )

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ortp.pc.in ${CMAKE_CURRENT_BINARY_DIR}/ortp.pc)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ortp.pc DESTINATION lib/pkgconfig)


include(CMakePackageConfigHelpers)
write_basic_package_version_file(
	"${CMAKE_CURRENT_BINARY_DIR}/ORTPConfigVersion.cmake"
	VERSION ${ORTP_VERSION}
	COMPATIBILITY AnyNewerVersion
)
export(EXPORT ORTPTargets
	FILE "${CMAKE_CURRENT_BINARY_DIR}/ORTPTargets.cmake"
	NAMESPACE BelledonneCommunications::
)
configure_file(ORTPConfig.cmake.in
	"${CMAKE_CURRENT_BINARY_DIR}/ORTPConfig.cmake"
	@ONLY
)

set(ConfigPackageLocation lib/cmake/oRTP)
install(EXPORT ORTPTargets
	FILE ORTPTargets.cmake
	NAMESPACE BelledonneCommunications::
	DESTINATION ${ConfigPackageLocation}
)
install(FILES
	"${CMAKE_CURRENT_BINARY_DIR}/ORTPConfig.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/ORTPConfigVersion.cmake"
	DESTINATION ${ConfigPackageLocation}
)
