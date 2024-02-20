############################################################################
# Copyright (c) 2010-2023 Belledonne Communications SARL.
#
# This file is part of oRTP 
# (see https://gitlab.linphone.org/BC/public/ortp).
#
############################################################################
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
############################################################################

cmake_minimum_required(VERSION 3.22)

project(Ortp VERSION 5.4.0)


set(ORTP_MAJOR_VERSION ${PROJECT_VERSION_MAJOR})
set(ORTP_MINOR_VERSION ${PROJECT_VERSION_MINOR})
set(ORTP_MICRO_VERSION ${PROJECT_VERSION_PATCH})
set(ORTP_VERSION ${PROJECT_VERSION})
set(ORTP_SO_VERSION "15") # incremented for 4.4.0 version.
set(ORTP_DOC_VERSION "${ORTP_VERSION_MAJOR}.${ORTP_VERSION_MINOR}")


option(ENABLE_DOC "Enable documentation generation with Doxygen." YES)
option(ENABLE_NTP_TIMESTAMP "Turn on NTP timestamping on packet reception." NO)
option(ENABLE_PERF "Disable costly features to reduce cpu consumtion and increase performance." NO)
option(ENABLE_STRICT "Build with strict compile options." YES)
option(ENABLE_TESTS "Enable compilation of test programs." NO)
option(ENABLE_UNIT_TESTS "Enable compilation of unit tests." YES)
option(ENABLE_DEBUG_LOGS "Turn on or off debug level logs." NO)
option(ENABLE_PACKAGE_SOURCE "Create 'package_source' target for source archive making" OFF)
set(WITH_THREAD_STACK_SIZE "0" CACHE STRING "Set thread stack size (0 is the OS default).")


list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")


include(CheckIncludeFile)
include(CheckFunctionExists)
include(GNUInstallDirs)
include(CheckCSourceCompiles)
include(CheckCXXSourceCompiles)
include(CheckSymbolExists)

if(NOT CMAKE_INSTALL_RPATH AND CMAKE_INSTALL_PREFIX)
	set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_FULL_LIBDIR})
	message(STATUS "Setting install rpath to ${CMAKE_INSTALL_RPATH}")
endif()

find_package(Threads)
find_library(LIBM NAMES m)

find_package(BCToolbox 5.3.0 REQUIRED)
#Mandatory to init default compilation flags
bc_init_compilation_flags(STRICT_OPTIONS_CPP STRICT_OPTIONS_C STRICT_OPTIONS_CXX ENABLE_STRICT)

check_include_file(sys/uio.h HAVE_SYS_UIO_H)
check_include_file(sys/audio.h HAVE_SYS_AUDIO_H)
if(NOT ANDROID)
	check_include_file(sys/shm.h HAVE_SYS_SHM_H)
endif()

set (CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS_BAK "${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")# need this for check_cxx_source_compiles because CMAKE_CXX_STANDARD doesn't work.
check_cxx_source_compiles("#include <atomic>
using namespace std;
int main(int argc, char *argv[]) {
atomic_int current_ref;
atomic_init(&current_ref, 1);
atomic_int previous_ref(atomic_fetch_sub_explicit(&current_ref, 1, memory_order_release));
return 0;
}"
	HAVE_ATOMIC)
if(NOT HAVE_ATOMIC)
	message(FATAL_ERROR "Atomic(C++) libraries have not been found for ORTP.")
endif()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_BAK}")

check_function_exists(arc4random HAVE_ARC4RANDOM)
check_symbol_exists(recvmsg "sys/socket.h" HAVE_RECVMSG)
check_symbol_exists(sendmsg "sys/socket.h" HAVE_SENDMSG)

include(TestBigEndian)
test_big_endian(WORDS_BIGENDIAN)
if(WORDS_BIGENDIAN)
	set(ORTP_BIGENDIAN 1)
endif()


include_directories(
	include/
	src/
	${PROJECT_BINARY_DIR}
)


set(ORTP_CPPFLAGS)
if(ENABLE_PERF)
	set(PERF 1)
endif()
if(ENABLE_NTP_TIMESTAMP)
	set(ORTP_TIMESTAMP 1)
	list(APPEND ORTP_CPPFLAGS "-DORTP_TIMESTAMP")
endif()
if(ENABLE_DEBUG_LOGS)
	add_definitions("-DORTP_DEBUG_MODE -DBCTBX_DEBUG_MODE")
endif()
if(CMAKE_USE_PTHREADS_INIT)
	set(ORTP_DEFAULT_THREAD_STACK_SIZE ${WITH_THREAD_STACK_SIZE})
endif()
if(APPLE)
	set(__APPLE_USE_RFC_3542 1)
endif()
if(ORTP_CPPFLAGS)
	add_definitions(${ORTP_CPPFLAGS})
endif()
set(POSIXTIMER_INTERVAL 10000)
configure_file(${PROJECT_SOURCE_DIR}/ortp-config.h.cmake ${PROJECT_BINARY_DIR}/ortp-config.h)
set_source_files_properties(${PROJECT_BINARY_DIR}/ortp-config.h PROPERTIES GENERATED ON)
add_compile_definitions("HAVE_CONFIG_H")

# Enable stdint.h limit macros on C++ files. (Windows only.)
if(MSVC)
	add_compile_definitions("__STDC_LIMIT_MACROS")
endif()

if(MSVC)
	if(ENABLE_STRICT)
		list(APPEND STRICT_OPTIONS_CPP "/WX")
	endif()
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()
if(STRICT_OPTIONS_CPP)
	list(REMOVE_DUPLICATES STRICT_OPTIONS_CPP)
endif()
if(STRICT_OPTIONS_C)
	list(REMOVE_DUPLICATES STRICT_OPTIONS_C)
endif()

add_subdirectory(include)
add_subdirectory(src)
if(ENABLE_UNIT_TESTS AND NOT WIN32)
	add_subdirectory(tester)
endif()

if(ENABLE_DOC)
	find_package(Doxygen)
	if(DOXYGEN_FOUND)
		set(DOXYGEN_INPUT "")
		file(GLOB DOC_INPUT_FILES
			"${PROJECT_SOURCE_DIR}/include/ortp/[^.]*.h"
			"${PROJECT_SOURCE_DIR}/src/[^.]*.h"
			"${PROJECT_SOURCE_DIR}/src/[^.]*.c"
		)
		foreach (INPUT_FILE ${DOC_INPUT_FILES})
			string(CONCAT DOXYGEN_INPUT ${DOXYGEN_INPUT} " \"${INPUT_FILE}\"")
		endforeach ()
		configure_file(${PROJECT_SOURCE_DIR}/ortp.doxygen.in ${PROJECT_BINARY_DIR}/ortp.doxygen)
		add_custom_command(OUTPUT "${PROJECT_BINARY_DIR}/doc/html/index.html"
			COMMAND "${DOXYGEN_EXECUTABLE}" "${PROJECT_BINARY_DIR}/ortp.doxygen"
			DEPENDS "${PROJECT_BINARY_DIR}/ortp.doxygen" ${DOC_INPUT_FILES}
		)
		add_custom_target(ortp-html-doc ALL DEPENDS "${PROJECT_BINARY_DIR}/doc/html/index.html")
		install(DIRECTORY "${PROJECT_BINARY_DIR}/doc/html"
			DESTINATION "${CMAKE_INSTALL_DATADIR}/doc/ortp-${ORTP_VERSION}")
	endif()
endif()



set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix ${prefix}/bin)
set(libdir ${prefix}/lib)
set(includedir ${prefix}/include)
set(ORTP_PKGCONFIG_VERSION "${ORTP_VERSION}")
set(ORTPDEPS_LIBS )

configure_file(${PROJECT_SOURCE_DIR}/ortp.pc.in ${PROJECT_BINARY_DIR}/ortp.pc)
install(FILES ${PROJECT_BINARY_DIR}/ortp.pc DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

if (ENABLE_PACKAGE_SOURCE)
	add_subdirectory(build)
endif()

include(CMakePackageConfigHelpers)
set(CMAKE_MODULES_INSTALL_DIR "${CMAKE_INSTALL_DATADIR}/${PROJECT_NAME}/cmake")
configure_package_config_file("cmake/${PROJECT_NAME}Config.cmake.in" "${PROJECT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
	INSTALL_DESTINATION "${CMAKE_MODULES_INSTALL_DIR}"
	NO_SET_AND_CHECK_MACRO
)
write_basic_package_version_file("${PROJECT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY AnyNewerVersion
)
install(FILES
	"${PROJECT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
	"${PROJECT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
	DESTINATION ${CMAKE_MODULES_INSTALL_DIR}
)

install(EXPORT ${PROJECT_NAME}Targets
	FILE "${PROJECT_NAME}Targets.cmake"
	DESTINATION ${CMAKE_MODULES_INSTALL_DIR}
)

install(FILES "${PROJECT_SOURCE_DIR}/README.md" 
	"${PROJECT_SOURCE_DIR}/CHANGELOG.md" 
	"${PROJECT_SOURCE_DIR}/LICENSE.txt" 
	"${PROJECT_SOURCE_DIR}/AUTHORS.md" 
	DESTINATION "${CMAKE_INSTALL_DATADIR}/doc/ortp-${ORTP_VERSION}"
)
