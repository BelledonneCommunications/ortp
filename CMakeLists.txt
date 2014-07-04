cmake_minimum_required(VERSION 2.6)
project(ORTP C)

option(ORTP_ENABLE_SRTP "Build oRTP with the SRTP transport support." ON)

include_directories(
	include/
	src/
)

include_directories(${CMAKE_INSTALL_PREFIX}/include)
if(ORTP_ENABLE_SRTP)
	find_library(LIBSRTP NAMES srtp)
endif(ORTP_ENABLE_SRTP)

if(WIN32)
	include_directories(build/wp8/oRTP)
endif(WIN32)

set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix ${prefix}/bin)
set(libdir ${prefix}/lib)
set(includedir ${prefix}/include)
set(ORTP_PKGCONFIG_VERSION "0.23.0")
if(ORTP_ENABLE_SRTP)
	set(ORTPDEPS_LIBS "-lsrtp")
endif()
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ortp.pc.in ${CMAKE_CURRENT_BINARY_DIR}/ortp.pc)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ortp.pc DESTINATION lib/pkgconfig)

add_subdirectory(include)
add_subdirectory(src)
