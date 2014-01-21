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
	include_directories(build/vsx/oRTP/oRTP)
endif(WIN32)

add_subdirectory(include)
add_subdirectory(src)
