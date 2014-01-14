cmake_minimum_required(VERSION 2.6)
project(LIBORTP C)

option(ORTP_ENABLE_SRTP "Build oRTP with the SRTP transport support." ON)

include_directories(
	include/
	src/
)

if(USE_INSTALLED_COMPONENTS)
	include_directories(${CMAKE_INSTALL_PREFIX}/include)
	if(ORTP_ENABLE_SRTP)
		find_library(LIBSRTP libsrtp PATHS ${CMAKE_INSTALL_PREFIX}/lib)
	endif(ORTP_ENABLE_SRTP)
endif()

if(WIN32)
include_directories(build/vsx/oRTP/oRTP)
endif(WIN32)

add_subdirectory(include)
add_subdirectory(src)

if(INSTALL_COMPONENT_IN_POSTBUILD)
	add_install_target(INSTALL_libortp COMP_libortp libortp)
endif()
