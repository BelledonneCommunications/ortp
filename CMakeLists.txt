cmake_minimum_required(VERSION 2.6)
project(LIBORTP C)

include_directories(
	include/
	src/
)

if(WIN32)
include_directories(build/vsx/oRTP/oRTP)
endif(WIN32)

add_subdirectory(include)
add_subdirectory(src)

if(INSTALL_COMPONENT_IN_POSTBUILD)
	add_install_target(INSTALL_libortp COMP_libortp libortp)
endif()
