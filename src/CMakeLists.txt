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

set(LIBS ${CMAKE_THREAD_LIBS_INIT})
if(HAVE_RT)
	list(APPEND LIBS rt)
endif()

set(ORTP_SOURCE_FILES_C
	avprofile.c
	b64.c
	event.c
	extremum.c
	jitterctl.c
	logging.c
	netsim.c
	ortp.c
	payloadtype.c
	port.c
	posixtimer.c
	rtcp.c
	rtcp_fb.c
	rtcp_xr.c
	rtcpparse.c
	rtpparse.c
	rtpprofile.c
	rtpsession.c
	rtpsession_inet.c
	rtpsignaltable.c
	rtptimer.c
	scheduler.c
	sessionset.c
	str_utils.c
	telephonyevents.c
	utils.c
)
set(ORTP_SOURCE_FILES_CXX )

if(WIN32)
	list(APPEND ORTP_SOURCE_FILES_C dll_entry.c)
	if(CMAKE_SYSTEM_NAME STREQUAL "WindowsPhone")
		list(APPEND ORTP_SOURCE_FILES_CXX winrttimer.cpp winrttimer.h)
		set_source_files_properties(winrttimer.cpp PROPERTIES COMPILE_FLAGS "/ZW /AI\$(WindowsSDK_MetadataPath)")
	endif()
endif()

add_definitions(
	-DORTP_EXPORTS
)

if(WIN32)
	add_definitions(-DWINDOWS_NATIVE)
	list(APPEND LIBS ws2_32)
	if(NOT CMAKE_SYSTEM_NAME STREQUAL "WindowsPhone")
		list(APPEND LIBS delayimp Winmm Qwave)
	endif()
endif()

apply_compile_flags(ORTP_SOURCE_FILES_C "CPP" "C")
apply_compile_flags(ORTP_SOURCE_FILES_CXX "CPP" "CXX")

if(ENABLE_STATIC)
	add_library(ortp STATIC ${ORTP_HEADER_FILES} ${ORTP_SOURCE_FILES_C} ${ORTP_SOURCE_FILES_CXX})
else()
	add_library(ortp SHARED ${ORTP_HEADER_FILES} ${ORTP_SOURCE_FILES_C} ${ORTP_SOURCE_FILES_CXX})
	set_target_properties(ortp PROPERTIES VERSION ${ORTP_SO_VERSION})
	if(MSVC)
		if(CMAKE_BUILD_TYPE STREQUAL "Debug")
			install(FILES ${CMAKE_CURRENT_BINARY_DIR}/Debug/ortp.pdb
				DESTINATION bin
				PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
			)
		endif()
	endif()
endif()
target_link_libraries(ortp ${LIBS})

install(TARGETS ortp EXPORT ${EXPORT_TARGETS_NAME}Targets
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

if(ENABLE_TESTS)
	#add_subdirectory(tests)
endif()
