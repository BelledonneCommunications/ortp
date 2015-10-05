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

set(SOURCE_FILES
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

if(WIN32)
	list(APPEND SOURCE_FILES dll_entry.c)
	if("${CMAKE_SYSTEM_NAME}" STREQUAL "WindowsPhone")
		list(APPEND SOURCE_FILES winrttimer.cpp winrttimer.h)
		set_source_files_properties(winrttimer.cpp PROPERTIES COMPILE_FLAGS "/ZW /AI\$(WindowsSDK_MetadataPath)")
	endif()
endif()

add_definitions(
	-DORTP_EXPORTS
)

if(WIN32)
	add_definitions(-DWINDOWS_NATIVE)
	list(APPEND LIBS ws2_32)
	if(NOT "${CMAKE_SYSTEM_NAME}" STREQUAL "WindowsPhone")
		list(APPEND LIBS delayimp Winmm Qwave)
	endif()
endif()

if(ENABLE_STATIC)
	add_library(ortp STATIC ${SOURCE_FILES})
	target_link_libraries(ortp ${LIBS})
else()
	add_library(ortp SHARED ${SOURCE_FILES})
	set_target_properties(ortp PROPERTIES VERSION ${ORTP_SO_VERSION})
	target_link_libraries(ortp ${LIBS})
	if(MSVC)
		if(CMAKE_BUILD_TYPE STREQUAL "Debug")
			install(FILES ${CMAKE_CURRENT_BINARY_DIR}/Debug/ortp.pdb
				DESTINATION bin
				PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
			)
		endif()
	endif()
endif()

install(TARGETS ortp EXPORT ORTPTargets
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

if(ENABLE_TESTS)
	#add_subdirectory(tests)
endif()
