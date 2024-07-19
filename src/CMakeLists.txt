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

set(LIBS )
if(NOT ANDROID)
	list(APPEND LIBS ${CMAKE_THREAD_LIBS_INIT})
endif()
if(HAVE_RT)
	list(APPEND LIBS rt)
endif()
if(LIBM)
	list(APPEND LIBS ${LIBM})
endif()

set(ORTP_SOURCE_FILES_C
	audiobandwidthestimator.c
	avprofile.c
	congestiondetector.c
	event.c
	extremum.c
	jitterctl.c
	kalmanrls.c
	logging.c
	nack.c
	netsim.c
	ortp.c
	payloadtype.c
	port.c
	posixtimer.c
	rtcp.c
	rtcp_fb.c
	rtcp_xr.c
	rtcpparse.c
	rtpaudiolevel.c
	rtpframemarking.c
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
set(ORTP_SOURCE_FILES_CXX
	dblk.cc	#HAVE_ATOMIC is mandatory
	rtpbundle.cc
	videobandwidthestimator.cc
	bandwidth-measurer.cc
	fecstream/fecstream.cc
	fecstream/fec-stream-stats.cc
	fecstream/fec-encoder.cpp
	fecstream/packet-api.cpp
	fecstream/receive-cluster.cpp
	fecstream/fec-packets-connection.cpp
	fecstream/fec-params.cpp
	fecstream/overhead.cpp
)

add_definitions(-DBCTBX_LOG_DOMAIN="ortp")

if(WIN32)
	list(APPEND ORTP_SOURCE_FILES_C dll_entry.c)
	if(CMAKE_SYSTEM_NAME STREQUAL "WindowsPhone")
		list(APPEND ORTP_SOURCE_FILES_CXX winrttimer.cpp winrttimer.h)
		set_source_files_properties(winrttimer.cpp PROPERTIES COMPILE_FLAGS "/ZW /AI\$(WindowsSDK_MetadataPath)")
	endif()
	list(APPEND LIBS ws2_32)# symbols for in6addr_any
endif()

if(WIN32)
	add_definitions(-DWINDOWS_NATIVE)
	if(NOT CMAKE_SYSTEM_NAME STREQUAL "WindowsStore")
		list(APPEND LIBS ws2_32)
	endif()
	if(NOT CMAKE_SYSTEM_NAME STREQUAL "WindowsPhone" AND NOT CMAKE_SYSTEM_NAME STREQUAL "WindowsStore")
		list(APPEND LIBS delayimp Winmm Qwave)
	endif()
endif()

bc_apply_compile_flags(ORTP_SOURCE_FILES_C STRICT_OPTIONS_CPP STRICT_OPTIONS_C)
bc_apply_compile_flags(ORTP_SOURCE_FILES_CXX STRICT_OPTIONS_CPP STRICT_OPTIONS_CXX)


add_library(ortp ${ORTP_HEADER_FILES} ${ORTP_SOURCE_FILES_C} ${ORTP_SOURCE_FILES_CXX})
set_target_properties(ortp PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(ortp PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
target_compile_definitions(ortp PRIVATE "ORTP_EXPORTS")
target_include_directories(ortp
	PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include>
)
target_link_libraries(ortp PUBLIC ${BCToolbox_TARGET} PRIVATE ${LIBS})
if(WIN32)
	target_compile_options(ortp PRIVATE "/DELAYLOAD:Qwave.dll")
endif()

if(BUILD_SHARED_LIBS)
	if(APPLE)
		set_target_properties(ortp PROPERTIES
			FRAMEWORK TRUE
			MACOSX_FRAMEWORK_IDENTIFIER org.linphone.ortp
  			MACOSX_FRAMEWORK_INFO_PLIST "${PROJECT_SOURCE_DIR}/build/osx/Info.plist.in"
			PUBLIC_HEADER "${ORTP_HEADER_FILES}"
		)
	endif()
	if(NOT ANDROID)
		# Do not version shared library on Android
		set_target_properties(ortp PROPERTIES SOVERSION ${ORTP_SO_VERSION})
	endif()
	if(MSVC)
		install(FILES $<TARGET_PDB_FILE:ortp>
			DESTINATION ${CMAKE_INSTALL_BINDIR}
			PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
			CONFIGURATIONS Debug RelWithDebInfo
		)
	endif()
endif()

install(TARGETS ortp EXPORT ${PROJECT_NAME}Targets
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	FRAMEWORK DESTINATION Frameworks
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

if(ENABLE_TESTS AND NOT CMAKE_SYSTEM_NAME STREQUAL "WindowsPhone" AND NOT CMAKE_SYSTEM_NAME STREQUAL "WindowsStore")
	add_subdirectory(tests)
endif()
