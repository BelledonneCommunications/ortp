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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
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
	avprofile.c
	b64.c
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
	videobandwidthestimator.c
	utils.c
)
set(ORTP_SOURCE_FILES_CXX
	rtpbundle.cc
)

add_definitions(
	-DBCTBX_LOG_DOMAIN="ortp"
)

if(WIN32)
	list(APPEND ORTP_SOURCE_FILES_C dll_entry.c)
	if(CMAKE_SYSTEM_NAME STREQUAL "WindowsPhone")
		list(APPEND ORTP_SOURCE_FILES_CXX winrttimer.cpp winrttimer.h)
		set_source_files_properties(winrttimer.cpp PROPERTIES COMPILE_FLAGS "/ZW /AI\$(WindowsSDK_MetadataPath)")
	endif()
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

if(ENABLE_STATIC)
	add_library(ortp-static STATIC ${ORTP_HEADER_FILES} ${ORTP_SOURCE_FILES_C} ${ORTP_SOURCE_FILES_CXX})
	set_target_properties(ortp-static PROPERTIES OUTPUT_NAME ortp)
	set_target_properties(ortp-static PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED ON)
	target_compile_definitions(ortp-static PRIVATE "ORTP_EXPORTS")
	target_link_libraries(ortp-static INTERFACE ${LIBS})
	install(TARGETS ortp-static EXPORT ${EXPORT_TARGET_NAME}Targets
		ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
		PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
endif()
if(ENABLE_SHARED)
	add_library(ortp SHARED ${ORTP_HEADER_FILES} ${ORTP_SOURCE_FILES_C} ${ORTP_SOURCE_FILES_CXX})
	set_target_properties(ortp PROPERTIES LINKER_LANGUAGE CXX)
	set_target_properties(ortp PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED ON)
	if(APPLE)
		if(IOS)
			set(MIN_OS ${LINPHONE_IOS_DEPLOYMENT_TARGET})
		else()
			set(MIN_OS ${CMAKE_OSX_DEPLOYMENT_TARGET})
		endif()
		set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/build/osx/")
		set_target_properties(ortp PROPERTIES
			FRAMEWORK TRUE
			MACOSX_FRAMEWORK_IDENTIFIER org.linphone.ortp
  			MACOSX_FRAMEWORK_INFO_PLIST Info.plist.in
			PUBLIC_HEADER "${ORTP_HEADER_FILES}"
		)
	endif()
	if(NOT ANDROID)
		# Do not version shared library on Android
		set_target_properties(ortp PROPERTIES SOVERSION ${ORTP_SO_VERSION})
	endif()
	if(WIN32)
		target_compile_options(ortp PRIVATE "/DELAYLOAD:Qwave.dll")
	endif()
	target_compile_definitions(ortp PRIVATE "ORTP_EXPORTS")
	target_include_directories(ortp
		INTERFACE $<INSTALL_INTERFACE:include>
	)
	target_link_libraries(ortp PUBLIC bctoolbox PRIVATE ${LIBS})
	if(MSVC)
		if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
			install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_BUILD_TYPE}/ortp.pdb
				DESTINATION ${CMAKE_INSTALL_BINDIR}
				PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
			)
		endif()
	endif()
	install(TARGETS ortp EXPORT ${EXPORT_TARGET_NAME}Targets
		RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
		LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
		ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
		FRAMEWORK DESTINATION Frameworks
		PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
endif()

if(ENABLE_TESTS AND NOT CMAKE_SYSTEM_NAME STREQUAL "WindowsPhone" AND NOT CMAKE_SYSTEM_NAME STREQUAL "WindowsStore")
	add_subdirectory(tests)
endif()
