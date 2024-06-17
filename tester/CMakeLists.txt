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

set(ORTP_LIBS_FOR_TESTER ortp)

if(WIN32)
	#required for htons()
	list(APPEND ORTP_LIBS_FOR_TESTER Ws2_32)
endif()

set(RAW_FILES
	raw/h265-iframe
)

set(SOURCE_FILES_C
	ortp_tester.c
	extension_header_tester.c
	rtp_tester.c
)

set(IOS_RESOURCE_FILE)
set(SOURCE_FILES_CXX
	bundle_tester.cc
	fec_tester.cc
	ortp_tester_utils.cc
)
set(SOURCE_FILES_OBJC)

add_definitions(-DBCTBX_LOG_DOMAIN="ortp")

bc_apply_compile_flags(SOURCE_FILES_C STRICT_OPTIONS_CPP STRICT_OPTIONS_C)
bc_apply_compile_flags(SOURCE_FILES_CXX STRICT_OPTIONS_CPP STRICT_OPTIONS_CXX)
bc_apply_compile_flags(SOURCE_FILES_OBJC STRICT_OPTIONS_CPP STRICT_OPTIONS_OBJC)

if(CMAKE_SYSTEM_NAME STREQUAL "WindowsStore")
	add_library(ortp-tester-static STATIC ${SOURCE_FILES_C} ${SOURCE_FILES_CXX})
	target_link_libraries(ortp-tester-static PRIVATE ${ORTP_LIBS_FOR_TESTER} PUBLIC ${BCToolbox_tester_TARGET})
	
	# TODO : implement tester-runtime like bellesip
	#install(FILES "${CMAKE_CURRENT_BINARY_DIR}/BelledonneCommunications.ortp.Tester.winmd" DESTINATION lib)

	#install(FILES ${CMAKE_CURRENT_BINARY_DIR}/Debug/BelledonneCommunications.ortp.Tester.pdb
	#	DESTINATION ${CMAKE_INSTALL_LIBDIR}
	#	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	#	CONFIGURATIONS Debug RelWithDebInfo
	#)
else()
	if(IOS)
		set_source_files_properties(${IOS_RESOURCES_FILES} PROPERTIES MACOSX_PACKAGE_LOCATION Resources)
		add_executable(ortp-tester MACOSX_BUNDLE ${IOS_RESOURCES_FILES} ${SOURCE_FILES_C} ${SOURCE_FILES_CXX} ${SOURCE_FILES_OBJC})
		set_target_properties(ortp-tester PROPERTIES
			MACOSX_FRAMEWORK_INFO_PLIST Info.plist.in
			MACOSX_BUNDLE_BUNDLE_NAME org.linphone.ortp.ortp-tester
			MACOSX_BUNDLE_BUNDLE_VERSION 1.0
			MACOSX_BUNDLE_SHORT_VERSION_STRING "1.0")

	else()
		add_executable(ortp-tester ${SOURCE_FILES_C} ${SOURCE_FILES_CXX} ${SOURCE_FILES_OBJC})
	endif()

	set_target_properties(ortp-tester PROPERTIES LINKER_LANGUAGE CXX)
	target_link_libraries(ortp-tester PRIVATE ${ORTP_LIBS_FOR_TESTER} ${BCToolbox_tester_TARGET})

	if(NOT IOS)
		install(TARGETS ortp-tester
			RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
			LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
			ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
			PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
		)
		install(FILES ${RAW_FILES} DESTINATION "${CMAKE_INSTALL_DATADIR}/ortp-tester/raw")
	endif()
endif()
