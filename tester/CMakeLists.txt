############################################################################
# Copyright (c) 2010-2022 Belledonne Communications SARL.
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

if(ENABLE_SHARED)
	set(ORTP_LIBS_FOR_TESTER ortp)
else()
	set(ORTP_LIBS_FOR_TESTER ortp-static)
endif()

if(WIN32)
	#required for htons()
	list(APPEND ORTP_LIBS_FOR_TESTER Ws2_32)
endif()

set(SOURCE_FILES_C
	ortp_tester.c
	fec_tester.c
)

set(IOS_RESOURCE_FILE)
set(SOURCE_FILES_CXX)
set(SOURCE_FILES_OBJC)

bc_apply_compile_flags(SOURCE_FILES_C STRICT_OPTIONS_CPP STRICT_OPTIONS_C)
bc_apply_compile_flags(SOURCE_FILES_CXX STRICT_OPTIONS_CPP STRICT_OPTIONS_CXX)
bc_apply_compile_flags(SOURCE_FILES_OBJC STRICT_OPTIONS_CPP STRICT_OPTIONS_OBJC)

if(CMAKE_SYSTEM_NAME STREQUAL "WindowsStore")
	add_library(ortp_tester_static STATIC ${SOURCE_FILES_C} ${SOURCE_FILES_CXX})
	target_include_directories(ortp_tester_static PUBLIC ${BCTOOLBOX_INCLUDE_DIRS})
	target_link_libraries(ortp_tester_static ${ORTP_LIBS_FOR_TESTER} bctoolbox bctoolbox-tester)
	
	# TODO : implement tester-runtime like bellesip
	#install(FILES "${CMAKE_CURRENT_BINARY_DIR}/BelledonneCommunications.ortp.Tester.winmd" DESTINATION lib)

	#if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	#	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/Debug/BelledonneCommunications.ortp.Tester.pdb
	#		DESTINATION ${CMAKE_INSTALL_LIBDIR}
	#		PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	#	)
	#endif()
else()
	if(IOS)
		set_source_files_properties(${IOS_RESOURCES_FILES} PROPERTIES MACOSX_PACKAGE_LOCATION Resources)
		add_executable(ortp_tester MACOSX_BUNDLE ${IOS_RESOURCES_FILES} ${SOURCE_FILES_C} ${SOURCE_FILES_CXX} ${SOURCE_FILES_OBJC})
		set_target_properties(ortp_tester PROPERTIES
			MACOSX_FRAMEWORK_INFO_PLIST Info.plist.in
			MACOSX_BUNDLE_BUNDLE_NAME org.linphone.ortp.ortp-tester
			MACOSX_BUNDLE_BUNDLE_VERSION 1.0
			MACOSX_BUNDLE_SHORT_VERSION_STRING "1.0")

	else()
		add_executable(ortp_tester ${SOURCE_FILES_C} ${SOURCE_FILES_CXX} ${SOURCE_FILES_OBJC})
	endif()

	set_target_properties(ortp_tester PROPERTIES LINKER_LANGUAGE CXX)
	target_include_directories(ortp_tester PUBLIC ${BCTOOLBOX_INCLUDE_DIRS})
	target_link_libraries(ortp_tester ${ORTP_LIBS_FOR_TESTER} bctoolbox bctoolbox-tester)
	string(REPLACE ";" " " LINK_FLAGS_STR "${LINK_FLAGS}")

	if(LINK_FLAGS_STR)
		set_target_properties(ortp_tester PROPERTIES LINK_FLAGS "${LINK_FLAGS_STR}")
	endif()

	if(NOT IOS)
		install(TARGETS ortp_tester
			RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
			LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
			ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
			PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
		)
	endif()
endif()
