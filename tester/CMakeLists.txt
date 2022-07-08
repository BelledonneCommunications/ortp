set(HEADER_FILES_C ortp_tester.h)
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
	target_link_libraries(ortp_tester_static bctoolbox bctoolbox-tester ortp)

	# tester-runtime useful here ?
	install(FILES "${CMAKE_CURRENT_BINARY_DIR}/BelledonneCommunications.ortp.Tester.winmd" DESTINATION lib)

	if(CMAKE_BUILD_TYPE STREQUAL "Debug")
		install(FILES ${CMAKE_CURRENT_BINARY_DIR}/Debug/BelledonneCommunications.ortp.Tester.pdb
			DESTINATION ${CMAKE_INSTALL_LIBDIR}
			PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
		)
	endif()
else()
	if(IOS)
		set_source_files_properties(${IOS_RESOURCES_FILES} PROPERTIES MACOSX_PACKAGE_LOCATION Resources)
		add_executable(ortp_tester MACOSX_BUNDLE ${IOS_RESOURCES_FILES} ${HEADER_FILES_C} ${SOURCE_FILES_C} ${SOURCE_FILES_CXX} ${SOURCE_FILES_OBJC})
		set_target_properties(ortp_tester PROPERTIES
			MACOSX_FRAMEWORK_INFO_PLIST Info.plist.in
			MACOSX_BUNDLE_BUNDLE_NAME org.linphone.ortp.ortp-tester
			MACOSX_BUNDLE_BUNDLE_VERSION 1.0
			MACOSX_BUNDLE_SHORT_VERSION_STRING "1.0")

	else()
		add_executable(ortp_tester ${SOURCE_FILES_C} ${HEADER_FILES_C} ${SOURCE_FILES_CXX} ${SOURCE_FILES_OBJC})
	endif()

	set_target_properties(ortp_tester PROPERTIES LINKER_LANGUAGE C)
	target_include_directories(ortp_tester PUBLIC ${BCTOOLBOX_INCLUDE_DIRS})
	target_link_libraries(ortp_tester bctoolbox bctoolbox-tester ortp)
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
