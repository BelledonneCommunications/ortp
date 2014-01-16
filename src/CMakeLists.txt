set(SOURCE_FILES
	avprofile.c
	b64.c
	event.c
	jitterctl.c
	logging.c
	netsim.c
	ortp.c
	ortp_srtp.c
	payloadtype.c
	port.c
	posixtimer.c
	rtcp.c
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
	stun.c
	stun_udp.c
	telephonyevents.c
	utils.c
	zrtp.c
)

if(WIN32)
set(SOURCE_FILES
	${SOURCE_FILES}
	dll_entry.c
)
endif(WIN32)

add_definitions(
	-DORTP_INET6
	-DORTP_EXPORTS
)

if(WIN32)
add_definitions(
	-DWINDOWS_NATIVE
)

set(LIBS ws2_32 delayimp Winmm qwave)
endif(WIN32)

if(ORTP_ENABLE_SRTP)
	add_definitions(-DHAVE_SRTP)
	list(APPEND LIBS ${LIBSRTP})
endif(ORTP_ENABLE_SRTP)

add_library(libortp SHARED ${SOURCE_FILES})
set_target_properties(libortp PROPERTIES VERSION 0.22.1 SOVERSION 9)

target_link_libraries(libortp ${LIBS})

install(TARGETS libortp
	COMPONENT COMP_libortp
	DESTINATION ${LIB_INSTALL_DIR}
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)
if(WIN32)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/Debug/libortp.pdb
	COMPONENT COMP_libortp
	DESTINATION ${LIB_INSTALL_DIR}
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)
endif()
endif(WIN32)
