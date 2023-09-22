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

set(HEADER_FILES
    event.h
	logging.h
	nack.h
	ortp.h
	payloadtype.h
	port.h
	rtcp.h
	rtp.h
	rtpprofile.h
	rtpsession.h
	rtpsignaltable.h
	sessionset.h
	str_utils.h
	telephonyevents.h
	utils.h
)

set(ORTP_HEADER_FILES )
foreach(HEADER_FILE ${HEADER_FILES})
	list(APPEND ORTP_HEADER_FILES "${CMAKE_CURRENT_LIST_DIR}/ortp/${HEADER_FILE}")
endforeach()
set(ORTP_HEADER_FILES ${ORTP_HEADER_FILES} PARENT_SCOPE)

install(FILES ${ORTP_HEADER_FILES}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ortp
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
