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

if (NOT IOS)
	set(EXECUTABLES rtpsend rtprecv mrtpsend mrtprecv test_timer tevrtpsend tevrtprecv rtpsend_stupid)
	foreach(executable ${EXECUTABLES})
		bc_apply_compile_flags(${executable}.c STRICT_OPTIONS_CPP STRICT_OPTIONS_C)
		add_executable(${executable} ${executable}.c)
		target_link_libraries(${executable} ortp ${BCToolbox_TARGET})
	endforeach()

	install(TARGETS ${EXECUTABLES}
		RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
		PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
endif()
