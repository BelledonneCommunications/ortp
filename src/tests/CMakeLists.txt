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

set(RTPSEND_SOURCES rtpsend.c)
apply_compile_flags(RTPSEND_SOURCES "CPP" "C")
add_executable(rtpsend ${RTPSEND_SOURCES})
target_link_libraries(rtpsend ortp)

set(RTPRECV_SOURCES rtprecv.c)
apply_compile_flags(RTPRECV_SOURCES "CPP" "C")
add_executable(rtprecv ${RTPRECV_SOURCES})
target_link_libraries(rtprecv ortp)

set(MRTPSEND_SOURCES mrtpsend.c)
apply_compile_flags(MRTPSEND_SOURCES "CPP" "C")
add_executable(mrtpsend ${MRTPSEND_SOURCES})
target_link_libraries(mrtpsend ortp)

set(MRTPRECV_SOURCES mrtprecv.c)
apply_compile_flags(MRTPRECV_SOURCES "CPP" "C")
add_executable(mrtprecv ${RTPRECV_SOURCES})
target_link_libraries(mrtprecv ortp)

set(TEST_TIMER_SOURCES test_timer.c)
apply_compile_flags(TEST_TIMER_SOURCES "CPP" "C")
add_executable(test_timer ${TEST_TIMER_SOURCES})
target_link_libraries(test_timer ortp)

set(TEVRTPSEND_SOURCES tevrtpsend.c)
apply_compile_flags(TEVRTPSEND_SOURCES "CPP" "C")
add_executable(tevrtpsend ${TEVRTPSEND_SOURCES})
target_link_libraries(tevrtpsend ortp)

set(TEVRTPRECV_SOURCES tevrtprecv.c)
apply_compile_flags(TEVRTPRECV_SOURCES "CPP" "C")
add_executable(tevrtprecv ${TEVRTPRECV_SOURCES})
target_link_libraries(tevrtprecv ortp)

set(RTPSEND_STUPID_SOURCES rtpsend_stupid.c)
apply_compile_flags(RTPSEND_STUPID_SOURCES "CPP" "C")
add_executable(rtpsend_stupid ${RTPSEND_STUPID_SOURCES})
target_link_libraries(rtpsend_stupid ortp)

install(TARGETS rtpsend rtprecv mrtpsend mrtprecv test_timer tevrtpsend tevrtprecv rtpsend_stupid
	RUNTIME DESTINATION bin
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)
