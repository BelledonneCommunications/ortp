############################################################################
# CMakeLists.txt
# Copyright (C) 2017-2018  Belledonne Communications, Grenoble France
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

if (NOT CPACK_PACKAGE_NAME)
	set(CPACK_PACKAGE_NAME "ortp")
endif()

set(CPACK_SOURCE_IGNORE_FILES "./.*")

bc_generate_rpm_specfile("rpm/ortp.spec.cmake" "rpm/ortp.spec.cmake")

add_custom_target(ortp-rpm-spec
	COMMAND ${CMAKE_COMMAND}
		"-DBCTOOLBOX_CMAKE_UTILS=${BCTOOLBOX_CMAKE_UTILS}"
		"-DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}"
		"-DPROJECT_VERSION=${PROJECT_VERSION}"
		"-DCMAKE_CURRENT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
		"-DCMAKE_CURRENT_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
		-P "${CMAKE_CURRENT_SOURCE_DIR}/rpm/ConfigureSpecfile.cmake"
	BYPRODUCTS "${PROJECT_SOURCE_DIR}/ortp.spec"
)

add_custom_target(package_source
	COMMAND ${CMAKE_COMMAND}
		"-DBCTOOLBOX_CMAKE_UTILS=${BCTOOLBOX_CMAKE_UTILS}"
		"-DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}"
		"-DPROJECT_BINARY_DIR=${PROJECT_BINARY_DIR}"
		"-DPROJECT_VERSION=${PROJECT_VERSION}"
		"-DCMAKE_CURRENT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
		"-DCPACK_PACKAGE_NAME=${CPACK_PACKAGE_NAME}"
		"-DEXCLUDE_PATTERNS='${CPACK_SOURCE_IGNORE_FILES}'"
		-P "${CMAKE_CURRENT_SOURCE_DIR}/MakeArchive.cmake"
	DEPENDS ortp-rpm-spec
)
