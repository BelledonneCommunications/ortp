############################################################################
# CMakeLists.txt
# Copyright (C) 2017  Belledonne Communications, Grenoble France
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
ENDIF()

set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/../COPYING")

set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})

set(CPACK_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME}-${PROJECT_VERSION})

set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES
"${CMAKE_BINARY_DIR}"
"^${PROJECT_SOURCE_DIR}/.git*"
)
find_program (WC wc)

if (WC)
        set(GIT_MINIMUN_VERSION 1.7.1) #might be even lower
else()
        set(GIT_MINIMUN_VERSION 1.7.10) # --count option of git rev-list is available only since (more or less) git 1.7.10)
endif()

find_package(Git ${GIT_MINIMUN_VERSION})
string(COMPARE GREATER "${GIT_VERSION_STRING}" "1.7.10" GIT_REV_LIST_HAS_COUNT)

if (GIT_REV_LIST_HAS_COUNT)
        set(GIT_REV_LIST_COMMAND "${GIT_EXECUTABLE}" "rev-list" "--count" "${PROJECT_VERSION}..HEAD")
        set(WC_COMMAND  "more") #nop
else()
        set(GIT_REV_LIST_COMMAND "${GIT_EXECUTABLE}" "rev-list" "${PROJECT_VERSION}..HEAD")
        set(WC_COMMAND "${WC}"  "-l")
endif()

if(GIT_EXECUTABLE)
        execute_process(
                COMMAND ${GIT_REV_LIST_COMMAND}
                COMMAND ${WC_COMMAND}
                OUTPUT_VARIABLE PROJECT_VERSION_BUILD
		OUTPUT_STRIP_TRAILING_WHITESPACE
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        )
        # if BUILD VERSION is available, append it to package filename
if (PROJECT_VERSION_BUILD)
        set (CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_FILE_NAME}-${PROJECT_VERSION_BUILD}")
endif()
	message("Package file name is ${CPACK_PACKAGE_FILE_NAME}" )
endif()
set(CPACK_SOURCE_PACKAGE_FILE_NAME ${CPACK_PACKAGE_FILE_NAME})
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/rpm/ortp.spec.cmake ${CMAKE_CURRENT_SOURCE_DIR}/../ortp.spec)

include(CPack)

