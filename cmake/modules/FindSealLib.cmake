# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Download and install dependency - Microsoft SEAL.
message(STATUS "3P_INSTALL_DIR ${3P_INSTALL_DIR}")
set(SEAL_DIR ${3P_INSTALL_DIR})
#set(SEAL_DIR ${CMAKE_SOURCE_DIR}/external/hit/build/Release/third-party/lib/cmake/SEAL-3.6/)
set(SEAL_DIR ${CMAKE_SOURCE_DIR}/build/Release/external/hit/third-party/lib/cmake/SEAL-3.6/)
find_package(SEAL 3.6 QUIET)

if (NOT SEAL_FOUND)
	download_external_project("seal")
	find_package(SEAL 3.6 REQUIRED)

	if (NOT SEAL_FOUND)
		message(FATAL "SEAL NOT FOUND")
	endif()
endif()

# when building HELR: 3P_INSTALL_DIR /home/ubuntu/HELR/build/Release/external/hit/third-party
# when building HIT:  3P_INSTALL_DIR /home/ubuntu/HELR/external/hit/build/Release/third-party
