# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set(TBB_CMAKE_FILE ${3P_INSTALL_DIR}/TBBGet.cmake)

# Download a single CMake file from TBB 2020
# This file is used to download the correct binary package for this system
file(
	DOWNLOAD
		https://raw.githubusercontent.com/oneapi-src/oneTBB/tbb_2020/cmake/TBBGet.cmake
		${TBB_CMAKE_FILE}
)
# Load the TBB CMake file
include(${TBB_CMAKE_FILE})
message(STATUS "Installing TBB...")
# Invoke it to automatically download the correct binary package for this system
# Unpack the downloaded content to ${3P_INSTALL_DIR}
# See https://sudonull.com/post/68014-Integration-of-Intel-Threading-Building-Blocks-into-your-CMake-project-Intel-Blog
# for details on the tbb_get arguments.
tbb_get(TBB_ROOT tbb_root CONFIG_DIR TBB_DIR SAVE_TO ${3P_INSTALL_DIR})
# Runtime linker error with GCC-9 in CI if I _don't_ specify the TBB components
# The problem seems to be that the default is to use more components, but the linker
# can't find the shared libraries of the (unused) components.
# See https://github.com/oneapi-src/oneTBB/blob/tbb_2020/cmake/README.rst#user-content-tbbconfig
find_package(TBB REQUIRED COMPONENTS tbb)
message(STATUS "TBB_VERSION : ${TBB_VERSION}")
