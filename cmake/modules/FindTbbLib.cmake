# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

download_external_project("tbb")

# Load the TBB CMake file
include(${HIT_THIRD_PARTY_DIR}/tbb/src/tbb/cmake/TBBGet.cmake)
include(${HIT_THIRD_PARTY_DIR}/tbb/src/tbb/cmake/TBBMakeConfig.cmake)
message(STATUS "Installing TBB...")
# Invoke it to automatically download the correct binary package for this system
# Unpack the downloaded content to ${3P_INSTALL_DIR}
# See https://sudonull.com/post/68014-Integration-of-Intel-Threading-Building-Blocks-into-your-CMake-project-Intel-Blog
# for details on the tbb_get arguments.
tbb_get(TBB_ROOT tbb_root RELEASE_TAG v2020.3 CONFIG_DIR TBB_DIR SAVE_TO ${3P_INSTALL_DIR})
# Runtime linker error with GCC-9 in CI if I _don't_ specify the TBB components
# The problem seems to be that the default is to use more components, but the linker
# can't find the shared libraries of the (unused) components.
# See https://github.com/oneapi-src/oneTBB/blob/tbb_2020/cmake/README.rst#user-content-tbbconfig
find_package(TBB REQUIRED COMPONENTS tbb)
message(STATUS "TBB_VERSION : ${TBB_VERSION}")
