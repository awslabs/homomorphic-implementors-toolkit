# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

download_external_project("tbb")

# Load the TBB CMake file
include(${HIT_THIRD_PARTY_DIR}/tbb/src/cmake/TBBBuild.cmake)
message(STATUS "Installing TBB...")

tbb_build(TBB_ROOT ${HIT_THIRD_PARTY_DIR}/tbb/src CONFIG_DIR TBB_DIR MAKE_ARGS)
# Runtime linker error with GCC-9 in CI if I _don't_ specify the TBB components
# The problem seems to be that the default is to use more components, but the linker
# can't find the shared libraries of the (unused) components.
# See https://github.com/oneapi-src/oneTBB/blob/tbb_2020/cmake/README.rst#user-content-tbbconfig
find_package(TBB REQUIRED COMPONENTS tbb)
message(STATUS "TBB_VERSION : ${TBB_VERSION}")
