# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# https://github.com/oneapi-src/oneTBB/tree/tbb_2020/cmake/README.rst
download_external_project("tbb")
set(TBB_SOURCE_DIR ${HIT_THIRD_PARTY_DIR}/tbb/src)
include(${TBB_SOURCE_DIR}/cmake/TBBGet.cmake)
message(STATUS "Installing TBB...")
tbb_get(TBB_ROOT ${TBB_SOURCE_DIR} CONFIG_DIR TBB_DIR)
find_package(TBB REQUIRED tbb)
message(STATUS "TBB_VERSION : ${TBB_VERSION}")
