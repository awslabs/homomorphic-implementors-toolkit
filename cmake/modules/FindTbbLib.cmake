# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

message(STATUS "Searching TBB lib.")
find_package(TBB QUIET)
if (TBB_FOUND)
    message(STATUS "TBB is found. Skip downloading source code.")
    set(TBB_IMPORTED_TARGETS tbb)
else ()
    # https://github.com/oneapi-src/oneTBB/tree/tbb_2020/cmake#tutorials-tbb-integration-using-cmake
    message(STATUS "Downloading and installing TBB since it is not found.")
    download_external_project("tbb")
    set(TBB_CONTENT_DIR ${HIT_THIRD_PARTY_DIR}/tbb/src)
    set(TBB_BUILD_DIR ${HIT_THIRD_PARTY_DIR}/tbb/build)
    include(${TBB_CONTENT_DIR}/cmake/TBBBuild.cmake)
    tbb_build(TBB_ROOT ${TBB_CONTENT_DIR} CONFIG_DIR TBB_BUILD_VAR MAKE_ARGS tbb_build_dir=${TBB_BUILD_DIR})
    message(STATUS "TBB_BUILD_VAR ${TBB_BUILD_VAR}.")
    find_package(TBB REQUIRED tbb HINTS ${TBB_BUILD_VAR})
endif ()
message(STATUS "TBB_VERSION : ${TBB_VERSION}")
