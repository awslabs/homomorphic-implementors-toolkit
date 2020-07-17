# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.12)

project(GTEST_DOWNLOAD VERSION 1.10.0)

message(STATUS "Downloading GoogleTest in ${CMAKE_CURRENT_LIST_DIR}.")

include(ExternalProject)
ExternalProject_Add(EP_GTEST
    TMP_DIR              ${CMAKE_CURRENT_LIST_DIR}/tmp
    STAMP_DIR            ${CMAKE_CURRENT_LIST_DIR}/stamp
    DOWNLOAD_DIR         ""
    SOURCE_DIR           ${CMAKE_CURRENT_LIST_DIR}/src
    BINARY_DIR           ${CMAKE_CURRENT_LIST_DIR}/build
    GIT_REPOSITORY       https://github.com/google/googletest.git
    GIT_TAG              release-${PROJECT_VERSION}
    GIT_CONFIG           advice.detachedHead=false
    CMAKE_ARGS           -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    CONFIGURE_COMMAND    ""
    BUILD_COMMAND        ""
    INSTALL_COMMAND      ""
    TEST_COMMAND         ""
)
