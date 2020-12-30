# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.12)

project(GTEST_DOWNLOAD VERSION 1.10.0)

if (EXISTS ${CMAKE_CURRENT_LIST_DIR}/src)
    set(DOWNLOAD_URL)
    message(STATUS "Found source code for GoogleTest in ${CMAKE_CURRENT_LIST_DIR}.")
else()
    message(STATUS "No source code found for GoogleTest; downloading in ${CMAKE_CURRENT_LIST_DIR}.")
    set(DOWNLOAD_URL https://github.com/google/googletest.git)
endif()

include(ExternalProject)
ExternalProject_Add(EP_GTEST
    TMP_DIR              ${CMAKE_CURRENT_LIST_DIR}/tmp
    STAMP_DIR            ${CMAKE_CURRENT_LIST_DIR}/stamp
    DOWNLOAD_DIR         ""
    SOURCE_DIR           ${CMAKE_CURRENT_LIST_DIR}/src
    BUILD_IN_SOURCE      False
    BINARY_DIR           ${CMAKE_CURRENT_LIST_DIR}/build
    GIT_REPOSITORY       ${DOWNLOAD_URL}
    GIT_TAG              release-${PROJECT_VERSION}
    GIT_CONFIG           advice.detachedHead=false
    CMAKE_ARGS           -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX=${3P_INSTALL_DIR}
    TEST_COMMAND         ""
)
