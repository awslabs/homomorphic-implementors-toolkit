# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.12)

project(GLOG_DOWNLOAD VERSION 0.4.0)

if (EXISTS ${CMAKE_CURRENT_LIST_DIR}/src)
    set(DOWNLOAD_URL)
    message(STATUS "Found source code for GoogleGlog in ${CMAKE_CURRENT_LIST_DIR}.")
else()
    message(STATUS "No source code found for GoogleGlog; downloading in ${CMAKE_CURRENT_LIST_DIR}.")
    set(DOWNLOAD_URL https://github.com/google/glog.git)
endif()

include(ExternalProject)
ExternalProject_Add(EP_GLOG
    TMP_DIR              ${CMAKE_CURRENT_LIST_DIR}/tmp
    STAMP_DIR            ${CMAKE_CURRENT_LIST_DIR}/stamp
    DOWNLOAD_DIR         ""
    SOURCE_DIR           ${CMAKE_CURRENT_LIST_DIR}/src
    BUILD_IN_SOURCE      False
    BINARY_DIR           ${CMAKE_CURRENT_LIST_DIR}/build
    GIT_REPOSITORY       ${DOWNLOAD_URL}
    GIT_TAG              v${PROJECT_VERSION}
    GIT_CONFIG           advice.detachedHead=false
    CMAKE_ARGS           -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=${3P_INSTALL_DIR}
    TEST_COMMAND         ""
)
