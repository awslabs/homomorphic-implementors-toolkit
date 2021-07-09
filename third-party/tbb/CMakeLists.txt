# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.12)

project(TBB_DOWNLOAD VERSION 2020.3)

# suppress a CMake warning about an unused variable
set(SUPPRESS_VAR_WARNING ${3P_INSTALL_DIR})

include(ExternalProject)
ExternalProject_Add(EP_TBB
    GIT_REPOSITORY       https://github.com/oneapi-src/oneTBB.git
    GIT_TAG              v${PROJECT_VERSION}
    GIT_SHALLOW          True
    GIT_PROGRESS         True
    GIT_CONFIG           advice.detachedHead=false
    DOWNLOAD_DIR         ${CMAKE_CURRENT_LIST_DIR}
    SOURCE_DIR           ${CMAKE_CURRENT_LIST_DIR}/src
    BUILD_IN_SOURCE      False
    BINARY_DIR           ${CMAKE_CURRENT_LIST_DIR}/build
    CONFIGURE_COMMAND    ""
    BUILD_COMMAND        ""
    INSTALL_COMMAND      ""
    TEST_COMMAND         ""
)
