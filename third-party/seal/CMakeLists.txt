# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.12)

project(SEAL_DOWNLOAD VERSION 4.1.1)

include(ExternalProject)
ExternalProject_Add(EP_SEAL
    GIT_REPOSITORY       https://github.com/microsoft/SEAL.git
    GIT_TAG              v${PROJECT_VERSION}
    GIT_SHALLOW          True
    GIT_PROGRESS         True
    DOWNLOAD_DIR         ${CMAKE_CURRENT_LIST_DIR}
    SOURCE_DIR           ${CMAKE_CURRENT_LIST_DIR}/src
    BUILD_IN_SOURCE      False
    BINARY_DIR           ${CMAKE_CURRENT_LIST_DIR}/build
    CMAKE_ARGS           -DCMAKE_INSTALL_PREFIX=${3P_INSTALL_DIR} -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    TEST_COMMAND         ""
)
