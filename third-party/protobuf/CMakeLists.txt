# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.12)

project(PROTOBUF_DOWNLOAD VERSION 3.21.12)

# https://github.com/protocolbuffers/protobuf/tree/master/src
include(ExternalProject)
ExternalProject_Add(EP_PROTOBUF
    GIT_REPOSITORY       https://github.com/protocolbuffers/protobuf.git
    GIT_TAG              v${PROJECT_VERSION}
    GIT_SHALLOW          True
    GIT_PROGRESS         True
    GIT_CONFIG           advice.detachedHead=false
    DOWNLOAD_DIR         ${CMAKE_CURRENT_LIST_DIR}
    SOURCE_DIR           ${CMAKE_CURRENT_LIST_DIR}/src
    BUILD_IN_SOURCE      False
    BINARY_DIR           ${CMAKE_CURRENT_LIST_DIR}/build
    SOURCE_SUBDIR        cmake
    CMAKE_ARGS           -DCMAKE_INSTALL_PREFIX=${3P_INSTALL_DIR}
    TEST_COMMAND         ""
)
