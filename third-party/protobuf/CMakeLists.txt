# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.12)

message(STATUS "Downloading Protobuf in ${CMAKE_CURRENT_LIST_DIR}.")

project(PROTOBUF_DOWNLOAD VERSION 3.12.3)

# https://github.com/protocolbuffers/protobuf/tree/master/src
include(ExternalProject)
set(PROTOBUF_URL_SUFFIX "v${PROJECT_VERSION}/protobuf-cpp-${PROJECT_VERSION}.zip")
ExternalProject_Add(EP_PROTOBUF
    URL                  https://github.com/google/protobuf/releases/download/${PROTOBUF_URL_SUFFIX}
    DOWNLOAD_DIR         ${CMAKE_CURRENT_LIST_DIR}
    SOURCE_DIR           ${CMAKE_CURRENT_LIST_DIR}/src
    SOURCE_SUBDIR        cmake
    CMAKE_ARGS           -DCMAKE_INSTALL_PREFIX=${3P_INSTALL_DIR}
    TEST_COMMAND         ""
)
