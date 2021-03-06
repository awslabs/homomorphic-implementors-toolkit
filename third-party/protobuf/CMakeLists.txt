# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.12)

project(PROTOBUF_DOWNLOAD VERSION 3.12.3)

if (EXISTS ${CMAKE_CURRENT_LIST_DIR}/src)
	set(DOWNLOAD_URL)
	message(STATUS "Found source code for Protobuf in ${CMAKE_CURRENT_LIST_DIR}.")
else()
	message(STATUS "No source code found for Protobuf; downloading in ${CMAKE_CURRENT_LIST_DIR}.")
	set(PROTOBUF_URL_SUFFIX "v${PROJECT_VERSION}/protobuf-cpp-${PROJECT_VERSION}.zip")
	set(DOWNLOAD_URL https://github.com/google/protobuf/releases/download/${PROTOBUF_URL_SUFFIX})
endif()

# https://github.com/protocolbuffers/protobuf/tree/master/src
include(ExternalProject)
ExternalProject_Add(EP_PROTOBUF
    URL                  ${DOWNLOAD_URL}
    DOWNLOAD_DIR         ${CMAKE_CURRENT_LIST_DIR}
    SOURCE_DIR           ${CMAKE_CURRENT_LIST_DIR}/src
    BUILD_IN_SOURCE      False
    BINARY_DIR           ${CMAKE_CURRENT_LIST_DIR}/build
    SOURCE_SUBDIR        cmake
    CMAKE_ARGS           -DCMAKE_INSTALL_PREFIX=${3P_INSTALL_DIR}
    TEST_COMMAND         ""
)
