# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.12)

project(SEAL_DOWNLOAD VERSION 3.6.1)

if (EXISTS ${CMAKE_CURRENT_LIST_DIR}/src)
	set(DOWNLOAD_URL)
	message(STATUS "Found source code for Microsoft SEAL in ${CMAKE_CURRENT_LIST_DIR}.")
else()
	message(STATUS "No source code found for Microsoft SEAL; downloading in ${CMAKE_CURRENT_LIST_DIR}.")
	set(DOWNLOAD_URL https://github.com/microsoft/SEAL/archive/v${PROJECT_VERSION}.zip)
endif()

include(ExternalProject)
ExternalProject_Add(EP_SEAL
    URL                  ${DOWNLOAD_URL}
    DOWNLOAD_DIR         ${CMAKE_CURRENT_LIST_DIR}
    SOURCE_DIR           ${CMAKE_CURRENT_LIST_DIR}/src
    BUILD_IN_SOURCE      False
    BINARY_DIR           ${CMAKE_CURRENT_LIST_DIR}/build
    CMAKE_ARGS           -DCMAKE_INSTALL_PREFIX=${3P_INSTALL_DIR} -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    TEST_COMMAND         ""
)
