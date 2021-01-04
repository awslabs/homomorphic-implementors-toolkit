# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.12)

project(TBB_DOWNLOAD VERSION 2021.1.1)

# suppress a CMake warning about an unused variable
set(SUPPRESS_VAR_WARNING ${3P_INSTALL_DIR})

if (EXISTS ${CMAKE_CURRENT_LIST_DIR}/src)
	set(DOWNLOAD_URL)
	message(STATUS "Found source code for Intel TBB in ${CMAKE_CURRENT_LIST_DIR}.")
else()
	message(STATUS "No source code found for Intel TBB; downloading in ${CMAKE_CURRENT_LIST_DIR}.")
	set(DOWNLOAD_URL https://github.com/oneapi-src/oneTBB/releases/download/v2020.3/tbb-2020.3-lin.tgz)
endif()

include(ExternalProject)
ExternalProject_Add(EP_TBB
    URL                  ${DOWNLOAD_URL}
    DOWNLOAD_DIR         ${CMAKE_CURRENT_LIST_DIR}
    SOURCE_DIR           ${CMAKE_CURRENT_LIST_DIR}/src
    BUILD_IN_SOURCE      False
    BINARY_DIR           ${CMAKE_CURRENT_LIST_DIR}/build
    CONFIGURE_COMMAND    ""
    BUILD_COMMAND        ""
    INSTALL_COMMAND      ""
    TEST_COMMAND         ""
)
