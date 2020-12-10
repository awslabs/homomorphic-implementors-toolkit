# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.12)

message(STATUS "Downloading Intel TBB in ${CMAKE_CURRENT_LIST_DIR}.")

project(TBB_DOWNLOAD VERSION 2021.1.1)

include(ExternalProject)
ExternalProject_Add(EP_TBB
	URL                  https://github.com/oneapi-src/oneTBB/releases/download/v2020.3/tbb-2020.3-lin.tgz
    DOWNLOAD_DIR         ${CMAKE_CURRENT_LIST_DIR}
    SOURCE_DIR           ${CMAKE_CURRENT_LIST_DIR}/src
    CONFIGURE_COMMAND    ""
    BUILD_COMMAND        ""
    INSTALL_COMMAND      ""
    TEST_COMMAND         ""
)
