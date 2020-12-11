# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.12)

message(STATUS "Downloading Microsoft SEAL in ${CMAKE_CURRENT_LIST_DIR}.")

project(SEAL_DOWNLOAD VERSION 3.6.1)

include(ExternalProject)
ExternalProject_Add(EP_SEAL
    URL                  https://github.com/microsoft/SEAL/archive/v${PROJECT_VERSION}.zip
    DOWNLOAD_DIR         ${CMAKE_CURRENT_LIST_DIR}
    SOURCE_DIR           ${CMAKE_CURRENT_LIST_DIR}/src
    CMAKE_ARGS           -DCMAKE_INSTALL_PREFIX=${3P_INSTALL_DIR}
    TEST_COMMAND         ""
)
