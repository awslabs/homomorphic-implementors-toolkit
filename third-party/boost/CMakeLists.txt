# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.12)

project(BOOST_DOWNLOAD VERSION 1.73.0)

message(STATUS "Downloading Boost in ${CMAKE_CURRENT_LIST_DIR}/src.")

string(REPLACE "." "_" BOOST_SUFFIX ${PROJECT_VERSION})

include(ExternalProject)
# Boost archived in GitHub does not include submodule libraries, which are needed by boost build.
# https://github.com/boostorg/boost/archive/boost-1.73.0.zip
ExternalProject_Add(EP_BOOST
    URL                  https://downloads.sourceforge.net/project/boost/boost/${PROJECT_VERSION}/boost_${BOOST_SUFFIX}.zip
    DOWNLOAD_DIR         ${CMAKE_CURRENT_LIST_DIR}/src
    SOURCE_DIR           ${CMAKE_CURRENT_LIST_DIR}/src
    CMAKE_ARGS           ""
    CONFIGURE_COMMAND    ""
    BUILD_COMMAND        ""
    INSTALL_COMMAND      ""
    TEST_COMMAND         ""
)
