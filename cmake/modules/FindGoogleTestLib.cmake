# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

find_package(GTest 1.10.0 QUIET)
if (GTest_FOUND)
    message(STATUS "GTest is already installed.")
    find_library(gtest_LIBRARIES gtest)
else ()
    message(STATUS "GTest was not found on your system.")
    download_external_project("googletest")
    find_package(GTest REQUIRED)
    find_library(gtest_LIBRARIES gtest PATHS ${3P_INSTALL_DIR} REQUIRED)
endif ()

