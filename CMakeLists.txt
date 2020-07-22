# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.12)

project(homomorphic-implementors-toolkit VERSION 0.0.1 LANGUAGES CXX)

# Define global variables.
# Build in Release mode by default; otherwise use selected option
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif ()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

# Include customized cmake functions.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/set-common-flags.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/download-external-project.cmake)

# Find third party from CMake modules.
set(HIT_THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party)
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)
find_package(BoostLib REQUIRED)
find_package(ProtobufLib REQUIRED)
find_package(SealLib REQUIRED)

# Build HIT source code.
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/helib)

# Build HIT test code if enabled.
option(BUILD_TESTING "Build the unit tests." ON)
if (BUILD_TESTING)
    enable_testing()
    # TODO: uncomment below when test code is imported. 
    # add_subdirectory(tests)
endif ()
