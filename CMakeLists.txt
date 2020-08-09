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
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/enable-hit-code-format.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/enable-clang-tidy.cmake)

# Find third party from CMake modules.
set(HIT_THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party)
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)
set(HIT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(HIT_TESTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tests)

find_package(BoostLib REQUIRED)
find_package(ProtobufLib REQUIRED)
find_package(SealLib REQUIRED)

# Enable tooling.
# clang-tidy and clang-format are used to provide some warnings for developer reference during development.
option(CMake_RUN_HIT_CODE_FORMAT "Run clang-format in place." OFF)
if (CMake_RUN_HIT_CODE_FORMAT)
    enable_hit_code_format()
endif ()
option(CMake_RUN_CLANG_TIDY "Run clang-tidy with the compiler." OFF)
if (CMake_RUN_CLANG_TIDY)
    enable_clang_tidy()
endif ()

# Build HIT source code.
add_subdirectory(${HIT_SOURCE_DIR})

# Build HIT test code if enabled.
option(BUILD_TESTING "Build the unit tests." ON)
if (BUILD_TESTING)
    enable_testing()
    add_subdirectory(${HIT_TESTS_DIR})
endif ()
