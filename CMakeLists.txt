# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.12)

project(homomorphic-implementors-toolkit VERSION 0.0.1 LANGUAGES CXX)

#################
# CMAKE OPTIONS #
#################

# Define global variables.
# Build in Release mode by default; otherwise use selected option
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif ()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

#########
# Paths #
#########

set(HIT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/hit)
set(HIT_TESTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tests)
set(HIT_THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party)

# Required files and directories
include(GNUInstallDirs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib/${CMAKE_BUILD_TYPE})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib/${CMAKE_BUILD_TYPE})
set(CMAKE_LIBRARY_RUNTIME_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE})
set(HIT_TARGETS_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/HITTargets.cmake)
set(HIT_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/HIT)
set(HIT_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDE_DIR}/hit)
set(HIT_INCLUDES_BUILD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE})
set(HIT_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/hit)

########################
# Custom Cmake Scripts #
########################

# Include custom cmake module path
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)
# And custom modules
include(set-common-flags)
include(download-external-project)
include(enable-hit-code-format)
include(enable-clang-tidy)

############################
# Third party dependencies #
############################

find_package(BoostLib REQUIRED)
find_package(SealLib REQUIRED)
find_package(ProtobufLib REQUIRED)
find_package(GlogLib REQUIRED)
find_package(TbbLib REQUIRED)

#####################
# Compile Protobufs #
#####################

set(HIT_PROTOBUF_DST ${CMAKE_CURRENT_BINARY_DIR}/protobuf/hit/protobuf)
add_subdirectory(protobuf)

######################
# Enable CMake Tools #
######################

# Enable tooling.
# clang-tidy and clang-format are used to provide some warnings for developer reference during development.
option(HIT_RUN_CLANG_FORMAT "Run clang-format and apply changes to source code." OFF)
if (CMake_RUN_HIT_CODE_FORMAT)
    enable_hit_code_format()
endif ()
option(HIT_RUN_CLANG_TIDY "Run clang-tidy with the compiler." OFF)
if (CMake_RUN_CLANG_TIDY)
    enable_clang_tidy()
endif ()

###############
# HIT Library #
###############

# Add the main source tree object library
add_subdirectory(src)

# Always build the static library
add_library(aws-hit STATIC $<TARGET_OBJECTS:aws_hit_obj> $<TARGET_OBJECTS:aws_hit_proto>)
target_compile_features(aws-hit PUBLIC cxx_std_17)
target_include_directories(aws-hit PUBLIC
        ${CMAKE_CURRENT_BINARY_DIR}/protobuf # to allow e.g., #include "protobuf/foo.ph.h"
        ${HIT_PROTOBUF_DST} # to allow e.g., #include "foo.ph.h", which is how auto-generated protobuf files expect imports to be available
        $<BUILD_INTERFACE:${HIT_INCLUDES_BUILD_DIR}>
        $<INSTALL_INTERFACE:${HIT_INCLUDES_INSTALL_DIR}>
    PRIVATE ${HIT_SOURCE_DIR}
    )
set_common_flags(aws-hit)

# Link dependencies
target_link_libraries(aws-hit PUBLIC seal PRIVATE stdc++fs ${Boost_LIBRARIES} ${Protobuf_LIBRARIES} glog::glog ${TBB_IMPORTED_TARGETS})

install(TARGETS aws-hit EXPORT HITTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# We export HITTargets from the build tree so it can be used by other projects
# without requiring an install.
export(
    EXPORT HITTargets
    NAMESPACE hit::
    FILE ${HIT_TARGETS_FILENAME})

export(TARGETS aws-hit FILE ${HIT_TARGETS_FILENAME})

#########
# Tests #
#########

# Build HIT test code if enabled.
option(HIT_BUILD_TESTS "Build the unit tests." OFF)
if (HIT_BUILD_TESTS)
    enable_testing()
    add_subdirectory(${HIT_TESTS_DIR})
endif ()

###############
# Executables #
###############

# Build code in the `examples` directory if enabled.
option(HIT_BUILD_EXAMPLES "Build HIT example/demo code." OFF)
if (HIT_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif ()
