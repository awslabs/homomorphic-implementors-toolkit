# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.16)

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

#########
# Paths #
#########

set(HIT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(HIT_TESTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tests)
set(HIT_THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party)

# Required files and directories
include(GNUInstallDirs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib/${CMAKE_BUILD_TYPE})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib/${CMAKE_BUILD_TYPE})
set(CMAKE_LIBRARY_RUNTIME_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)
set(HIT_TARGETS_FILENAME ${CMAKE_CURRENT_SOURCE_DIR}/cmake/HITTargets.cmake)
# set(HIT_CONFIG_IN_FILENAME ${HIT_SOURCE_DIR}/cmake/HITConfig.cmake.in)
# set(HIT_CONFIG_FILENAME ${HIT_SOURCE_DIR}/cmake/HITConfig.cmake)
# set(HIT_CONFIG_VERSION_FILENAME ${HIT_SOURCE_DIR}/cmake/HITConfigVersion.cmake)
set(HIT_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/HIT)
set(HIT_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/HIT)
set(HIT_INCLUDES_BUILD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

########################
# Custom Cmake Scripts #
########################

# Include custom cmake module path
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)
message(STATUS "CMAKE_MODULE_PATH: ${CMAKE_MODULE_PATH}")
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

#####################
# Compile Protobufs #
#####################

# https://crascit.com/2017/04/18/generated-sources-in-cmake-builds/

set(HIT_PROTOBUF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/protobuf)
set(HIT_PROTOBUF_DST ${CMAKE_CURRENT_BINARY_DIR}/protobuf)

add_custom_command(
  OUTPUT
    ${HIT_PROTOBUF_DST}/ciphertext.pb.h
    ${HIT_PROTOBUF_DST}/ciphertext.pb.cc
    ${HIT_PROTOBUF_DST}/ckksparams.pb.h
    ${HIT_PROTOBUF_DST}/ckksparams.pb.cc
  COMMAND protoc --cpp_out=${HIT_PROTOBUF_DST} -I${HIT_PROTOBUF_SRC} ${HIT_PROTOBUF_SRC}/ciphertext.proto
  COMMAND protoc --cpp_out=${HIT_PROTOBUF_DST} -I${HIT_PROTOBUF_SRC} ${HIT_PROTOBUF_SRC}/ckksparams.proto
  DEPENDS
    ${HIT_PROTOBUF_SRC}/ciphertext.proto
    ${HIT_PROTOBUF_SRC}/ckksparams.proto
)

# https://stackoverflow.com/a/49591908/925978
# avoid running clang-tidy on generated files
add_library(hit_proto
  OBJECT
    ${HIT_PROTOBUF_DST}/ciphertext.pb.cc
    ${HIT_PROTOBUF_DST}/ckksparams.pb.cc)

install(
  FILES
    ${HIT_PROTOBUF_DST}/ckksparams.pb.h
    ${HIT_PROTOBUF_DST}/ciphertext.pb.h
  DESTINATION
    ${HIT_INCLUDES_INSTALL_DIR}
)

# disable all compiler warnings for auto-generated files
set_source_files_properties(
  ${HIT_PROTOBUF_DST}/ciphertext.pb.h
  ${HIT_PROTOBUF_DST}/ciphertext.pb.cc
  ${HIT_PROTOBUF_DST}/ckksparams.pb.h
  ${HIT_PROTOBUF_DST}/ckksparams.pb.cc
  PROPERTIES
    COMPILE_FLAGS "-w"
)

# disable all clang-tidy warnings for auto-generated files
set_target_properties(hit_proto
  PROPERTIES
    CXX_CLANG_TIDY "")

###############
# HIT Library #
###############

# Create an object library to compile sources only once
add_library(hit_obj OBJECT)

# Add source files to library and header files to install
add_subdirectory(src)

# Set C++ language version and include directories for the object library
target_compile_features(hit_obj PUBLIC cxx_std_17)
target_include_directories(hit_obj PUBLIC
        ${CMAKE_CURRENT_BINARY_DIR} # to allow e.g., #include "protobuf/foo.ph.h"
        $<BUILD_INTERFACE:${HIT_INCLUDES_BUILD_DIR}>
        $<INSTALL_INTERFACE:${HIT_INCLUDES_INSTALL_DIR}>)
target_link_libraries(hit_obj PRIVATE seal hit_proto)
set_common_flags(hit_obj)

# Always build the static library
message(STATUS "CMAKE_CURRENT_BINARY_DIR: ${CMAKE_CURRENT_BINARY_DIR}")
add_library(hit STATIC $<TARGET_OBJECTS:hit_obj> $<TARGET_OBJECTS:hit_proto>)
target_compile_features(hit PUBLIC cxx_std_17)
target_include_directories(hit PUBLIC
        ${CMAKE_CURRENT_BINARY_DIR} # to allow e.g., #include "protobuf/foo.ph.h"
        $<BUILD_INTERFACE:${HIT_INCLUDES_BUILD_DIR}>
        $<INSTALL_INTERFACE:${HIT_INCLUDES_INSTALL_DIR}>)
set_common_flags(hit)

# Link dependencies
target_link_libraries(hit seal stdc++fs ${Boost_LIBRARIES} ${Protobuf_LIBRARIES})

install(TARGETS hit EXPORT HITTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

#########
# Tests #
#########

# Build HIT test code if enabled.
option(BUILD_TESTING "Build the unit tests." ON)
if (BUILD_TESTING)
    enable_testing()
    add_subdirectory(${HIT_TESTS_DIR})
endif ()
