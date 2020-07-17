# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.12)
include(ExternalProject)

# include scripts used in this file
include(${CMAKE_CURRENT_SOURCE_DIR}/scripts/cmake/apply-git-patch.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/scripts/cmake/update-git-submodules.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/scripts/cmake/set-common-flags.cmake)

project(HELR VERSION 0.0.1 LANGUAGES CXX)

include(FindProtobuf)
include_directories(${PROTOBUF_INCLUDE_DIR})

include(FindBoost)
include_directories(${Boost_INCLUDE_DIRS})

# Build in Release mode by default; otherwise use selected option
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE
        STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
        STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/bin/${CMAKE_BUILD_TYPE})

if(DEFINED ENV{NO_CHECKOUT_SEAL})
  message(STATUS "Skipping submodule updates")
else()
  # check out all git submodules at DETACHED HEAD
  update_submodules()

  # double check that submodule updates were successful
  if(NOT EXISTS "${PROJECT_SOURCE_DIR}/external/SEAL/CMakeLists.txt")
      message(FATAL_ERROR "The SEAL submodule was not downloaded! GIT_SUBMODULE was turned off or failed. Please update submodules and try again.")
  endif()

  if(NOT EXISTS "${PROJECT_SOURCE_DIR}/external/googletest/CMakeLists.txt")
      message(FATAL_ERROR "The GoogleTest submodule was not downloaded! GIT_SUBMODULE was turned off or failed. Please update submodules and try again.")
  endif()

  # Set the version of SEAL that we want to depend on
  set(SEAL_VERSION "3.5.1")

  # Checkout the correct branch of SEAL
  execute_process(COMMAND ${GIT_EXECUTABLE} checkout ${SEAL_VERSION}
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/external/SEAL
                  RESULT_VARIABLE GIT_SUBMOD_RESULT
                  OUTPUT_QUIET)
  if(NOT GIT_SUBMOD_RESULT EQUAL "0")
      message(FATAL_ERROR "Could not checkout SEAL branch ${SEAL_VERSION}")
  endif()
endif()

message(STATUS "Searching for dependencies...")
find_package(Protobuf REQUIRED)
find_package(Boost 1.65 REQUIRED COMPONENTS program_options)

# Import Microsoft SEAL prior to compiling helib
message(STATUS "Compiling SEAL...")
add_subdirectory(external/SEAL)

message(STATUS "Compiling HELib...")
add_subdirectory(helib)

enable_testing()

message(STATUS "Compiling GoogleTest...")
add_subdirectory(external/googletest)

if(NOT HELR_ROOT_DIR)
  set(HELR_ROOT_DIR "${PROJECT_SOURCE_DIR}/")
endif()

add_executable(evaldemo examples/evaluator_demo.cpp)
set_common_flags(evaldemo)

target_link_libraries(evaldemo helib)

add_custom_target(
  run_evaldemo
  COMMAND bin/${CMAKE_BUILD_TYPE}/evaldemo
  WORKING_DIRECTORY ${HELR_ROOT_DIR}
  DEPENDS evaldemo
  USES_TERMINAL)
