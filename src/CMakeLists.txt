# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.10)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ../lib/${CMAKE_BUILD_TYPE})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ../lib/${CMAKE_BUILD_TYPE})
set(HIT_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/src)

# https://crascit.com/2017/04/18/generated-sources-in-cmake-builds/
add_custom_command(
  OUTPUT
    ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ciphertext.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ciphertext.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ckksparams.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ckksparams.pb.cc
  COMMAND protoc --cpp_out=${CMAKE_CURRENT_BINARY_DIR}/../protobuf -I${CMAKE_SOURCE_DIR}/protobuf ${CMAKE_SOURCE_DIR}/protobuf/ciphertext.proto
  COMMAND protoc --cpp_out=${CMAKE_CURRENT_BINARY_DIR}/../protobuf -I${CMAKE_SOURCE_DIR}/protobuf ${CMAKE_SOURCE_DIR}/protobuf/ckksparams.proto
  DEPENDS
    ${CMAKE_SOURCE_DIR}/protobuf/ciphertext.proto
    ${CMAKE_SOURCE_DIR}/protobuf/ckksparams.proto
)

# https://stackoverflow.com/a/49591908/925978
# avoid running clang-tidy on generated files
add_library(hit_proto
  OBJECT
    ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ciphertext.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ciphertext.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ckksparams.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ckksparams.pb.cc)

# disable all warnings for auto-generated files
# disable clang-tidy for auto-generated files
set_source_files_properties(
  ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ciphertext.pb.h
  ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ciphertext.pb.cc
  ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ckksparams.pb.h
  ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ckksparams.pb.cc
  PROPERTIES
    COMPILE_FLAGS "-w"
)

set_target_properties(hit_proto
  PROPERTIES
    CXX_CLANG_TIDY "")

add_library(hit STATIC "")
target_sources(hit
  PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/CKKSInstance.cpp
    ${CMAKE_CURRENT_LIST_DIR}/common.cpp
    ${CMAKE_CURRENT_LIST_DIR}/matrix.cpp
    $<TARGET_OBJECTS:hit_proto>
)
set_common_flags(hit)

add_subdirectory(api)

target_include_directories(hit PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:${HIT_INCLUDES_INSTALL_DIR}>
)

target_include_directories(hit PUBLIC ${CMAKE_SOURCE_DIR}/external ${CMAKE_CURRENT_BINARY_DIR}/..)

# Link Microsoft SEAL and PPLR
target_link_libraries(hit seal stdc++fs ${Boost_LIBRARIES} ${Protobuf_LIBRARIES})

install(
  FILES
    ${CMAKE_CURRENT_LIST_DIR}/CKKSInstance.h
    ${CMAKE_CURRENT_LIST_DIR}/common.h
    ${CMAKE_CURRENT_LIST_DIR}/matrix.h
    ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ckksparams.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ciphertext.pb.h
  DESTINATION
    ${HIT_INCLUDES_INSTALL_DIR}
)

# Associate hit to export HitTargets
install(TARGETS hit EXPORT HitTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
