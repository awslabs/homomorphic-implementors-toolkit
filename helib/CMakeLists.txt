# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.10)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ../lib/${CMAKE_BUILD_TYPE})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ../lib/${CMAKE_BUILD_TYPE})
set(HELIB_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/helib)

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

add_library(helib STATIC "")
target_sources(helib
  PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/CKKSInstance.cpp
    ${CMAKE_CURRENT_LIST_DIR}/common.cpp
    ${CMAKE_CURRENT_LIST_DIR}/matrix.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ciphertext.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ckksparams.pb.cc
)
set_common_flags(helib)

add_subdirectory(api)

# disable all warnings for auto-generated files
set_source_files_properties(
  ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ciphertext.pb.h
  ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ciphertext.pb.cc
  ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ckksparams.pb.h
  ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ckksparams.pb.cc
  PROPERTIES
  COMPILE_FLAGS "-w"
)

target_include_directories(helib PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/helib>
    $<INSTALL_INTERFACE:${HELIB_INCLUDES_INSTALL_DIR}>
)

target_include_directories(helib PUBLIC ${CMAKE_SOURCE_DIR}/external ${CMAKE_CURRENT_BINARY_DIR}/..)

# Link Microsoft SEAL and PPLR
target_link_libraries(helib seal stdc++fs ${Boost_LIBRARIES} ${PROTOBUF_LIBRARY})

install(
  FILES
    ${CMAKE_CURRENT_LIST_DIR}/CKKSInstance.h
    ${CMAKE_CURRENT_LIST_DIR}/common.h
    ${CMAKE_CURRENT_LIST_DIR}/matrix.h
    ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ckksparams.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/../protobuf/ciphertext.pb.h
  DESTINATION
    ${HELIB_INCLUDES_INSTALL_DIR}
)

# Associate helib to export HelibTargets
install(TARGETS helib EXPORT HelibTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
