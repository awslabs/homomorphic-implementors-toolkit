# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Use the .proto descriptions in this folder to generate parser code
# for ciphertexts and parameters.
# We generate files in the build directory and then link them into the aws_hit_proto object library.
# Disable all compiler and clang-tidy warnings on these generated files because we have no control
# over what is generated.

# The basic technique for the CMake code in this file came from
# https://crascit.com/2017/04/18/generated-sources-in-cmake-builds/

add_custom_command(
  OUTPUT
    ${HIT_PROTOBUF_DST}/ciphertext.pb.h
    ${HIT_PROTOBUF_DST}/ciphertext.pb.cc
    ${HIT_PROTOBUF_DST}/ckksparams.pb.h
    ${HIT_PROTOBUF_DST}/ckksparams.pb.cc
  COMMAND protoc --cpp_out=${HIT_PROTOBUF_DST} -I${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/ciphertext.proto
  COMMAND protoc --cpp_out=${HIT_PROTOBUF_DST} -I${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/ckksparams.proto
  DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/ciphertext.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/ckksparams.proto
)

# https://stackoverflow.com/a/49591908/925978
# avoid running clang-tidy on generated files
add_library(aws_hit_proto
  OBJECT
    ${HIT_PROTOBUF_DST}/ciphertext.pb.cc
    ${HIT_PROTOBUF_DST}/ckksparams.pb.cc)

install(
  FILES
    ${HIT_PROTOBUF_DST}/ckksparams.pb.h
    ${HIT_PROTOBUF_DST}/ciphertext.pb.h
  DESTINATION
    ${HIT_INCLUDES_INSTALL_DIR}/protobuf
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
set_target_properties(aws_hit_proto
  PROPERTIES
    CXX_CLANG_TIDY "")
