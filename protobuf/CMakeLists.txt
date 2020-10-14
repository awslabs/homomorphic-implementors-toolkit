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
    ${HIT_PROTOBUF_DST}/encoding_unit.pb.h
    ${HIT_PROTOBUF_DST}/encoding_unit.pb.cc
    ${HIT_PROTOBUF_DST}/ciphertext_vector.pb.h
    ${HIT_PROTOBUF_DST}/ciphertext_vector.pb.cc
    ${HIT_PROTOBUF_DST}/encrypted_matrix.pb.h
    ${HIT_PROTOBUF_DST}/encrypted_matrix.pb.cc
    ${HIT_PROTOBUF_DST}/encrypted_row_vector.pb.h
    ${HIT_PROTOBUF_DST}/encrypted_row_vector.pb.cc
    ${HIT_PROTOBUF_DST}/encrypted_col_vector.pb.h
    ${HIT_PROTOBUF_DST}/encrypted_col_vector.pb.cc
  COMMAND ${Protobuf_PROTOC_EXECUTABLE} --cpp_out=${HIT_PROTOBUF_DST} -I${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/ciphertext.proto
  COMMAND ${Protobuf_PROTOC_EXECUTABLE} --cpp_out=${HIT_PROTOBUF_DST} -I${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/ckksparams.proto
  COMMAND ${Protobuf_PROTOC_EXECUTABLE} --cpp_out=${HIT_PROTOBUF_DST} -I${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/encoding_unit.proto
  COMMAND ${Protobuf_PROTOC_EXECUTABLE} --cpp_out=${HIT_PROTOBUF_DST} -I${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/ciphertext_vector.proto
  COMMAND ${Protobuf_PROTOC_EXECUTABLE} --cpp_out=${HIT_PROTOBUF_DST} -I${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/encrypted_matrix.proto
  COMMAND ${Protobuf_PROTOC_EXECUTABLE} --cpp_out=${HIT_PROTOBUF_DST} -I${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/encrypted_row_vector.proto
  COMMAND ${Protobuf_PROTOC_EXECUTABLE} --cpp_out=${HIT_PROTOBUF_DST} -I${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/encrypted_col_vector.proto
  DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/ciphertext.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/ckksparams.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/encoding_unit.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/ciphertext_vector.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/encrypted_matrix.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/encrypted_row_vector.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/encrypted_col_vector.proto
)

# https://stackoverflow.com/a/49591908/925978
# avoid running clang-tidy on generated files
add_library(aws_hit_proto
  OBJECT
    ${HIT_PROTOBUF_DST}/ciphertext.pb.cc
    ${HIT_PROTOBUF_DST}/ckksparams.pb.cc
    ${HIT_PROTOBUF_DST}/encoding_unit.pb.cc
    ${HIT_PROTOBUF_DST}/ciphertext_vector.pb.cc
    ${HIT_PROTOBUF_DST}/encrypted_matrix.pb.cc
    ${HIT_PROTOBUF_DST}/encrypted_row_vector.pb.cc
    ${HIT_PROTOBUF_DST}/encrypted_col_vector.pb.cc
)

install(
  FILES
    ${HIT_PROTOBUF_DST}/ciphertext.pb.h
    ${HIT_PROTOBUF_DST}/ckksparams.pb.h
    ${HIT_PROTOBUF_DST}/encoding_unit.pb.h
    ${HIT_PROTOBUF_DST}/ciphertext_vector.pb.h
    ${HIT_PROTOBUF_DST}/encrypted_matrix.pb.h
    ${HIT_PROTOBUF_DST}/encrypted_row_vector.pb.h
    ${HIT_PROTOBUF_DST}/encrypted_col_vector.pb.h
  DESTINATION
    ${HIT_INCLUDES_INSTALL_DIR}/protobuf
)

# disable all compiler warnings for auto-generated files
set_source_files_properties(
  ${HIT_PROTOBUF_DST}/ciphertext.pb.h
  ${HIT_PROTOBUF_DST}/ciphertext.pb.cc
  ${HIT_PROTOBUF_DST}/ckksparams.pb.h
  ${HIT_PROTOBUF_DST}/ckksparams.pb.cc
  ${HIT_PROTOBUF_DST}/encoding_unit.pb.h
  ${HIT_PROTOBUF_DST}/encoding_unit.pb.cc
  ${HIT_PROTOBUF_DST}/ciphertext_vector.pb.h
  ${HIT_PROTOBUF_DST}/ciphertext_vector.pb.cc
  ${HIT_PROTOBUF_DST}/encrypted_matrix.pb.h
  ${HIT_PROTOBUF_DST}/encrypted_matrix.pb.cc
  ${HIT_PROTOBUF_DST}/encrypted_row_vector.pb.h
  ${HIT_PROTOBUF_DST}/encrypted_row_vector.pb.cc
  ${HIT_PROTOBUF_DST}/encrypted_col_vector.pb.h
  ${HIT_PROTOBUF_DST}/encrypted_col_vector.pb.cc
  PROPERTIES
    COMPILE_FLAGS "-w"
)
