# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

target_sources(aws_hit_obj
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/ciphertext.cpp
        ${CMAKE_CURRENT_LIST_DIR}/decryptor.cpp
        ${CMAKE_CURRENT_LIST_DIR}/encryptor.cpp
        ${CMAKE_CURRENT_LIST_DIR}/evaluator.cpp
        ${CMAKE_CURRENT_LIST_DIR}/linearalgebra.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/ciphertext.h
        ${CMAKE_CURRENT_LIST_DIR}/decryptor.h
        ${CMAKE_CURRENT_LIST_DIR}/encryptor.h
        ${CMAKE_CURRENT_LIST_DIR}/evaluator.h
        ${CMAKE_CURRENT_LIST_DIR}/linearalgebra.h
        ${CMAKE_CURRENT_LIST_DIR}/metadata.h
    DESTINATION
        ${HIT_INCLUDES_INSTALL_DIR}/api
)

add_subdirectory(evaluator)
