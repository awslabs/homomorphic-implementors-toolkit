# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

target_sources(aws_hit_obj
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/linearalgebra.cpp
        ${CMAKE_CURRENT_LIST_DIR}/encodingunit.cpp
        ${CMAKE_CURRENT_LIST_DIR}/encryptedmatrix.cpp
        ${CMAKE_CURRENT_LIST_DIR}/encryptedrowvector.cpp
        ${CMAKE_CURRENT_LIST_DIR}/encryptedcolvector.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/linearalgebra.h
        ${CMAKE_CURRENT_LIST_DIR}/encodingunit.h
        ${CMAKE_CURRENT_LIST_DIR}/encryptedmatrix.h
        ${CMAKE_CURRENT_LIST_DIR}/encryptedrowvector.h
        ${CMAKE_CURRENT_LIST_DIR}/encryptedcolvector.h
    DESTINATION
        ${HIT_INCLUDES_INSTALL_DIR}/api/evaluator/linearalgebra
)
