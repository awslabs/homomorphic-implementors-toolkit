# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

target_sources(aws_hit_obj
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/debug.cpp
        ${CMAKE_CURRENT_LIST_DIR}/explicitdepthfinder.cpp
        ${CMAKE_CURRENT_LIST_DIR}/implicitdepthfinder.cpp
        ${CMAKE_CURRENT_LIST_DIR}/homomorphic.cpp
        ${CMAKE_CURRENT_LIST_DIR}/opcount.cpp
        ${CMAKE_CURRENT_LIST_DIR}/plaintext.cpp
        ${CMAKE_CURRENT_LIST_DIR}/rotations.cpp
        ${CMAKE_CURRENT_LIST_DIR}/scaleestimator.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/debug.h
        ${CMAKE_CURRENT_LIST_DIR}/explicitdepthfinder.h
        ${CMAKE_CURRENT_LIST_DIR}/implicitdepthfinder.h
        ${CMAKE_CURRENT_LIST_DIR}/homomorphic.h
        ${CMAKE_CURRENT_LIST_DIR}/opcount.h
        ${CMAKE_CURRENT_LIST_DIR}/plaintext.h
        ${CMAKE_CURRENT_LIST_DIR}/rotations.h
        ${CMAKE_CURRENT_LIST_DIR}/scaleestimator.h
    DESTINATION
        ${HIT_INCLUDES_INSTALL_DIR}/api/evaluator
)
