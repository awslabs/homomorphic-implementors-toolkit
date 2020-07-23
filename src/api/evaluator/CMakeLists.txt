# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

target_sources(helib
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/debug.cpp
        ${CMAKE_CURRENT_LIST_DIR}/depthfinder.cpp
        ${CMAKE_CURRENT_LIST_DIR}/homomorphic.cpp
        ${CMAKE_CURRENT_LIST_DIR}/opcount.cpp
        ${CMAKE_CURRENT_LIST_DIR}/plaintext.cpp
        ${CMAKE_CURRENT_LIST_DIR}/scaleestimator.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/debug.h
        ${CMAKE_CURRENT_LIST_DIR}/depthfinder.h
        ${CMAKE_CURRENT_LIST_DIR}/homomorphic.h
        ${CMAKE_CURRENT_LIST_DIR}/opcount.h
        ${CMAKE_CURRENT_LIST_DIR}/plaintext.h
        ${CMAKE_CURRENT_LIST_DIR}/scaleestimator.h
    DESTINATION
        ${HELIB_INCLUDES_INSTALL_DIR}/api/evaluator
)
