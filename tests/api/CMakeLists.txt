# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_subdirectory(evaluator)

list(APPEND HIT_TEST_FILES
        "${CMAKE_CURRENT_LIST_DIR}/ciphertext.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/linearalgebra.cpp"
    )
set(HIT_TEST_FILES ${HIT_TEST_FILES} PARENT_SCOPE)
