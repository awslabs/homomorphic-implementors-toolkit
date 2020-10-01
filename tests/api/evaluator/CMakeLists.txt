# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

list(APPEND HIT_TEST_FILES
        "${CMAKE_CURRENT_LIST_DIR}/depthfinder.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/plaintext.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/scaleestimator.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/homomorphic.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/debug.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/opcount.cpp"
    )
set(HIT_TEST_FILES ${HIT_TEST_FILES} PARENT_SCOPE)
