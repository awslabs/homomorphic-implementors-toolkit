# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

list(APPEND HIT_TEST_FILES
        "${CMAKE_CURRENT_LIST_DIR}/linearalgebra.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/encodingunit.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/encryptedmatrix.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/encryptedrowvector.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/encryptedcolvector.cpp"
    )
set(HIT_TEST_FILES ${HIT_TEST_FILES} PARENT_SCOPE)
