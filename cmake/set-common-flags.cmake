# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

function(set_common_flags target_name)
    target_compile_options(${target_name} PRIVATE -std=c++17 -fvisibility=hidden -fno-common -funsigned-char
            -Wfatal-errors)
    #-Wextra turns on sign-compare which is strict on comparing loop indexes (int) with size_t from vector length
    target_compile_options(${target_name} PRIVATE -Wno-sign-compare)
endfunction()
