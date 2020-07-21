# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

function(set_common_flags target_name)
    target_compile_options(${target_name} PUBLIC -std=c++17 -Wall -Werror -Wformat=2 -Wwrite-strings -Wvla
            -fvisibility=hidden -fno-common -funsigned-char -Wextra -Wunused -Wcomment -Wchar-subscripts -Wuninitialized
            -Wunused-result -Wfatal-errors)
    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${target_name} PUBLIC -Wmissing-declarations -Wmissing-field-initializers -Wshadow
                -Wpedantic)
    endif()
    #-Wextra turns on sign-compare which is strict on comparing loop indexes (int) with size_t from vector length
    target_compile_options(${target_name} PUBLIC -Wno-sign-compare)
endfunction()
