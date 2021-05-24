# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

function(enable_clang_tidy)
    # clang-tidy is not used to fail built but only provide some warnings during development.
    # This is because third-party warnings are hard to be excluded. See https://reviews.llvm.org/D26418
    # Define CMAKE_CXX_CLANG_TIDY for code analysis.
    # Reference:
    # 1. https://gitlab.kitware.com/cmake/cmake/-/issues/18926
    # 2. https://clang.llvm.org/extra/clang-tidy/
    message(STATUS "Checking if clang-tidy is installed.")
    find_program(CLANG_TIDY_COMMAND NAMES clang-tidy)
    if (CLANG_TIDY_COMMAND)
        message(STATUS "Found clang-tidy.")
        # `-checks` argument is not specified in below clang-tidy command.
        # In this case, clang-tidy gets the checks by searching a .clang-tidy file.
        set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_COMMAND}" PARENT_SCOPE)
    else ()
        message(WARNING "CMake_RUN_CLANG_TIDY is ON but clang-tidy is not found!" PARENT_SCOPE)
        set(CMAKE_CXX_CLANG_TIDY "" CACHE STRING "" FORCE)
    endif ()
endfunction()
