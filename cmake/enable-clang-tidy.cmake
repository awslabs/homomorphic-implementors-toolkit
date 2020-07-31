# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

function(enable_clang_tidy)
    # Define CMAKE_CXX_CLANG_TIDY for code analysis.
    # Reference:
    # 1. https://gitlab.kitware.com/cmake/cmake/-/issues/18926
    # 2. https://clang.llvm.org/extra/clang-tidy/
    message(STATUS "Checking if clang-tidy is installed.")
    find_program(CLANG_TIDY_COMMAND NAMES clang-tidy)
    if (NOT CLANG_TIDY_COMMAND)
        message(WARNING "CMake_RUN_CLANG_TIDY is ON but clang-tidy is not found!" PARENT_SCOPE)
        set(CMAKE_CXX_CLANG_TIDY "" CACHE STRING "" FORCE)
    else ()
        # `-checks` argument is not specified in below clang-tidy command.
        # In this case, clang-tidy gets the checks by searching a .clang-tidy file.
        set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_COMMAND};-header-filter='${CMAKE_SOURCE_DIR}/src/*';-warnings-as-errors=*" PARENT_SCOPE)
    endif ()
endfunction()
