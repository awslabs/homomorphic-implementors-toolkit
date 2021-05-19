# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

function(enable_hit_code_format)
    # clang-format is used to format code during development but not to fail build.
    # Only version starting from 10.0.0 has option can turn warnings to errors.
    message(STATUS "Checking if clang-format is installed.")
    find_program(CLANG_FORMAT_COMMAND NAMES clang-format)
    if (CLANG_FORMAT_COMMAND)
        message(STATUS "Found clang-format.")
        # List all files
        file(GLOB_RECURSE HIT_CPP_FILES "${HIT_SOURCE_DIR}/*.h" "${HIT_SOURCE_DIR}/*.cpp" "${HIT_TESTS_DIR}/*.h" "${HIT_TESTS_DIR}/*.cpp")
        message(STATUS "Using clang-format to format ${HIT_CPP_FILES}.")
        execute_process(
                COMMAND ${CLANG_FORMAT_COMMAND} -style=file -i ${HIT_CPP_FILES}
                RESULT_VARIABLE result
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
    else ()
        message(WARNING "CMake_RUN_CLANG_FORMAT is ON but clang-format is not found!" PARENT_SCOPE)
        set(CMAKE_CXX_CLANG_FORMAT "" CACHE STRING "" FORCE)
    endif ()
endfunction()
