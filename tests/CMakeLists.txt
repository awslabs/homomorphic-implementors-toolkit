# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

find_package(GoogleTestLib REQUIRED)
include_directories(${PROJECT_SOURCE_DIR}/src)

list(APPEND HIT_TEST_FILES "CKKSInstance.cpp" "matrix.cpp")
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/api/evaluator)
add_executable(hit-unit-test ${HIT_TEST_FILES})

target_link_libraries(hit-unit-test PUBLIC hit gtest gtest_main)
set_common_flags(hit-unit-test)

add_test(NAME hit-unit-test COMMAND hit-unit-test)
add_custom_command(
        TARGET hit-unit-test
        COMMENT "Run unit tests in ${CMAKE_BINARY_DIR}"
        POST_BUILD
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMAND ${CMAKE_CTEST_COMMAND} -C $<CONFIGURATION> -R "^hit-unit-test$" --output-on-failures
)
