# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Exclude code analysis (clang-tidy) on tests.
# clang-tidy reports lots of warning on GTest related usage.
# See https://github.com/google/googletest/issues/2442
set(CMAKE_CXX_CLANG_TIDY "")

find_package(GoogleTestLib REQUIRED)

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/api)
list(APPEND HIT_TEST_FILES "testutil.cpp")
add_executable(hit-unit-test ${HIT_TEST_FILES})

target_link_libraries(hit-unit-test PUBLIC aws-hit gtest gtest_main)
set_common_flags(hit-unit-test)

add_custom_target(NAME hit-unit-test COMMAND hit-unit-test)

add_custom_target(
  run_hit_tests
  COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/hit-unit-test
  WORKING_DIRECTORY ${HELR_ROOT_DIR}
  DEPENDS hit-unit-test
  USES_TERMINAL)
