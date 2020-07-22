# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

find_package(GoogleTestLib REQUIRED)
include_directories(${PROJECT_SOURCE_DIR}/helib)

add_executable(testhit CKKSInstance.cpp)

target_link_libraries(testhit PUBLIC helib gtest gtest_main)
set_common_flags(testhit)

add_test(NAME testhit COMMAND testhit)
add_custom_command(
        TARGET testhit
        COMMENT "Run unit tests in ${CMAKE_BINARY_DIR}"
        POST_BUILD
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMAND ${CMAKE_CTEST_COMMAND} -C $<CONFIGURATION> -R "^testhit$" --output-on-failures
)
