# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# System installed GTest is not used here because
# 1. Unlike other dependencies (Boost and Protobuf), GTest is light to download and build.
# 2. More search engine results recommend building project with GTest directly.
message(STATUS "Downloading and installing GTest.")
# Download and install test dependency - Google Test.
# https://github.com/google/googletest/blob/release-1.10.0/googletest/README.md.
download_external_project("googletest")
# Add googletest directly to our build.
# This defines the gtest and gtest_main targets.
add_subdirectory(
        ${HIT_THIRD_PARTY_DIR}/googletest/src
        ${HIT_THIRD_PARTY_DIR}/googletest/build
        EXCLUDE_FROM_ALL)
