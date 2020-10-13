# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# System installed GTest is not used here because
# 1. Unlike other dependencies (Boost and Protobuf), GTest is light to download and build.
# 2. More search engine results recommend building project with GTest directly.
message(STATUS "Downloading and installing GTest.")

find_package(GTest QUIET)
if (GTest_FOUND)
    message(STATUS "Found GTest.")
else ()
	# Download and install test dependency - Google Test.
	# https://github.com/google/googletest/blob/release-1.10.0/googletest/README.md.
	download_external_project("googletest")
	# Add googletest directly to our build.
	# This defines the gtest and gtest_main targets.
	# add_subdirectory(
	#         ${HIT_THIRD_PARTY_DIR}/googletest/src
	#         ${HIT_THIRD_PARTY_DIR}/googletest/build
	#         EXCLUDE_FROM_ALL)
	find_package(GTest REQUIRED)
	find_library(gtest_LIBRARIES gtest PATHS ${3P_INSTALL_DIR} REQUIRED)

	if (GTest_FOUND)
	    message(STATUS "Installed local copy of GTest.")
	else ()
		message(FATAL_ERROR "GTest is not found.")
	endif ()
endif ()

