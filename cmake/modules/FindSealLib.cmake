# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# System installed GTest is not used here because we are sensitive
# to SEAL API changes
message(STATUS "Downloading and installing Microsoft SEAL.")

# Download and install test dependency - Microsoft SEAL.
download_external_project("seal")
find_package(SEAL 3.5 REQUIRED)

if (SEAL_FOUND)
    message(STATUS "Installed local copy of SEAL.")
else ()
	message(FATAL_ERROR "SEAL is not found.")
endif ()
