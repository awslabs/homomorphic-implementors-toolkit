# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# System installed GTest is not used here because we are sensitive
# to SEAL API changes
message(STATUS "Downloading and installing Microsoft SEAL.")

# Download and install test dependency - Microsoft SEAL.
download_external_project("seal")
# Add seal directly to our build.
add_subdirectory(
        ${HIT_THIRD_PARTY_DIR}/seal/src
        EXCLUDE_FROM_ALL)
