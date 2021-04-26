# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Download and install dependency - Latticpp.
download_external_project("latticpp")
add_subdirectory(${HIT_THIRD_PARTY_DIR}/latticpp/src)
