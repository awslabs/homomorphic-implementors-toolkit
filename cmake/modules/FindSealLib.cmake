# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Download and install test dependency - Microsoft SEAL.
download_external_project("seal")
find_package(SEAL 3.5 REQUIRED)
