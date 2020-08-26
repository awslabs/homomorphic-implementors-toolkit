# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

message(STATUS "Downloading and installing Glog.")
download_external_project("glog")
add_subdirectory(
        ${HIT_THIRD_PARTY_DIR}/glog/src
        ${HIT_THIRD_PARTY_DIR}/glog/build
        EXCLUDE_FROM_ALL)
