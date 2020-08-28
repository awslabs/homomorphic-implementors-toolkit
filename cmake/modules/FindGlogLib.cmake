# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# https://github.com/google/glog/blob/master/cmake/INSTALL.md
message(STATUS "Downloading and installing Glog.")
download_external_project("glog")
set(WITH_GFLAGS OFF CACHE BOOL "Disable optional build flavor -- WITH_GFLAGS.")
add_subdirectory(
        ${HIT_THIRD_PARTY_DIR}/glog/src
        ${HIT_THIRD_PARTY_DIR}/glog/build
        EXCLUDE_FROM_ALL)
