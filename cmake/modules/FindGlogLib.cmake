# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set(LIB_NAME glog)

find_package(glog 0.3.5 QUIET)
if (glog_FOUND)
    message(STATUS "GLog is already installed.")
else ()
    message(STATUS "GLog was not found on your system.")
    download_external_project("glog")
    find_package(glog REQUIRED)
endif ()
