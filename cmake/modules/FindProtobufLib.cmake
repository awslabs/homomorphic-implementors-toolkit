# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

find_package(Protobuf 3.0.0 QUIET)
if (Protobuf_FOUND)
    message(STATUS "Protobuf is already installed.")
else ()
    message(STATUS "Protobuf was not found on your system.")
    download_external_project("protobuf")
    find_package(Protobuf "3.0.0" REQUIRED)
    set(Protobuf_LIBRARIES "${3P_INSTALL_DIR}/lib/libprotobuf.a")
endif ()
