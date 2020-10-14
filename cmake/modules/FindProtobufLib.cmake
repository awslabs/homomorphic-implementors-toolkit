# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

find_package(Protobuf 3.0.0 QUIET)
find_program(Protoc_FOUND protoc)
# require both the protobuf library and the protoc compiler to be installed,
# otherwise build them ourselves. The versions must be compatible,
# so it's not a good idea to use, e.g., a system-installed protoc and
# build-from-source protobuf library
if (Protobuf_FOUND AND Protoc_FOUND)
    message(STATUS "Protobuf is already installed.")
else ()
    message(STATUS "Protobuf was not found on your system.")
    download_external_project("protobuf")
    # Even though find_package(Protobuf) succeeds at this point, it doesn't set
    # the variables `Protobuf_LIBRARIES` and `Protobuf_PROTOC_EXECUTABLE`
    # like it is supposed to, so we set them manually.
    # find_package(Protobuf "3.0.0" REQUIRED HINTS ${3P_INSTALL_DIR})
    set(Protobuf_LIBRARIES "${3P_INSTALL_DIR}/lib/libprotobuf.a")
    find_program(Protobuf_PROTOC_EXECUTABLE protoc)
endif ()
