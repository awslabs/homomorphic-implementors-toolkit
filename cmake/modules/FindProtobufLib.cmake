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
    # the call to `find_package` above sets Protobuf_LIBRARIES to `NOTFOUND`
    # When we call `find_package` again after installing protobuf, this variable
    # is not updated unless we `unset` its value first.
    unset(Protobuf_LIBRARIES)
    download_external_project("protobuf")
    find_package(Protobuf "3.0.0" REQUIRED)
	message(STATUS "Protoc compiler: ${Protobuf_PROTOC_EXECUTABLE}")
endif ()
