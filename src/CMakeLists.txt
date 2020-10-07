# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Create an object library to compile sources only once
# Sources are added by the CMakeLists in the source tree via `target_sources`
add_library(aws_hit_obj OBJECT)

# Add source files to library and header files to install
add_subdirectory(hit)

target_include_directories(aws_hit_obj PUBLIC
        ${CMAKE_CURRENT_BINARY_DIR}/../protobuf # to allow e.g., #include "protobuf/foo.ph.h"
        ${HIT_PROTOBUF_DST} # to allow e.g., #include "foo.ph.h", which is how auto-generated protobuf files expect imports to be available
        $<BUILD_INTERFACE:${HIT_INCLUDES_BUILD_DIR}>
        $<INSTALL_INTERFACE:${HIT_INCLUDES_INSTALL_DIR}>
    PRIVATE ${HIT_SOURCE_DIR}
    )

# Object libraries may be used as the target (first argument) of target_link_libraries
# specify dependencies of their sources on other libraries.
# https://stackoverflow.com/a/59220856/925978
target_link_libraries(aws_hit_obj PRIVATE seal glog::glog)

set_common_flags(aws_hit_obj)
