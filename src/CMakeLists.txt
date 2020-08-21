# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Create an object library to compile sources only once
# Sources are added by the CMakeLists in the source tree via `target_sources`
add_library(aws_hit_obj OBJECT)

# Add source files to library and header files to install
add_subdirectory(hit)

# Set C++ language version and include directories for the object library
target_compile_features(aws_hit_obj PUBLIC cxx_std_17)
target_include_directories(aws_hit_obj PUBLIC
        ${CMAKE_CURRENT_BINARY_DIR}/../protobuf # to allow e.g., #include "protobuf/foo.ph.h"
        ${HIT_PROTOBUF_DST} # to allow e.g., #include "foo.ph.h", which is how auto-generated protobuf files expect imports to be available
        $<BUILD_INTERFACE:${HIT_INCLUDES_BUILD_DIR}>
        $<INSTALL_INTERFACE:${HIT_INCLUDES_INSTALL_DIR}>
    PRIVATE ${HIT_SOURCE_DIR}
    )
target_link_libraries(aws_hit_obj PUBLIC aws_hit_proto PRIVATE seal)
set_common_flags(aws_hit_obj)
