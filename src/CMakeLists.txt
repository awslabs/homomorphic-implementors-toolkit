# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Create an object library to compile sources only once
# Sources are added by the CMakeLists in the source tree via `target_sources`
add_library(aws_hit_obj OBJECT)
# Declare a dependency on aws_hit_proto so that the protobuf files are
# generated prior to compiling aws_hit_obj, which imports the generated headers
add_dependencies(aws_hit_obj aws_hit_proto)

# Disable parallelism in debug mode for easier debugging, especially with GDB
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(aws_hit_obj PUBLIC -DDISABLE_PARALLELISM)
endif ()

# Add source files to library and header files to install
add_subdirectory(hit)

# Set C++ language version and include directories for the object library
target_compile_features(aws_hit_obj PUBLIC cxx_std_17)
target_include_directories(aws_hit_obj
	PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}/../protobuf # to allow e.g., #include "protobuf/foo.ph.h"
        ${HIT_PROTOBUF_DST} # to allow e.g., #include "foo.ph.h", which is how auto-generated protobuf files expect imports to be available
        $<BUILD_INTERFACE:${HIT_INCLUDES_BUILD_DIR}>
        $<INSTALL_INTERFACE:${HIT_INCLUDES_INSTALL_DIR}>
        ${HIT_SOURCE_DIR}
    )

# Object libraries may be used as the target (first argument) of target_link_libraries
# specify dependencies of their sources on other libraries.
# https://stackoverflow.com/a/59220856/925978
target_link_libraries(aws_hit_obj PRIVATE SEAL::seal glog::glog ${TBB_IMPORTED_TARGETS})

set_common_flags(aws_hit_obj)
