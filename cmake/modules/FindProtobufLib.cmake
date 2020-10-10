# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

message(STATUS "Searching Protobuf.")
#find_package(Protobuf "3.0.0" QUIET)
#if (Protobuf_FOUND)
#    message(STATUS "Protobuf is found. Skip downloading source code.")
#else ()
message(STATUS "Downloading and installing Protobuf since it is not found.")
# Download source code.
download_external_project("protobuf")
# Build and install Protobuf project.
# https://github.com/protocolbuffers/protobuf/blob/master/src/README.md
set(PROTOBUF_CONTENT_DIR ${HIT_THIRD_PARTY_DIR}/protobuf/src)
set(PROTOBUF_BUILD_DIR ${HIT_THIRD_PARTY_DIR}/protobuf/build)
file(REMOVE_RECURSE ${PROTOBUF_BUILD_DIR})
file(MAKE_DIRECTORY ${PROTOBUF_BUILD_DIR})
execute_process(
        COMMAND ./configure --prefix ${PROTOBUF_BUILD_DIR}
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${PROTOBUF_CONTENT_DIR})
if (result)
    message(FATAL_ERROR "Failed to configure Protobuf. Error code: (${result}).")
endif ()
execute_process(
        COMMAND make -j
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${PROTOBUF_CONTENT_DIR})
if (result)
    message(FATAL_ERROR "Failed to build Protobuf. Error code: (${result}).")
endif ()
execute_process(
        COMMAND make install
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${PROTOBUF_CONTENT_DIR})
if (result)
    message(FATAL_ERROR "Failed to install Protobuf. Error code: (${result}).")
endif ()
set(PROTOBUF_USE_STATIC_LIBS false)
# Set the library prefix and library suffix properly.
if (PROTOBUF_USE_STATIC_LIBS)
    set(LIB_PREFIX ${CMAKE_STATIC_LIBRARY_PREFIX})
    set(LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
else ()
    set(LIB_PREFIX ${CMAKE_SHARED_LIBRARY_PREFIX})
    set(LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
endif ()
set(Protobuf_INCLUDE_DIRS ${PROTOBUF_BUILD_DIR}/include)
set(Protobuf_LIBRARIES "${PROTOBUF_BUILD_DIR}/lib/${LIB_PREFIX}protobuf${LIB_SUFFIX}")
#endif ()
message(STATUS "Protobuf include dir : ${Protobuf_INCLUDE_DIRS}")
message(STATUS "Protobuf libraries : ${Protobuf_LIBRARIES}")
