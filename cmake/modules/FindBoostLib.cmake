# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

message(STATUS "Searching Boost lib.")
find_package(Boost 1.65 COMPONENTS program_options)
if (Boost_FOUND)
    message(STATUS "Boost is found. Skip downloading source code.")
else ()
    message(STATUS "Downloading and installing Boost since it is not found.")
    # Variables
    set(BOOST_USE_STATIC_LIBS false)
    # Set the library prefix and library suffix properly.
    if (BOOST_USE_STATIC_LIBS)
        set(LIB_PREFIX ${CMAKE_STATIC_LIBRARY_PREFIX})
        set(LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
    else ()
        set(LIB_PREFIX ${CMAKE_SHARED_LIBRARY_PREFIX})
        set(LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
    endif ()
    # Download source code.
    download_external_project("boost")
    set(BOOST_CONTENT_DIR ${HIT_THIRD_PARTY_DIR}/boost/src)
    set(BOOST_BUILD_DIR ${HIT_THIRD_PARTY_DIR}/boost/build)
    # Build project.
    # https://github.com/boostorg/wiki/wiki/Getting-Started%3A-Overview
    file(REMOVE_RECURSE ${BOOST_BUILD_DIR})
    file(MAKE_DIRECTORY ${BOOST_BUILD_DIR})
    execute_process(
            COMMAND "./bootstrap.sh" "--prefix=${BOOST_BUILD_DIR}"
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${BOOST_CONTENT_DIR})
    if (result)
        message(FATAL_ERROR "Failed to bootstrap boost build. Error code: (${result}).")
    endif ()
    execute_process(
            COMMAND ./b2 --prefix=${BOOST_BUILD_DIR} --with-program_options install
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${BOOST_CONTENT_DIR})
    if (result)
        message(FATAL_ERROR "Failed to build boost. Error code: (${result}).")
    endif ()
    set(Boost_INCLUDE_DIRS ${BOOST_BUILD_DIR}/include)
    set(Boost_LIBRARY_DIRS ${BOOST_BUILD_DIR}/lib/${LIB_PREFIX}boost_${component}${LIB_SUFFIX})
endif ()
message(STATUS "Boost version : ${Boost_VERSION}")
message(STATUS "Boost_INCLUDE_DIRS : ${Boost_INCLUDE_DIRS}")
message(STATUS "Boost_LIBRARY_DIRS : ${Boost_LIBRARY_DIRS}")
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${Boost_LIBRARY_DIRS})
