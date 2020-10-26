# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Boost is primarily a header-only library (https://www.boost.org/doc/libs/1_74_0/more/getting_started/unix-variants.html#header-only-libraries)
# This means that "installation" is just copying header files. Rather than
# download 150MB zip file of the entire Boost library, we include only the subset
# of headers we need. I extracted the required subset of Boost headers by running
# the following in the boost source directory:
# > ./bootstrap.sh
# > ./b2 tools/bcp
# > ./dist/bin/bcp --boost=/usr/local/include boost/numeric/ublas/matrix.hpp ./foo
# > ./dist/bin/bcp --boost=/usr/local/include boost/numeric/ublas/vector.hpp ./foo

find_package(Boost 1.65 QUIET)
if (Boost_FOUND)
    message(STATUS "Found Boost installed on the system.")
else ()
    message(STATUS "Boost was not found on your system.")
    message(STATUS "Installing Boost...")
    # Installation is easy: just unzip the headers to the third-party
    # installation directory
    file(MAKE_DIRECTORY ${3P_INSTALL_DIR}/include)
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E tar xzf ${HIT_THIRD_PARTY_DIR}/boost/boost_ublas.zip
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${3P_INSTALL_DIR}/include)
    if(result)
        message(FATAL_ERROR "Failed to install Boost (${result}).")
    endif()
endif ()
