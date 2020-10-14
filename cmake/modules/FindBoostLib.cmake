# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# boost_ublas contains all header files needed to use boost/numeric/ublas/matrix.hpp
# and boost/numeric/ublas/vector.hpp.
# You can extract the required subset of Boost headers by runninig the following
# in the boost source directory:
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
    message(STATUS "Made directory...")
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E tar xzf ${HIT_THIRD_PARTY_DIR}/boost/boost_ublas.zip
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${3P_INSTALL_DIR}/include)
    if(result)
        message(FATAL_ERROR "Failed to install Boost (${result}).")
    endif()
endif ()
