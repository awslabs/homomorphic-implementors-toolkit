# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.12)

project(LATTICPP_DOWNLOAD VERSION 0.0.1)

# suppress a CMake warning about an unused variable
set(SUPPRESS_VAR_WARNING ${3P_INSTALL_DIR})

include(ExternalProject)
ExternalProject_Add(EP_AWSLATIGO
    SOURCE_DIR           ${CMAKE_CURRENT_LIST_DIR}/src
    GIT_REPOSITORY       https://github.com/awslabs/aws-cppwrapper-lattigo.git
    GIT_TAG              main
    GIT_CONFIG           advice.detachedHead=false
    CMAKE_ARGS           -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    UPDATE_COMMAND       ""
    CONFIGURE_COMMAND    ""
    BUILD_COMMAND        ""
    INSTALL_COMMAND      ""
    TEST_COMMAND         ""
    TEST_COMMAND         ""
)

