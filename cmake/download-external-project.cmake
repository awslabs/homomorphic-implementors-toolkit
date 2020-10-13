# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

function(download_external_project project_dir)
    message(STATUS "Downloading ${project_dir}.")
    set(EXTERNAL_PROJECT_CMAKE_CACHE_FILE ${HIT_THIRD_PARTY_DIR}/${project_dir}/CMakeCache.txt)
    if(EXISTS ${EXTERNAL_PROJECT_CMAKE_CACHE_FILE})
        message(STATUS "Removing old ${EXTERNAL_PROJECT_CMAKE_CACHE_FILE}")
        file(REMOVE ${EXTERNAL_PROJECT_CMAKE_CACHE_FILE})
    endif()
    set(COMMAND_WORK_DIR ${HIT_THIRD_PARTY_DIR}/${project_dir})
    # include(${COMMAND_WORK_DIR}/CMakeLists.txt RESULT_VARIABLE result)
    execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" . -D3P_INSTALL_DIR=${3P_INSTALL_DIR}
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${COMMAND_WORK_DIR})
    if(result)
        message(FATAL_ERROR "Failed to download (${result}).")
    endif()
    message(STATUS "Building ${project_dir}.")
    execute_process(COMMAND ${CMAKE_COMMAND} --build .
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${COMMAND_WORK_DIR})
    if(result)
        message(FATAL_ERROR "Failed to build (${result}).")
    endif()
    message(STATUS "Building ${project_dir}.")
    execute_process(COMMAND ${CMAKE_COMMAND} --install .
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${COMMAND_WORK_DIR})
    if(result)
        message(FATAL_ERROR "Failed to install (${result}).")
    endif()
endfunction()
