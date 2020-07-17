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
    execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${COMMAND_WORK_DIR})
    if(result)
        message(FATAL_ERROR "Failed to download (${result}).")
    endif()
    execute_process(COMMAND ${CMAKE_COMMAND} --build .
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${COMMAND_WORK_DIR})
    if(result)
        message(FATAL_ERROR "Failed to build (${result}).")
    endif()
endfunction()
