# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

function(download_external_project project_dir)
    set(COMMAND_WORK_DIR ${HIT_THIRD_PARTY_DIR}/${project_dir})
    message(STATUS "Cleaning ${project_dir} directory...")
    execute_process(
        # delete all items in ${COMMAND_WORK_DIR} _execpt_
        #  - CMakeLists.txt (which is part of the repo)
        #  - src/, which is where our build system unpacks the downloaded content. If this folder exists, we don't need to re-download
        COMMAND find . -maxdepth 1 \( ! -name "CMakeLists.txt" ! -name "." ! -path "./src" \) -exec rm -rf {} \;
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${COMMAND_WORK_DIR}
        OUTPUT_QUIET)
    message(STATUS "Obtaining ${project_dir}...")
    execute_process(
        COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" . -D3P_INSTALL_DIR=${3P_INSTALL_DIR}
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${COMMAND_WORK_DIR}
        OUTPUT_QUIET)
    if(result)
        message(FATAL_ERROR "Failed to download (${result}).")
    endif()
    message(STATUS "Building ${project_dir}...")
    execute_process(COMMAND ${CMAKE_COMMAND} --build .
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${COMMAND_WORK_DIR}
        OUTPUT_QUIET)
    if(result)
        message(FATAL_ERROR "Failed to build (${result}).")
    endif()
endfunction()
