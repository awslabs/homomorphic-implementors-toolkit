# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Apply a Git patch
#
# We assume that the full path to the patch is
# ${path_to_patch}/${patch_name}.patch
#
# We assume that the full path to the repo (location of the .git folder)
# is ${path_to_repo}
#
function(apply_patch path_to_patch patch_name path_to_repo)
  # https://github.com/facebook/hhvm/blob/master/CMakeLists.txt
  message(STATUS "Applying ${patch_name}")
  execute_process(
    COMMAND ${GIT_EXECUTABLE} apply --ignore-whitespace --whitespace=nowarn
    WORKING_DIRECTORY "${path_to_repo}"
    INPUT_FILE "${path_to_patch}/${patch_name}.patch"
    OUTPUT_VARIABLE OUTPUT
    RESULT_VARIABLE RESULT
    ERROR_QUIET)
  if (RESULT EQUAL 0)
    message(STATUS "${patch_name} patch applied")
  else()
    # Unfortunately although patch will recognise that a patch is already
    # applied it will still return an error.
    execute_process(
      COMMAND ${GIT_EXECUTABLE} apply --ignore-whitespace --whitespace=nowarn -R --check
      WORKING_DIRECTORY "${path_to_repo}"
      INPUT_FILE "${path_to_patch}/${patch_name}.patch"
      OUTPUT_VARIABLE OUTPUT
      RESULT_VARIABLE RESULT2)
    if (RESULT2 EQUAL 0)
      message(STATUS "${patch_name} patch was already applied")
    else()
      message(FATAL_ERROR "Error applying ${patch_name} patch")
    endif()
  endif()
endfunction()
