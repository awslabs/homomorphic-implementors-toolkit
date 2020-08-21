# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_executable(evaldemo evaluator_demo.cpp)
set_common_flags(evaldemo)
target_link_libraries(evaldemo aws-hit)

add_custom_target(
  run_evaldemo
  COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/evaldemo
  WORKING_DIRECTORY ${HELR_ROOT_DIR}
  DEPENDS evaldemo
  USES_TERMINAL)
