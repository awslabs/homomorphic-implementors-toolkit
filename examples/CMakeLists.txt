# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_executable(hit-example evaluator_example.cpp)
set_common_flags(hit-example)
target_link_libraries(hit-example aws-hit glog::glog)

add_executable(hit-temp temp.cpp ../tests/testutil.h ../tests/testutil.cpp)
set_common_flags(hit-temp)
target_link_libraries(hit-temp aws-hit)

add_custom_target(
  run_hit_example
  COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/hit-example
  WORKING_DIRECTORY ${HELR_ROOT_DIR}
  DEPENDS hit-example
  USES_TERMINAL)
