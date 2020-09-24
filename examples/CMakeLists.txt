# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_executable(hit-example evaluator_example.cpp)
set_common_flags(hit-example)
target_link_libraries(hit-example aws-hit glog::glog)

add_executable(hit-example-1 example_1_ckks.cpp)
target_link_libraries(hit-example-1 aws-hit)
add_executable(hit-example-2 example_1_ckks.cpp example_2_plaintext.cpp)
target_link_libraries(hit-example-2 aws-hit)
add_executable(hit-example-3 example_1_ckks.cpp example_2_plaintext.cpp example_3_parameters.cpp)
target_link_libraries(hit-example-3 aws-hit)

add_custom_target(
  run_hit_example
  COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/hit-example
  WORKING_DIRECTORY ${HELR_ROOT_DIR}
  DEPENDS hit-example
  USES_TERMINAL)
