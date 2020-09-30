# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_executable(hit-example evaluator_example.cpp)
set_common_flags(hit-example)
target_link_libraries(hit-example aws-hit glog::glog)



add_library(aws_hit_examples OBJECT)
target_sources(aws_hit_examples
  PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/example_1_ckks.cpp
    ${CMAKE_CURRENT_LIST_DIR}/example_2_plaintext.cpp
    ${CMAKE_CURRENT_LIST_DIR}/example_3_evaluators.cpp
    ${CMAKE_CURRENT_LIST_DIR}/example_4_linearalgebra.cpp
    ${CMAKE_CURRENT_LIST_DIR}/example_5_serialization.cpp
)
target_link_libraries(aws_hit_examples PUBLIC aws-hit)

add_executable(hit-examples
  run_examples.cpp
  example_1_ckks.cpp
  example_2_plaintext.cpp
  example_3_evaluators.cpp
  example_4_linearalgebra.cpp
  example_5_serialization
)
set_common_flags(hit-examples)
target_link_libraries(hit-examples aws-hit)

add_custom_target(
  run_hit_example
  COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/hit-example
  WORKING_DIRECTORY ${HELR_ROOT_DIR}
  DEPENDS hit-example
  USES_TERMINAL)
