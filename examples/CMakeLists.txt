# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_executable(hit-examples
  run_examples.cpp
  example_1_ckks.cpp
  example_2_plaintext.cpp
  example_3_evaluators.cpp
  example_4_linearalgebra.cpp
  example_5_serialization.cpp
)
set_common_flags(hit-examples)
target_link_libraries(hit-examples aws-hit)

add_custom_target(
  run_hit_examples
  COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/hit-examples
  WORKING_DIRECTORY ${HELR_ROOT_DIR}
  DEPENDS hit-examples
  USES_TERMINAL)
