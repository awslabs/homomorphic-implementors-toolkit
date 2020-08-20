# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_executable(hit-example evaluator_example.cpp)
set_common_flags(hit-example)
target_link_libraries(hit-example aws-hit glog::glog)
