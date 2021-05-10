# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

target_sources(aws_hit_obj
  PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/common.cpp
)

install(
  FILES
    ${CMAKE_CURRENT_LIST_DIR}/common.h
    ${CMAKE_CURRENT_LIST_DIR}/hit.h
  DESTINATION
    ${HIT_INCLUDES_INSTALL_DIR}
)

add_subdirectory(api)
