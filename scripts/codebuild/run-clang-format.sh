#!/bin/bash -ex
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

if [ -d build ]; then rm -Rf build; fi
mkdir -p build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DCMake_RUN_HIT_CODE_FORMAT=ON ../
ninja -j $(nproc)
