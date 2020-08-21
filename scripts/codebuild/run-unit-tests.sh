#!/bin/bash -ex
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

if [ -d build ]; then rm -Rf build; fi
mkdir -p build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DCMake_RUN_CLANG_TIDY=ON -DBUILD_TESTING=ON -DBUILD_EXAMPLES=ON../
ninja -j $(nproc)
ninja run_evaldemo
