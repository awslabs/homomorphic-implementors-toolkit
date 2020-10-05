#!/bin/bash -ex
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Common variables
export CUR_DIR=`pwd`

if [ -d build ]; then rm -Rf build; fi
mkdir -p build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release \
    -DHIT_BUILD_TESTS=ON -DHIT_RUN_CLANG_TIDY=ON \
    -DHIT_BUILD_EXAMPLES=ON ../
ninja -j $(nproc)

# GLog flags/configuration.
# Default false. Log messages to stderr instead of logfiles.
export GLOG_logtostderr=true
# Default 0 (INFO). Log messages at or above this level.
# The numbers of severity levels INFO, WARNING, ERROR, and FATAL are 0, 1, 2, and 3, respectively.
# We don't want to see any messages in the tests (since some are expected failures), so
# only show FATAL errors.
export GLOG_minloglevel=3

ninja run_hit_tests
ninja run_hit_examples
