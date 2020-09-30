#!/bin/bash -ex
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Common variables
export CUR_DIR=`pwd`

# GLog flags/configuration.
# Default 0. Show all VLOG(m) messages for m less or equal the value of this flag.
export GLOG_v=1
# Default false. Log messages to stderr instead of logfiles.
export GLOG_logtostderr=false
# Default 0 (INFO). Log messages at or above this level.
# The numbers of severity levels INFO, WARNING, ERROR, and FATAL are 0, 1, 2, and 3, respectively.
export GLOG_minloglevel=0
# Logging directory.
export GLOG_log_dir="${CUR_DIR}/hit_log"

if [ -d ${GLOG_log_dir} ]; then rm -Rf ${GLOG_log_dir}; fi
mkdir -p ${GLOG_log_dir}
if [ -d build ]; then rm -Rf build; fi
mkdir -p build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release \
    -DHIT_BUILD_TESTS=ON -DHIT_RUN_CLANG_TIDY=ON \
    -DHIT_BUILD_EXAMPLES=ON ../
ninja -j $(nproc)
ninja run_hit_tests
ninja run_hit_examples
