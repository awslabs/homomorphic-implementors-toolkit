#!/bin/bash -ex
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

if [ -d build ]; then rm -Rf build; fi
cmake . -Bbuild/Release -GNinja -DCMAKE_BUILD_TYPE=Release
ninja -Cbuild/Release
