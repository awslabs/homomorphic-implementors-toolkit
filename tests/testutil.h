// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <iostream>
#include <vector>

uint32_t createRandomPositiveInt(const int mod = 100);

std::vector<double> randomVector(int dim, double maxNorm);
