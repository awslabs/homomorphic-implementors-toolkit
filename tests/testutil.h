// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <iostream>
#include <vector>
#include "hit/matrix.h"

uint32_t createRandomPositiveInt(const int mod = 100);

std::vector<double> randomVector(int dim, double maxNorm);

hit::Vector random_vec(int size);

hit::Matrix random_mat(int height, int width);
