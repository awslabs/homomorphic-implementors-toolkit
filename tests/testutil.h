// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <iostream>
#include <vector>

#include "hit/common.h"

uint32_t create_random_positive_int(const int mod = 100);

std::vector<double> random_vector(int dim, double max_norm);

hit::Vector random_vec(int size);

hit::Matrix random_mat(int height, int width);
