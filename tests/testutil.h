// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

using namespace std;

inline uint32_t createRandomPositiveInt(const int mod = 100) {
    srand(time(nullptr));
    return rand() % mod + 1;
}
