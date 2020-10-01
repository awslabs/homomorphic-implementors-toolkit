// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include "../../testutil.h"
#include "gtest/gtest.h"
#include "hit/hit.h"

using namespace std;
using namespace hit;

// Test variables.
const int RANGE = 16;
const int NUM_OF_SLOTS = 4096;

TEST(OpcountTest, BasicFlow) {
    OpCount ckks_instance = OpCount();
    vector<double> vector_input = random_vector(NUM_OF_SLOTS, RANGE);
    CKKSCiphertext ciphertext = ckks_instance.encrypt(vector_input);
    ckks_instance.square_inplace(ciphertext);
    ckks_instance.relinearize_inplace(ciphertext);
    ckks_instance.rescale_to_next_inplace(ciphertext);
}
