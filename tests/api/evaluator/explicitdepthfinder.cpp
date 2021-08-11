// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/api/evaluator/explicitdepthfinder.h"

#include <iostream>

#include "gtest/gtest.h"
#include "hit/api/ciphertext.h"

using namespace std;
using namespace hit;

// Test variables.
const int SIZE = 4096;
const double VALUE = 1;
const vector<double> VECTOR_1(SIZE, VALUE);

TEST(ExplicitDepthFinderTest, MultiplyPlainMatrix) {
    ExplicitDepthFinder ckks_instance = ExplicitDepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1, 1);
    ciphertext2 = ckks_instance.multiply_plain(ciphertext1, VECTOR_1);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(1, ckks_instance.get_multiplicative_depth());
}

TEST(ExplicitDepthFinderTest, RescaleToNextInPlace_ExplicitLevel) {
    ExplicitDepthFinder ckks_instance = ExplicitDepthFinder();
    CKKSCiphertext ciphertext1 = ckks_instance.encrypt(VECTOR_1, 1);
    ckks_instance.multiply_plain_inplace(ciphertext1, 1);
    int he_level = ciphertext1.he_level();
    ckks_instance.rescale_to_next_inplace(ciphertext1);
    ASSERT_EQ(he_level - 1, ciphertext1.he_level());
    ASSERT_EQ(1, ckks_instance.get_multiplicative_depth());
}
