// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/api/evaluator/depthfinder.h"

#include <iostream>

#include "gtest/gtest.h"
#include "hit/api/ciphertext.h"

using namespace std;
using namespace hit;

// Test variables.
const int SIZE = 4096;
const double VALUE = 1;
const double PLAIN_TEXT = 1;
const int STEPS = 1;
const vector<double> VECTOR_1(SIZE, VALUE);

TEST(DepthFinderTest, RotateLeft) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.rotate_left(ciphertext1, STEPS);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_multiplicative_depth());
}

TEST(DepthFinderTest, RotateRight) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.rotate_right(ciphertext1, STEPS);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_multiplicative_depth());
}

TEST(DepthFinderTest, Negate) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.negate(ciphertext1);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_multiplicative_depth());
}

TEST(DepthFinderTest, AddPlainScalar) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.add_plain(ciphertext1, PLAIN_TEXT);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_multiplicative_depth());
}

TEST(DepthFinderTest, AddPlaintext) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.add_plain(ciphertext1, VECTOR_1);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_multiplicative_depth());
}

TEST(DepthFinderTest, Add) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.encrypt(VECTOR_1);
    ciphertext3 = ckks_instance.add(ciphertext1, ciphertext2);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext3.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_multiplicative_depth());
}

TEST(DepthFinderTest, SubPlainScalar) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.sub_plain(ciphertext1, PLAIN_TEXT);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_multiplicative_depth());
}

TEST(DepthFinderTest, SubPlaintext) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.sub_plain(ciphertext1, VECTOR_1);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_multiplicative_depth());
}

TEST(DepthFinderTest, Sub) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.encrypt(VECTOR_1);
    ciphertext3 = ckks_instance.sub(ciphertext1, ciphertext2);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext3.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_multiplicative_depth());
}

TEST(DepthFinderTest, AddCiphertextWithDiffHeLevel) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.encrypt(VECTOR_1);
    ckks_instance.reduce_level_to_inplace(ciphertext2, ciphertext2.he_level() - 1);
    ASSERT_THROW((
                     // Expect invalid_argument is thrown because he_level of the two ciphertexts is different.
                     ckks_instance.add(ciphertext1, ciphertext2)),
                 invalid_argument);
}

TEST(DepthFinderTest, MultiplyPlainScalar) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.multiply_plain(ciphertext1, PLAIN_TEXT);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_multiplicative_depth());
}

TEST(DepthFinderTest, Multiply) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.encrypt(VECTOR_1);
    ciphertext3 = ckks_instance.multiply(ciphertext1, ciphertext2);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext3.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_multiplicative_depth());
}

TEST(DepthFinderTest, Multiply_InvalidCase) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.encrypt(VECTOR_1);
    ckks_instance.reduce_level_to_inplace(ciphertext2, ciphertext2.he_level() - 1);
    ASSERT_THROW((
                     // Expect invalid_argument is thrown because he_level of the two ciphertexts is different.
                     ckks_instance.multiply(ciphertext1, ciphertext2)),
                 invalid_argument);
}

TEST(DepthFinderTest, Square) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.square(ciphertext1);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_multiplicative_depth());
}

TEST(DepthFinderTest, ReduceLevelToMin) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.encrypt(VECTOR_1);
    ciphertext3 = ckks_instance.encrypt(VECTOR_1);
    ckks_instance.reduce_level_to_inplace(ciphertext3, ciphertext3.he_level() - 1);
    ckks_instance.reduce_level_to_min_inplace(ciphertext1, ciphertext3);
    ckks_instance.reduce_level_to_min_inplace(ciphertext3, ciphertext2);
    // Expect he_level is changed.
    ASSERT_EQ(ciphertext3.he_level(), ciphertext2.he_level());
    ASSERT_EQ(ciphertext3.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_multiplicative_depth());
}

TEST(DepthFinderTest, ReduceLevelTo) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    int he_level = ciphertext1.he_level();
    ciphertext2 = ckks_instance.reduce_level_to(ciphertext1, he_level - 1);
    // Expect he_level is changed.
    ASSERT_EQ(he_level - 1, ciphertext2.he_level());
    ASSERT_EQ(0, ckks_instance.get_multiplicative_depth());
}

TEST(DepthFinderTest, ReduceLevelTo_InvalidCase) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    int he_level = ciphertext1.he_level();
    ASSERT_THROW((
                     // Expect invalid_argument is thrown when cipherText is mod to higher level.
                     ckks_instance.reduce_level_to(ciphertext1, he_level + 1)),
                 invalid_argument);
}

TEST(DepthFinderTest, RescaleToNextInPlace) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ckks_instance.multiply_plain_inplace(ciphertext1, 1);
    int he_level = ciphertext1.he_level();
    ckks_instance.rescale_to_next_inplace(ciphertext1);
    ASSERT_EQ(he_level - 1, ciphertext1.he_level());
    ASSERT_EQ(1, ckks_instance.get_multiplicative_depth());
}

TEST(DepthFinderTest, Bootstrapping1) {
    // We arbitrarily assume the post-bootstrapping level is 1.
    DepthFinder ckks_instance = DepthFinder(1);
    // Our circuit will be depth 3, so for accounting purposes,
    // assume this is encrypted at level 3.
    CKKSCiphertext ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ckks_instance.multiply_plain_inplace(ciphertext1, 1);
    // reduce to level 2
    ckks_instance.rescale_to_next_inplace(ciphertext1);
    ckks_instance.multiply_plain_inplace(ciphertext1, 1);
    // reduce to level 1
    ckks_instance.rescale_to_next_inplace(ciphertext1);
    // bootstrap. Above, we specified the post-bootstrapping level is 1
    CKKSCiphertext ciphertext2 = ckks_instance.bootstrap(ciphertext1);
    ASSERT_EQ(1, ciphertext2.he_level());
    ckks_instance.multiply_plain_inplace(ciphertext2, 1);
    // reduce to level 0
    ckks_instance.rescale_to_next_inplace(ciphertext2);
    ASSERT_EQ(3, ckks_instance.get_multiplicative_depth());
}

TEST(DepthFinderTest, MultiplyPlainMatrix) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1, 1);
    ciphertext2 = ckks_instance.multiply_plain(ciphertext1, VECTOR_1);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_multiplicative_depth());
}

TEST(DepthFinderTest, RescaleToNextInPlace_Level) {
    DepthFinder ckks_instance = DepthFinder();
    CKKSCiphertext ciphertext1 = ckks_instance.encrypt(VECTOR_1, 1);
    ckks_instance.multiply_plain_inplace(ciphertext1, 1);
    int he_level = ciphertext1.he_level();
    ckks_instance.rescale_to_next_inplace(ciphertext1);
    ASSERT_EQ(he_level - 1, ciphertext1.he_level());
    ASSERT_EQ(1, ckks_instance.get_multiplicative_depth());
}

TEST(DepthFinderTest, Bootstrapping2) {
    // We arbitrarily assume the post-bootstrapping level is 1.
    DepthFinder ckks_instance = DepthFinder(3);
    // Encrypt at level 3
    CKKSCiphertext ciphertext1 = ckks_instance.encrypt(VECTOR_1, 3);
    ckks_instance.multiply_plain_inplace(ciphertext1, 1);
    // reduce to level 2
    ckks_instance.rescale_to_next_inplace(ciphertext1);
    ckks_instance.multiply_plain_inplace(ciphertext1, 1);
    // reduce to level 1
    ckks_instance.rescale_to_next_inplace(ciphertext1);
    ckks_instance.multiply_plain_inplace(ciphertext1, 1);
    // reduce to level 0
    ckks_instance.rescale_to_next_inplace(ciphertext1);
    // bootstrap. Above, we specified the post-bootstrapping level is 1
    CKKSCiphertext ciphertext2 = ckks_instance.bootstrap(ciphertext1, false);
    ASSERT_EQ(3, ciphertext2.he_level());
    ckks_instance.multiply_plain_inplace(ciphertext2, 1);
    // reduce to level 2
    ckks_instance.rescale_to_next_inplace(ciphertext2);
    ASSERT_EQ(4, ckks_instance.get_multiplicative_depth());
}
