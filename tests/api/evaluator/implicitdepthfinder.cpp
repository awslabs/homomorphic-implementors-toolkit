// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/api/evaluator/implicitdepthfinder.h"

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

TEST(ImplicitDepthFinderTest, RotateLeft) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.rotate_left(ciphertext1, STEPS);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_param_eval_depth());
    ASSERT_EQ(0, ckks_instance.get_param_bootstrap_depth());
}

TEST(ImplicitDepthFinderTest, RotateRight) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.rotate_right(ciphertext1, STEPS);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_param_eval_depth());
    ASSERT_EQ(0, ckks_instance.get_param_bootstrap_depth());
}

TEST(ImplicitDepthFinderTest, Negate) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.negate(ciphertext1);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_param_eval_depth());
    ASSERT_EQ(0, ckks_instance.get_param_bootstrap_depth());
}

TEST(ImplicitDepthFinderTest, AddPlainScalar) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.add_plain(ciphertext1, PLAIN_TEXT);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_param_eval_depth());
    ASSERT_EQ(0, ckks_instance.get_param_bootstrap_depth());
}

TEST(ImplicitDepthFinderTest, AddPlaintext) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.add_plain(ciphertext1, VECTOR_1);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_param_eval_depth());
    ASSERT_EQ(0, ckks_instance.get_param_bootstrap_depth());
}

TEST(ImplicitDepthFinderTest, Add) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.encrypt(VECTOR_1);
    ciphertext3 = ckks_instance.add(ciphertext1, ciphertext2);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext3.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_param_eval_depth());
    ASSERT_EQ(0, ckks_instance.get_param_bootstrap_depth());
}

TEST(ImplicitDepthFinderTest, SubPlainScalar) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.sub_plain(ciphertext1, PLAIN_TEXT);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_param_eval_depth());
    ASSERT_EQ(0, ckks_instance.get_param_bootstrap_depth());
}

TEST(ImplicitDepthFinderTest, SubPlaintext) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.sub_plain(ciphertext1, VECTOR_1);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_param_eval_depth());
    ASSERT_EQ(0, ckks_instance.get_param_bootstrap_depth());
}

TEST(ImplicitDepthFinderTest, Sub) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.encrypt(VECTOR_1);
    ciphertext3 = ckks_instance.sub(ciphertext1, ciphertext2);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext3.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_param_eval_depth());
    ASSERT_EQ(0, ckks_instance.get_param_bootstrap_depth());
}

TEST(ImplicitDepthFinderTest, AddCiphertextWithDiffHeLevel) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.encrypt(VECTOR_1);
    ckks_instance.reduce_level_to_inplace(ciphertext2, ciphertext2.he_level() - 1);
    ASSERT_THROW((
                     // Expect invalid_argument is thrown because he_level of the two ciphertexts is different.
                     ckks_instance.add(ciphertext1, ciphertext2)),
                 invalid_argument);
}

TEST(ImplicitDepthFinderTest, MultiplyPlainScalar) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.multiply_plain(ciphertext1, PLAIN_TEXT);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_param_eval_depth());
    ASSERT_EQ(0, ckks_instance.get_param_bootstrap_depth());
}

TEST(ImplicitDepthFinderTest, Multiply) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.encrypt(VECTOR_1);
    ciphertext3 = ckks_instance.multiply(ciphertext1, ciphertext2);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext3.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_param_eval_depth());
    ASSERT_EQ(0, ckks_instance.get_param_bootstrap_depth());
}

TEST(ImplicitDepthFinderTest, Multiply_InvalidCase) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.encrypt(VECTOR_1);
    ckks_instance.reduce_level_to_inplace(ciphertext2, ciphertext2.he_level() - 1);
    ASSERT_THROW((
                     // Expect invalid_argument is thrown because he_level of the two ciphertexts is different.
                     ckks_instance.multiply(ciphertext1, ciphertext2)),
                 invalid_argument);
}

TEST(ImplicitDepthFinderTest, Square) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.square(ciphertext1);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckks_instance.get_param_eval_depth());
    ASSERT_EQ(0, ckks_instance.get_param_bootstrap_depth());
}

TEST(ImplicitDepthFinderTest, ReduceLevelToMin) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
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
    ASSERT_EQ(0, ckks_instance.get_param_eval_depth());
    ASSERT_EQ(0, ckks_instance.get_param_bootstrap_depth());
}

TEST(ImplicitDepthFinderTest, ReduceLevelTo) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    int he_level = ciphertext1.he_level();
    ciphertext2 = ckks_instance.reduce_level_to(ciphertext1, he_level - 1);
    // Expect he_level is changed.
    ASSERT_EQ(he_level - 1, ciphertext2.he_level());
    ASSERT_EQ(0, ckks_instance.get_param_eval_depth());
    ASSERT_EQ(0, ckks_instance.get_param_bootstrap_depth());
}

TEST(ImplicitDepthFinderTest, ReduceLevelTo_InvalidCase) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
    CKKSCiphertext ciphertext1;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    int he_level = ciphertext1.he_level();
    ASSERT_THROW((
                     // Expect invalid_argument is thrown when cipherText is mod to higher level.
                     ckks_instance.reduce_level_to(ciphertext1, he_level + 1)),
                 invalid_argument);
}

TEST(ImplicitDepthFinderTest, RescaleToNextInPlace) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
    CKKSCiphertext ciphertext1;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ckks_instance.multiply_plain_inplace(ciphertext1, 1);
    int he_level = ciphertext1.he_level();
    ckks_instance.rescale_to_next_inplace(ciphertext1);
    ASSERT_EQ(he_level - 1, ciphertext1.he_level());
    ASSERT_EQ(1, ckks_instance.get_param_eval_depth());
    ASSERT_EQ(0, ckks_instance.get_param_bootstrap_depth());
}

TEST(ImplicitDepthFinderTest, Bootstrapping1) {
    ImplicitDepthFinder ckks_instance = ImplicitDepthFinder();
    // our circuit will be depth 3, so the max level is implicitly 3
    CKKSCiphertext ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ckks_instance.multiply_plain_inplace(ciphertext1, 1);
    // reduce to level 2
    ckks_instance.rescale_to_next_inplace(ciphertext1);
    ckks_instance.multiply_plain_inplace(ciphertext1, 1);
    // reduce to level 1
    ckks_instance.rescale_to_next_inplace(ciphertext1);
    // bootstrap. For this test, we make the bootstrapping depth 2, meaning
    // that post-bootstrapping, the ciphertext should be at level 1.
    CKKSCiphertext ciphertext2 = ckks_instance.bootstrap(ciphertext1);
    ckks_instance.multiply_plain_inplace(ciphertext2, 1);
    // reduce to level 0
    ckks_instance.rescale_to_next_inplace(ciphertext2);

    ASSERT_EQ(1, ckks_instance.get_param_eval_depth());
    ASSERT_EQ(2, ckks_instance.get_param_bootstrap_depth());
}