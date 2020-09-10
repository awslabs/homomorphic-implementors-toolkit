// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include "gtest/gtest.h"
#include "hit/CKKSInstance.h"
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
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2 = ckksInstance->evaluator->rotate_left(ciphertext1, STEPS);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckksInstance->get_multiplicative_depth());
}

TEST(DepthFinderTest, RotateRight) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2 = ckksInstance->evaluator->rotate_right(ciphertext1, STEPS);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckksInstance->get_multiplicative_depth());
}

TEST(DepthFinderTest, Negate) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2 = ckksInstance->evaluator->negate(ciphertext1);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckksInstance->get_multiplicative_depth());
}

TEST(DepthFinderTest, AddPlainScalar) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2 = ckksInstance->evaluator->add_plain(ciphertext1, PLAIN_TEXT);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckksInstance->get_multiplicative_depth());
}

TEST(DepthFinderTest, AddPlaintext) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2 = ckksInstance->evaluator->add_plain(ciphertext1, VECTOR_1);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckksInstance->get_multiplicative_depth());
}

TEST(DepthFinderTest, Add) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2 = ckksInstance->encrypt(VECTOR_1);
    ciphertext3 = ckksInstance->evaluator->add(ciphertext1, ciphertext2);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext3.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckksInstance->get_multiplicative_depth());
}

TEST(DepthFinderTest, SubPlainScalar) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2 = ckksInstance->evaluator->sub_plain(ciphertext1, PLAIN_TEXT);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckksInstance->get_multiplicative_depth());
}

TEST(DepthFinderTest, SubPlaintext) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2 = ckksInstance->evaluator->sub_plain(ciphertext1, VECTOR_1);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckksInstance->get_multiplicative_depth());
}

TEST(DepthFinderTest, Sub) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2 = ckksInstance->encrypt(VECTOR_1);
    ciphertext3 = ckksInstance->evaluator->sub(ciphertext1, ciphertext2);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext3.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckksInstance->get_multiplicative_depth());
}

TEST(DepthFinderTest, AddCiphertextWithDiffHeLevel) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2.he_level() = ciphertext1.he_level() + 1;
    ASSERT_THROW((
                     // Expect invalid_argument is thrown because he_level of the two ciphertexts is different.
                     ckksInstance->evaluator->add(ciphertext1, ciphertext2)),
                 invalid_argument);
}

TEST(DepthFinderTest, MultiplyPlainScalar) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2 = ckksInstance->evaluator->multiply_plain(ciphertext1, PLAIN_TEXT);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckksInstance->get_multiplicative_depth());
}

TEST(DepthFinderTest, MultiplyPlainMatrix) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1, 1);
    ciphertext2 = ckksInstance->evaluator->multiply_plain(ciphertext1, VECTOR_1);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckksInstance->get_multiplicative_depth());
}

TEST(DepthFinderTest, Multiply) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2 = ckksInstance->encrypt(VECTOR_1);
    ciphertext3 = ckksInstance->evaluator->multiply(ciphertext1, ciphertext2);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext3.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckksInstance->get_multiplicative_depth());
}

TEST(DepthFinderTest, Multiply_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2.he_level() = ciphertext1.he_level() + 1;
    ASSERT_THROW((
                     // Expect invalid_argument is thrown because he_level of the two ciphertexts is different.
                     ckksInstance->evaluator->multiply(ciphertext1, ciphertext2)),
                 invalid_argument);
}

TEST(DepthFinderTest, Square) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2 = ckksInstance->evaluator->square(ciphertext1);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckksInstance->get_multiplicative_depth());
}

TEST(DepthFinderTest, ModDownTo) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2 = ckksInstance->encrypt(VECTOR_1);
    int he_level = ciphertext1.he_level();
    ASSERT_EQ(he_level, ciphertext2.he_level());
    ciphertext1.he_level() = he_level + 1;
    ckksInstance->evaluator->mod_down_to_inplace(ciphertext1, ciphertext2);
    // Expect he_level is changed.
    ASSERT_EQ(he_level, ciphertext1.he_level());
    ASSERT_EQ(0, ckksInstance->get_multiplicative_depth());
}

TEST(DepthFinderTest, ModDownTo_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2.he_level() = ciphertext1.he_level() + 1;
    ASSERT_THROW((
                     // Expect invalid_argument is thrown because the he_level of second argument is larger.
                     ckksInstance->evaluator->mod_down_to(ciphertext1, ciphertext2)),
                 invalid_argument);
}

TEST(DepthFinderTest, ModDownToMin) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2 = ckksInstance->encrypt(VECTOR_1);
    ciphertext3 = ckksInstance->encrypt(VECTOR_1);
    ciphertext3.he_level() = ciphertext3.he_level() - 1;
    ckksInstance->evaluator->mod_down_to_min_inplace(ciphertext1, ciphertext3);
    ckksInstance->evaluator->mod_down_to_min_inplace(ciphertext3, ciphertext2);
    // Expect he_level is changed.
    ASSERT_EQ(ciphertext3.he_level(), ciphertext2.he_level());
    ASSERT_EQ(ciphertext3.he_level(), ciphertext1.he_level());
    ASSERT_EQ(0, ckksInstance->get_multiplicative_depth());
}

TEST(DepthFinderTest, ModDownToLevel) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    int he_level = ciphertext1.he_level();
    ciphertext2 = ckksInstance->evaluator->mod_down_to_level(ciphertext1, he_level - 1);
    // Expect he_level is changed.
    ASSERT_EQ(he_level - 1, ciphertext2.he_level());
    ASSERT_EQ(0, ckksInstance->get_multiplicative_depth());
}

TEST(DepthFinderTest, ModDownToLevel_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    int he_level = ciphertext1.he_level();
    ASSERT_THROW((
                     // Expect invalid_argument is thrown when cipherText is mod to higher level.
                     ckksInstance->evaluator->mod_down_to_level(ciphertext1, he_level + 1)),
                 invalid_argument);
}

TEST(DepthFinderTest, RescaleToNextInPlace) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    int he_level = ciphertext1.he_level();
    ckksInstance->evaluator->rescale_to_next_inplace(ciphertext1);
    ASSERT_EQ(he_level - 1, ciphertext1.he_level());
    ASSERT_EQ(1, ckksInstance->get_multiplicative_depth());
}

TEST(DepthFinderTest, RescaleToNextInPlace_ExplicitLevel) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_depthfinder_instance();
    CKKSCiphertext ciphertext1;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1, 1);
    int he_level = ciphertext1.he_level();
    ckksInstance->evaluator->rescale_to_next_inplace(ciphertext1);
    ASSERT_EQ(he_level - 1, ciphertext1.he_level());
    ASSERT_EQ(1, ckksInstance->get_multiplicative_depth());
}
