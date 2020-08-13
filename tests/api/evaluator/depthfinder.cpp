// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include "gtest/gtest.h"

#include "CKKSInstance.h"
#include "api/ciphertext.h"

using namespace std;

// Test variables.
const bool VERBOSE = false;
const int SIZE = 4096;
const double VALUE = 1;
const double PLAIN_TEXT = 1;
const int STEPS = 1;
const vector<double> VECTOR_1(SIZE, VALUE);

TEST(DepthFinderTest, RotateVectorLeft) {
    CKKSInstance* ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->rotate_vector_left(ciphertext1, STEPS);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level, ciphertext1.he_level);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, RotateVectorRight) {
    CKKSInstance* ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->rotate_vector_right(ciphertext1, STEPS);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level, ciphertext1.he_level);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, AddPlainScalar) {
    CKKSInstance* ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->add_plain_scalar(ciphertext1, PLAIN_TEXT);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level, ciphertext1.he_level);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, Add) {
    CKKSInstance* ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext2);
    ciphertext3 = ckksInstance->evaluator->add(ciphertext1, ciphertext2);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext3.he_level, ciphertext1.he_level);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, AddCiphertextWithDiffHeLevel) {
    CKKSInstance* ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext2);
    ciphertext2.he_level = ciphertext1.he_level + 1;
    ASSERT_THROW((
                     // Expect invalid_argument is thrown because he_level of the two ciphertexts is different.
                     ckksInstance->evaluator->add(ciphertext1, ciphertext2)),
                 invalid_argument);
}

TEST(DepthFinderTest, MultiplyPlainScalar) {
    CKKSInstance* ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->multiply_plain_scalar(ciphertext1, PLAIN_TEXT);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level, ciphertext1.he_level);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, MultiplyPlainMattrix) {
    CKKSInstance* ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, 1, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->multiply_plain_mat(ciphertext1, VECTOR_1);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level, ciphertext1.he_level);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, Multiply) {
    CKKSInstance* ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext2);
    ciphertext3 = ckksInstance->evaluator->multiply(ciphertext1, ciphertext2);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext3.he_level, ciphertext1.he_level);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, Multiply_InvalidCase) {
    CKKSInstance* ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext2);
    ciphertext2.he_level = ciphertext1.he_level + 1;
    ASSERT_THROW((
                     // Expect invalid_argument is thrown because he_level of the two ciphertexts is different.
                     ckksInstance->evaluator->multiply(ciphertext1, ciphertext2)),
                 invalid_argument);
}

TEST(DepthFinderTest, Square) {
    CKKSInstance* ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->square(ciphertext1);
    // Expect he_level does not change.
    ASSERT_EQ(ciphertext2.he_level, ciphertext1.he_level);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, ModDownTo) {
    CKKSInstance* ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext2);
    int he_level = ciphertext1.he_level;
    ASSERT_EQ(he_level, ciphertext2.he_level);
    ciphertext1.he_level = he_level + 1;
    ckksInstance->evaluator->modDownTo(ciphertext1, ciphertext2);
    // Expect he_level is changed.
    ASSERT_EQ(he_level, ciphertext1.he_level);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, ModDownTo_InvalidCase) {
    CKKSInstance* ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext2);
    ciphertext2.he_level = ciphertext1.he_level + 1;
    ASSERT_THROW((
                     // Expect invalid_argument is thrown because the he_level of second argument is larger.
                     ckksInstance->evaluator->modDownTo(ciphertext1, ciphertext2)),
                 invalid_argument);
}

TEST(DepthFinderTest, ModDownToMin) {
    CKKSInstance* ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext2);
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext3);
    ciphertext3.he_level = ciphertext3.he_level - 1;
    ckksInstance->evaluator->modDownToMin(ciphertext1, ciphertext3);
    ckksInstance->evaluator->modDownToMin(ciphertext3, ciphertext2);
    // Expect he_level is changed.
    ASSERT_EQ(ciphertext3.he_level, ciphertext2.he_level);
    ASSERT_EQ(ciphertext3.he_level, ciphertext1.he_level);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, ModDownToLevel) {
    CKKSInstance* ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    int he_level = ciphertext1.he_level;
    ciphertext2 = ckksInstance->evaluator->modDownToLevel(ciphertext1, he_level - 1);
    // Expect he_level is changed.
    ASSERT_EQ(he_level - 1, ciphertext2.he_level);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, ModDownToLevel_InvalidCase) {
    CKKSInstance* ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    int he_level = ciphertext1.he_level;
    ASSERT_THROW((
                     // Expect invalid_argument is thrown when cipherText is mod to higher level.
                     ckksInstance->evaluator->modDownToLevel(ciphertext1, he_level + 1)),
                 invalid_argument);
}

TEST(DepthFinderTest, RescaleToNextInPlace) {
    CKKSInstance* ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    int he_level = ciphertext1.he_level;
    ckksInstance->evaluator->rescale_to_next_inplace(ciphertext1);
    ASSERT_EQ(he_level - 1, ciphertext1.he_level);
    ASSERT_EQ(1, ckksInstance->getMultiplicativeDepth());
}
