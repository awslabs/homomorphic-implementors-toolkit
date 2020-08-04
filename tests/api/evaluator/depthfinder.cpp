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
    CKKSInstance *ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->rotate_vector_left(ciphertext1, STEPS);
    // Expect heLevel does not change.
    ASSERT_EQ(ciphertext2.heLevel, ciphertext1.heLevel);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, RotateVectorRight) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->rotate_vector_right(ciphertext1, STEPS);
    // Expect heLevel does not change.
    ASSERT_EQ(ciphertext2.heLevel, ciphertext1.heLevel);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, AddPlainScalar) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->add_plain_scalar(ciphertext1, PLAIN_TEXT);
    // Expect heLevel does not change.
    ASSERT_EQ(ciphertext2.heLevel, ciphertext1.heLevel);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, Add) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext2);
    ciphertext3 = ckksInstance->evaluator->add(ciphertext1, ciphertext2);
    // Expect heLevel does not change.
    ASSERT_EQ(ciphertext3.heLevel, ciphertext1.heLevel);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, AddCiphertextWithDiffHeLevel) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext2);
    ciphertext2.heLevel = ciphertext1.heLevel + 1;
    ASSERT_THROW((
        // Expect invalid_argument is thrown because heLevel of the two ciphertexts is different.
        ckksInstance->evaluator->add(ciphertext1, ciphertext2)
        ), invalid_argument);
}

TEST(DepthFinderTest, MultiplyPlainScalar) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->multiply_plain_scalar(ciphertext1, PLAIN_TEXT);
    // Expect heLevel does not change.
    ASSERT_EQ(ciphertext2.heLevel, ciphertext1.heLevel);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, MultiplyPlainMattrix) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, 1, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->multiply_plain_mat(ciphertext1, VECTOR_1);
    // Expect heLevel does not change.
    ASSERT_EQ(ciphertext2.heLevel, ciphertext1.heLevel);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, Multiply) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext2);
    ciphertext3 = ckksInstance->evaluator->multiply(ciphertext1, ciphertext2);
    // Expect heLevel does not change.
    ASSERT_EQ(ciphertext3.heLevel, ciphertext1.heLevel);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, Multiply_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext2);
    ciphertext2.heLevel = ciphertext1.heLevel + 1;
    ASSERT_THROW((
        // Expect invalid_argument is thrown because heLevel of the two ciphertexts is different.
        ckksInstance->evaluator->multiply(ciphertext1, ciphertext2)
        ), invalid_argument);
}

TEST(DepthFinderTest, Square) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->square(ciphertext1);
    // Expect heLevel does not change.
    ASSERT_EQ(ciphertext2.heLevel, ciphertext1.heLevel);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, ModDownTo) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext2);
    int heLevel = ciphertext1.heLevel;
    ASSERT_EQ(heLevel, ciphertext2.heLevel);
    ciphertext1.heLevel = heLevel + 1;
    ckksInstance->evaluator->modDownTo(ciphertext1, ciphertext2);
    // Expect heLevel is changed.
    ASSERT_EQ(heLevel, ciphertext1.heLevel);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, ModDownTo_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext2);
    ciphertext2.heLevel = ciphertext1.heLevel + 1;
    ASSERT_THROW((
        // Expect invalid_argument is thrown because the heLevel of second argument is larger.
        ckksInstance->evaluator->modDownTo(ciphertext1, ciphertext2)
        ), invalid_argument);
}

TEST(DepthFinderTest, ModDownToMin) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext2);
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext3);
    ciphertext3.heLevel = ciphertext3.heLevel - 1;
    ckksInstance->evaluator->modDownToMin(ciphertext1, ciphertext3);
    ckksInstance->evaluator->modDownToMin(ciphertext3, ciphertext2);
    // Expect heLevel is changed.
    ASSERT_EQ(ciphertext3.heLevel, ciphertext2.heLevel);
    ASSERT_EQ(ciphertext3.heLevel, ciphertext1.heLevel);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, ModDownToLevel) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    int heLevel = ciphertext1.heLevel;
    ciphertext2 = ckksInstance->evaluator->modDownToLevel(ciphertext1, heLevel - 1);
    // Expect heLevel is changed.
    ASSERT_EQ(heLevel - 1, ciphertext2.heLevel);
    ASSERT_EQ(0, ckksInstance->getMultiplicativeDepth());
}

TEST(DepthFinderTest, ModDownToLevel_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    int heLevel = ciphertext1.heLevel;
    ASSERT_THROW((
        // Expect invalid_argument is thrown when cipherText is mod to higher level.
        ckksInstance->evaluator->modDownToLevel(ciphertext1, heLevel + 1)
        ), invalid_argument);
}

TEST(DepthFinderTest, RescaleToNextInPlace) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewDepthFinderInstance(VERBOSE);
    CKKSCiphertext ciphertext1;
    ckksInstance->encryptRowVec(VECTOR_1, SIZE, ciphertext1);
    int heLevel = ciphertext1.heLevel;
    ckksInstance->evaluator->rescale_to_next_inplace(ciphertext1);
    ASSERT_EQ(heLevel - 1, ciphertext1.heLevel);
    ASSERT_EQ(1, ckksInstance->getMultiplicativeDepth());
}
