// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include "gtest/gtest.h"
#include "seal/seal.h"

#include "api/ciphertext.h"
#include "CKKSInstance.h"

using namespace std;

// Test variables.
const bool VERBOSE = false;
const int NUM_OF_SLOTS = 4096;
const int WIDTH = 1;
const double PLAIN_TEXT = 2;
const double VALUE = 4;
const double INI_PLAIN_MAX_LOG = -100;
const int STEPS = 1;
const vector<double> VECTOR_1(NUM_OF_SLOTS, VALUE);

TEST(PlainTextTest, RotateVectorLeft) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->rotate_vector_left(ciphertext1, STEPS);
    // Check MaxLogPlainVal.
    ASSERT_EQ(INI_PLAIN_MAX_LOG, ckksInstance->getExactMaxLogPlainVal());
}

TEST(PlainTextTest, RotateVectorRight) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->rotate_vector_right(ciphertext1, STEPS);
    // Check MaxLogPlainVal.
    ASSERT_EQ(INI_PLAIN_MAX_LOG, ckksInstance->getExactMaxLogPlainVal());
}

TEST(PlainTextTest, Add) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext2);
    ciphertext3 = ckksInstance->evaluator->add(ciphertext1, ciphertext2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(VALUE * 2), ckksInstance->getExactMaxLogPlainVal());
}

TEST(PlainTextTest, AddPlainScalar) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext2);
    ciphertext3 = ckksInstance->evaluator->add_plain_scalar(ciphertext1, PLAIN_TEXT);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(VALUE + PLAIN_TEXT), ckksInstance->getExactMaxLogPlainVal());
}

TEST(PlainTextTest, MultiplyPlainScalar) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext2);
    ciphertext3 = ckksInstance->evaluator->multiply_plain_scalar(ciphertext1, PLAIN_TEXT);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(VALUE * PLAIN_TEXT), ckksInstance->getExactMaxLogPlainVal());
}

TEST(PlainTextTest, MultiplyPlainMattrix) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, 1, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->multiply_plain_mat(ciphertext1, VECTOR_1);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(VALUE * VALUE), ckksInstance->getExactMaxLogPlainVal());
}

TEST(PlainTextTest, Multiply) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
;    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext2);
    ciphertext3 = ckksInstance->evaluator->multiply(ciphertext1, ciphertext2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(VALUE * VALUE), ckksInstance->getExactMaxLogPlainVal());
}

TEST(PlainTextTest, Square) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->square(ciphertext1);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(VALUE * VALUE), ckksInstance->getExactMaxLogPlainVal());
}
