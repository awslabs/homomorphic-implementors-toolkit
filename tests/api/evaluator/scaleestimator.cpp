// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include "seal/seal.h"
#include "gtest/gtest.h"

#include "CKKSInstance.h"
#include "sealutils.h"
#include "api/ciphertext.h"

// Test variables.
const bool VERBOSE = false;
const int DEFAULT_LOG_SCALE = 30;
const int WIDTH = 1;
const int NUM_OF_SLOTS = 4096;
const int ZERO_MULTI_DEPTH = 0;
const int ONE_MULTI_DEPTH = 1;
const int TWO_MULTI_DEPTH = 2;
const double PLAINTEXT_LOG_MAX = 59;
const double VALUE = 4;
const double PLAIN_TEXT = 2;
const int STEPS = 1;
const std::vector<double> VECTOR_1(NUM_OF_SLOTS, VALUE);

TEST(ScaleEstimatorTest, RotateVectorLeft) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewScaleEstimatorInstance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    double estimatedMaxLogScale = ckksInstance->getEstimatedMaxLogScale();
    ciphertext2 = ckksInstance->evaluator->rotate_vector_left(ciphertext1, STEPS);
    // Expect estimatedMaxLogScale does not change.
    ASSERT_EQ(estimatedMaxLogScale, ckksInstance->getEstimatedMaxLogScale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.heLevel);
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale);
}

TEST(ScaleEstimatorTest, RotateVectorRight) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewScaleEstimatorInstance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    double estimatedMaxLogScale = ckksInstance->getEstimatedMaxLogScale();
    ciphertext2 = ckksInstance->evaluator->rotate_vector_right(ciphertext1, STEPS);
    // Expect estimatedMaxLogScale does not change.
    ASSERT_EQ(estimatedMaxLogScale, ckksInstance->getEstimatedMaxLogScale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.heLevel);
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale);
}

TEST(ScaleEstimatorTest, AddPlainScalar) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewScaleEstimatorInstance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->add_plain_scalar(ciphertext1, PLAIN_TEXT);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE + PLAIN_TEXT);
    ASSERT_EQ(estimatedMaxLogScale, ckksInstance->getEstimatedMaxLogScale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.heLevel);
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale);
}

TEST(ScaleEstimatorTest, Add) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewScaleEstimatorInstance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext2);
    ciphertext3 = ckksInstance->evaluator->add(ciphertext1, ciphertext2);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE + VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckksInstance->getEstimatedMaxLogScale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.heLevel);
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale);
}

TEST(ScaleEstimatorTest, MultiplyPlainScalar) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewScaleEstimatorInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->multiply_plain_scalar(ciphertext1, PLAIN_TEXT);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE * PLAIN_TEXT);
    ASSERT_EQ(estimatedMaxLogScale, ckksInstance->getEstimatedMaxLogScale());
    ASSERT_EQ(ONE_MULTI_DEPTH, ciphertext2.heLevel);
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2), ciphertext2.scale);
}

TEST(ScaleEstimatorTest, MultiplyPlainMattrix) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewScaleEstimatorInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->multiply_plain_mat(ciphertext1, VECTOR_1);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE * VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckksInstance->getEstimatedMaxLogScale());
    ASSERT_EQ(ONE_MULTI_DEPTH, ciphertext2.heLevel);
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2), ciphertext2.scale);
}

TEST(ScaleEstimatorTest, Multiply) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewScaleEstimatorInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext2);
    ciphertext3 = ckksInstance->evaluator->multiply(ciphertext1, ciphertext2);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE * VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckksInstance->getEstimatedMaxLogScale());
    ASSERT_EQ(ONE_MULTI_DEPTH, ciphertext3.heLevel);
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2), ciphertext3.scale);
}

TEST(ScaleEstimatorTest, Square) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewScaleEstimatorInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->square(ciphertext1);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE * VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckksInstance->getEstimatedMaxLogScale());
    ASSERT_EQ(ONE_MULTI_DEPTH, ciphertext2.heLevel);
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2), ciphertext2.scale);
}

TEST(ScaleEstimatorTest, ModDownToLevel) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewScaleEstimatorInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    uint64_t prime = getLastPrime(ckksInstance->context, ciphertext1.heLevel);
    ciphertext2 = ckksInstance->evaluator->modDownToLevel(ciphertext1, ZERO_MULTI_DEPTH);
    // Check estimatedMaxLogScale.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckksInstance->getEstimatedMaxLogScale());
    // Expect heLevel is decreased.
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.heLevel);
    // Check scale.
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2)/prime, ciphertext2.scale);
}

// TODO: investigate why previous impl can still pass this test.
TEST(ScaleEstimatorTest, ModDownToLevel_MultiDepthIsTwo) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewScaleEstimatorInstance(NUM_OF_SLOTS, TWO_MULTI_DEPTH, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1, TWO_MULTI_DEPTH);
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext3, ZERO_MULTI_DEPTH);
    ciphertext2 = ckksInstance->evaluator->modDownToLevel(ciphertext1, ZERO_MULTI_DEPTH);
    // Expect heLevel is decreased.
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.heLevel);
    // Check scale.
    ASSERT_EQ(ciphertext3.scale, ciphertext2.scale);
}

TEST(ScaleEstimatorTest, ModDownTo) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewScaleEstimatorInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    uint64_t prime = getLastPrime(ckksInstance->context, ciphertext1.heLevel);
    ciphertext2 = ckksInstance->evaluator->modDownToLevel(ciphertext1, ZERO_MULTI_DEPTH);
    ckksInstance->evaluator->modDownTo(ciphertext1, ciphertext2);
    // Check estimatedMaxLogScale.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckksInstance->getEstimatedMaxLogScale());
    // Expect heLevel is decreased.
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext1.heLevel);
    // Check scale.
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2)/prime, ciphertext1.scale);
}

TEST(ScaleEstimatorTest, ModDownToMin) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewScaleEstimatorInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ciphertext3 = ciphertext1;
    uint64_t prime = getLastPrime(ckksInstance->context, ciphertext1.heLevel);
    ciphertext2 = ckksInstance->evaluator->modDownToLevel(ciphertext1, ZERO_MULTI_DEPTH);
    ckksInstance->evaluator->modDownToMin(ciphertext1, ciphertext2);
    // Check estimatedMaxLogScale.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckksInstance->getEstimatedMaxLogScale());
    // Expect heLevel is decreased.
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext1.heLevel);
    // Check scale.
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2)/prime, ciphertext1.scale);
    // Test modDownToMin symmetric.
    ckksInstance->evaluator->modDownToMin(ciphertext2, ciphertext3);
    // Check estimatedMaxLogScale.
    ASSERT_EQ(estimatedMaxLogScale, ckksInstance->getEstimatedMaxLogScale());
    // Expect heLevel is decreased.
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext3.heLevel);
    // Check scale.
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2)/prime, ciphertext3.scale);
}

TEST(ScaleEstimatorTest, RescaleToNextInPlace) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewScaleEstimatorInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->square(ciphertext1);
    uint64_t prime = getLastPrime(ckksInstance->context, ciphertext2.heLevel);
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2), ciphertext2.scale);
    ckksInstance->evaluator->rescale_to_next_inplace(ciphertext2);
    // Check scale.
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2)/prime, ciphertext2.scale);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE * VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckksInstance->getEstimatedMaxLogScale());
}
