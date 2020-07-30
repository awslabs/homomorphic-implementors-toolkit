// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include "gtest/gtest.h"
#include "seal/seal.h"

#include "sealutils.h"
#include "CKKSInstance.h"
#include "api/ciphertext.h"
#include "common.h"
#include "sealutils.h"

using namespace std;

// Test variables.
const bool VERBOSE = false;
const int NUM_OF_SLOTS = 4096;
const int WIDTH = 1;
const int ZERO_MULTI_DEPTH = 0;
const int ONE_MULTI_DEPTH = 1;
const int LOG_SCALE = 25;
const double PLAIN_TEXT = 2;
const double VALUE = 4;
const double INI_PLAIN_MAX_LOG = -100;
const int STEPS = 1;
const vector<double> VECTOR_1(NUM_OF_SLOTS, VALUE);

void compare(const vector<double> &expected, const vector<double> &actual, const double precision = 0.1) {
    ASSERT_EQ(expected.size(), actual.size());
    for (int i = 0; i < expected.size(); i++) {
        ASSERT_LE(abs(expected[i] - actual[i]), precision);
    }
}

TEST(HomomorphicTest, RotateVectorLeft) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewHomomorphicInstance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE, VERBOSE);
    CKKSCiphertext ciphertext1;
    vector<double> vector1(NUM_OF_SLOTS, VALUE);
    double newValue = VALUE * 2;
    vector1[0] = newValue;
    ckksInstance->encryptRowVec(vector1, WIDTH, ciphertext1);
    CKKSCiphertext ciphertext2 = ckksInstance->evaluator->rotate_vector_left(ciphertext1, STEPS);
    vector<double> vector2 = ckksInstance->decrypt(ciphertext2, VERBOSE);
    vector<double> vector3(NUM_OF_SLOTS, VALUE);
    // Expect vector is rotated.
    vector3[NUM_OF_SLOTS - 1] = newValue;
    compare(vector3, vector2);
}

TEST(HomomorphicTest, RotateVectorLeft_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewHomomorphicInstance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE, VERBOSE);
    CKKSCiphertext ciphertext1;
    ASSERT_THROW((
        // Expect invalid_argument is thrown because the rotate step should not be negative.
        ckksInstance->evaluator->rotate_vector_left(ciphertext1, -1)
        ), invalid_argument);

}

TEST(HomomorphicTest, RotateVectorRight) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewHomomorphicInstance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE, VERBOSE);
    CKKSCiphertext ciphertext1;
    vector<double> vector1(NUM_OF_SLOTS, VALUE);
    double newValue = VALUE * 2;
    vector1[0] = newValue;
    ckksInstance->encryptRowVec(vector1, WIDTH, ciphertext1);
    CKKSCiphertext ciphertext2 = ckksInstance->evaluator->rotate_vector_right(ciphertext1, STEPS);
    vector<double> vector2 = ckksInstance->decrypt(ciphertext2, VERBOSE);
    vector<double> vector3(NUM_OF_SLOTS, VALUE);
    // Expect vector is rotated.
    vector3[1] = newValue;
    compare(vector3, vector2);
}

TEST(HomomorphicTest, RotateVectorRight_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewHomomorphicInstance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE, VERBOSE);
    CKKSCiphertext ciphertext1;
    ASSERT_THROW((
        // Expect invalid_argument is thrown because the rotate step should not be negative.
        ckksInstance->evaluator->rotate_vector_right(ciphertext1, -1)
        ), invalid_argument);
}

// TODO: add more tests to cover invalid and corner cases from evaluator.cpp.
TEST(HomomorphicTest, Add) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewHomomorphicInstance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext2);
    CKKSCiphertext ciphertext3 = ckksInstance->evaluator->add(ciphertext1, ciphertext2);
    vector<double> vector2 = ckksInstance->decrypt(ciphertext3, VERBOSE);
    vector<double> vector3(NUM_OF_SLOTS, VALUE + VALUE);
    // Check vector values.
    compare(vector3, vector2);
}

TEST(HomomorphicTest, AddPlainScalar) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewHomomorphicInstance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->add_plain_scalar(ciphertext1, PLAIN_TEXT);
    vector<double> vector2 = ckksInstance->decrypt(ciphertext2, VERBOSE);
    vector<double> vector3(NUM_OF_SLOTS, VALUE + PLAIN_TEXT);
    // Check vector values.
    compare(vector3, vector2);
}

TEST(HomomorphicTest, MultiplyPlainScalar) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewHomomorphicInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->multiply_plain_scalar(ciphertext1, PLAIN_TEXT);
    vector<double> vector2 = ckksInstance->decrypt(ciphertext2, VERBOSE);
    vector<double> vector3(NUM_OF_SLOTS, VALUE * PLAIN_TEXT);
    // Check vector values.
    compare(vector3, vector2);
}

TEST(HomomorphicTest, MultiplyPlainMattrix) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewHomomorphicInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE, VERBOSE);
    CKKSCiphertext ciphertext1;
    ckksInstance->encryptRowVec(VECTOR_1, 1, ciphertext1);
    CKKSCiphertext ciphertext2 = ckksInstance->evaluator->multiply_plain_mat(ciphertext1, VECTOR_1);
    vector<double> vector2 = ckksInstance->decrypt(ciphertext2, VERBOSE);
    vector<double> vector3(NUM_OF_SLOTS, VALUE * VALUE);
    // Check vector values.
    compare(vector3, vector2);
}

TEST(HomomorphicTest, MultiplyPlainMattrix_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewHomomorphicInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE, VERBOSE);
    CKKSCiphertext ciphertext1;
    ckksInstance->encryptRowVec(VECTOR_1, 1, ciphertext1);
    vector<double> vector2(1, VALUE * VALUE);
    ASSERT_THROW((
        // Expect invalid_argument is thrown because encoded size does not match plaintext input.
        ckksInstance->evaluator->multiply_plain_mat(ciphertext1, vector2)
        ), invalid_argument);
}

TEST(HomomorphicTest, Multiply) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewHomomorphicInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext2);
    CKKSCiphertext ciphertext3 = ckksInstance->evaluator->multiply(ciphertext1, ciphertext2);
    vector<double> vector2 = ckksInstance->decrypt(ciphertext3, VERBOSE);
    vector<double> vector3(NUM_OF_SLOTS, VALUE * VALUE);
    // Check vector values.
    compare(vector3, vector2);
}

TEST(HomomorphicTest, Constructor_ScaleBelowLowerBounds) {
    ASSERT_THROW((
        // Expect invalid_argument is thrown because the scale is less than the minimum, 22.
        CKKSInstance::getNewHomomorphicInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, 21, VERBOSE)
        ), invalid_argument);
}

TEST(HomomorphicTest, Square) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewHomomorphicInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE, VERBOSE);
    CKKSCiphertext ciphertext1;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    CKKSCiphertext ciphertext2 = ckksInstance->evaluator->square(ciphertext1);
    vector<double> vector2 = ckksInstance->decrypt(ciphertext2, VERBOSE);
    vector<double> vector3(NUM_OF_SLOTS, VALUE * VALUE);
    // Check vector values.
    compare(vector3, vector2);
}

TEST(HomomorphicTest, ModDownToLevel) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewHomomorphicInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->modDownToLevel(ciphertext1, ZERO_MULTI_DEPTH);
    // Check vector values.
    vector<double> vector2(NUM_OF_SLOTS, VALUE);
    vector<double> vector3 = ckksInstance->decrypt(ciphertext2, VERBOSE);
    double diff = diff2Norm(vector2, vector3);
    ASSERT_NE(diff, -1);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, ModDownToLevel_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewHomomorphicInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE, VERBOSE);
    CKKSCiphertext ciphertext1;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ASSERT_THROW((
        // Expect invalid_argument is thrown when the level is higher.
        ckksInstance->evaluator->modDownToLevel(ciphertext1, ONE_MULTI_DEPTH + 1)
        ), invalid_argument);
}

TEST(HomomorphicTest, ModDownTo) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewHomomorphicInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->modDownToLevel(ciphertext1, ZERO_MULTI_DEPTH);
    ckksInstance->evaluator->modDownTo(ciphertext1, ciphertext2);
    // Check vector values.
    vector<double> vector2(NUM_OF_SLOTS, VALUE);
    vector<double> vector3 = ckksInstance->decrypt(ciphertext1, VERBOSE);
    double diff = diff2Norm(vector2, vector3);
    ASSERT_NE(diff, -1);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, ModDownTo_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewHomomorphicInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->modDownToLevel(ciphertext1, ZERO_MULTI_DEPTH);
    ASSERT_THROW((
        // Expect invalid_argument is thrown when the level is higher.
        ckksInstance->evaluator->modDownTo(ciphertext2, ciphertext1)
        ), invalid_argument);
}

TEST(HomomorphicTest, ModDownToMin) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewHomomorphicInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ciphertext3 = ciphertext1;
    ciphertext2 = ckksInstance->evaluator->modDownToLevel(ciphertext1, ZERO_MULTI_DEPTH);
    ckksInstance->evaluator->modDownToMin(ciphertext1, ciphertext2);
    ckksInstance->evaluator->modDownToMin(ciphertext2, ciphertext3);
    // Check vector values.
    vector<double> vector2(NUM_OF_SLOTS, VALUE);
    vector<double> vector3 = ckksInstance->decrypt(ciphertext1, VERBOSE);
    double diff1 = diff2Norm(vector2, vector3);
    ASSERT_NE(diff1, -1);
    ASSERT_LE(diff1, MAX_NORM);
    vector<double> vector4 = ckksInstance->decrypt(ciphertext3, VERBOSE);
    double diff2 = diff2Norm(vector2, vector4);
    ASSERT_NE(diff2, -1);
    ASSERT_LE(diff2, MAX_NORM);
}

TEST(HomomorphicTest, RescaleToNextInPlace) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewHomomorphicInstance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ckksInstance->encryptRowVec(VECTOR_1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->square(ciphertext1);
    ckksInstance->evaluator->relinearize_inplace(ciphertext2);
    uint64_t prime = getLastPrime(ckksInstance->context, ciphertext2.heLevel);
    ckksInstance->evaluator->rescale_to_next_inplace(ciphertext2);
    // Check scale.
    ASSERT_LE(abs(pow(2, LOG_SCALE * 2)/prime - ciphertext2.scale), 0.1);
    // Check vector values.
    vector<double> vector2(NUM_OF_SLOTS, VALUE * VALUE);
    vector<double> vector3 = ckksInstance->decrypt(ciphertext2, VERBOSE);
    double diff = diff2Norm(vector2, vector3);
    ASSERT_LE(abs(diff), 0.1);
}
