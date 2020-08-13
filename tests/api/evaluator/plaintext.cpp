// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include "gtest/gtest.h"
#include "seal/seal.h"

#include "../../testutil.h"
#include "CKKSInstance.h"
#include "api/ciphertext.h"
#include "common.h"

using namespace std;

// Test variables.
const bool VERBOSE = false;
const int RANGE = 16;
const int NUM_OF_SLOTS = 4096;
const int WIDTH = 1;
const double INVALID_NORM = -1;
const int STEPS = 1;

TEST(PlainTextTest, RotateVectorLeft) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2;
    vector2.reserve(NUM_OF_SLOTS);
    for (int i = 1; i < NUM_OF_SLOTS; i++) {
        vector2.push_back(vector1[i]);
    }
    vector2.push_back(vector1[0]);
    ckksInstance->encryptRowVec(vector1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->rotate_vector_left(ciphertext1, STEPS);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector2)), ckksInstance->getExactMaxLogPlainVal());
    // Check Diff2Norm.
    vector<double> vector3 = ciphertext2.encoded_pt.data();
    double diff = diff2Norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, RotateVectorRight) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2;
    vector2.reserve(NUM_OF_SLOTS);
    vector2.push_back(vector1[NUM_OF_SLOTS - 1]);
    for (int i = 0; i < NUM_OF_SLOTS - 1; i++) {
        vector2.push_back(vector1[i]);
    }
    ckksInstance->encryptRowVec(vector1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->rotate_vector_right(ciphertext1, STEPS);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector2)), ckksInstance->getExactMaxLogPlainVal());
    // Check Diff2Norm.
    vector<double> vector3 = ciphertext2.encoded_pt.data();
    double diff = diff2Norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, Add) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = randomVector(NUM_OF_SLOTS, RANGE);
    ckksInstance->encryptRowVec(vector1, WIDTH, ciphertext1);
    ckksInstance->encryptRowVec(vector2, WIDTH, ciphertext2);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), plus<>());
    ciphertext3 = ckksInstance->evaluator->add(ciphertext1, ciphertext2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector3)), ckksInstance->getExactMaxLogPlainVal());
    // Check Diff2Norm.
    vector<double> vector4 = ciphertext3.encoded_pt.data();
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, AddPlainScalar) {
    double plaintext = (double)createRandomPositiveInt();
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2(NUM_OF_SLOTS, plaintext);
    ckksInstance->encryptRowVec(vector1, WIDTH, ciphertext1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), plus<>());
    ciphertext2 = ckksInstance->evaluator->add_plain_scalar(ciphertext1, plaintext);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector3)), ckksInstance->getExactMaxLogPlainVal());
    // Check Diff2Norm.
    vector<double> vector4 = ciphertext2.encoded_pt.data();
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, MultiplyPlainScalar) {
    double plaintext = (double)createRandomPositiveInt();
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2(NUM_OF_SLOTS, plaintext);
    ckksInstance->encryptRowVec(vector1, WIDTH, ciphertext1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), multiplies<>());
    ciphertext2 = ckksInstance->evaluator->multiply_plain_scalar(ciphertext1, plaintext);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector3)), ckksInstance->getExactMaxLogPlainVal());
    // Check Diff2Norm.
    vector<double> vector4 = ciphertext2.encoded_pt.data();
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, MultiplyPlainMattrix) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = randomVector(NUM_OF_SLOTS, RANGE);
    ckksInstance->encryptRowVec(vector1, WIDTH, ciphertext1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), multiplies<>());
    ciphertext2 = ckksInstance->evaluator->multiply_plain_mat(ciphertext1, vector2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector3)), ckksInstance->getExactMaxLogPlainVal());
    // Check Diff2Norm.
    vector<double> vector4 = ciphertext2.encoded_pt.data();
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, Multiply) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = randomVector(NUM_OF_SLOTS, RANGE);
    ckksInstance->encryptRowVec(vector1, WIDTH, ciphertext1);
    ckksInstance->encryptRowVec(vector2, WIDTH, ciphertext2);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), multiplies<>());
    ciphertext3 = ckksInstance->evaluator->multiply(ciphertext1, ciphertext2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector3)), ckksInstance->getExactMaxLogPlainVal());
    // Check Diff2Norm.
    vector<double> vector4 = ciphertext3.encoded_pt.data();
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, Square) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    ckksInstance->encryptRowVec(vector1, WIDTH, ciphertext1);
    vector<double> vector2(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector1.begin(), vector2.begin(), multiplies<>());
    ciphertext2 = ckksInstance->evaluator->square(ciphertext1);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector2)), ckksInstance->getExactMaxLogPlainVal());
    // Check Diff2Norm.
    vector<double> vector3 = ciphertext2.encoded_pt.data();
    double diff = diff2Norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}
