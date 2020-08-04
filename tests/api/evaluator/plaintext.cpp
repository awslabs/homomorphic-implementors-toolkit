// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include "gtest/gtest.h"
#include "seal/seal.h"

#include "api/ciphertext.h"
#include "CKKSInstance.h"
#include "common.h"
#include "../../testutil.h"

using namespace std;

// Test variables.
const bool VERBOSE = false;
const int NUM_OF_SLOTS = 4096;
const int WIDTH = 1;
const double INI_PLAIN_MAX_LOG = -100;
const double INVALID_NORM = -1;
const int STEPS = 1;

TEST(PlainTextTest, RotateVectorLeft) {
    int range = createRandomPositiveInt();
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, range);
    int special_value = range + 1;
    vector1[0] = special_value;
    vector<double> vector2;
    vector2.reserve(NUM_OF_SLOTS);
    for (int i = 1; i < NUM_OF_SLOTS; i++) {
        vector2.push_back(vector1[i]);
    }
    vector2.push_back(special_value);
    ckksInstance->encryptRowVec(vector1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->rotate_vector_left(ciphertext1, STEPS);
    // Check MaxLogPlainVal.
    ASSERT_EQ(INI_PLAIN_MAX_LOG, ckksInstance->getExactMaxLogPlainVal());
    // Check Diff2Norm.
    vector<double> vector3 = ciphertext2.encoded_pt.data();
    double diff = diff2Norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, RotateVectorRight) {
    int range = createRandomPositiveInt();
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, range);
    vector<double> vector2;
    vector2.reserve(NUM_OF_SLOTS);
    vector2.push_back(vector1[NUM_OF_SLOTS - 1]);
    for (int i = 0; i < NUM_OF_SLOTS - 1; i++) {
        vector2.push_back(vector1[i]);
    }
    ckksInstance->encryptRowVec(vector1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->rotate_vector_right(ciphertext1, STEPS);
    // Check MaxLogPlainVal.
    ASSERT_EQ(INI_PLAIN_MAX_LOG, ckksInstance->getExactMaxLogPlainVal());
    // Check Diff2Norm.
    vector<double> vector3 = ciphertext2.encoded_pt.data();
    double diff = diff2Norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, Add) {
    int range = createRandomPositiveInt();
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, range);
    vector<double> vector2 = randomVector(NUM_OF_SLOTS, range);
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
    int range = createRandomPositiveInt();
    double plaintext = (double)createRandomPositiveInt();
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, range);
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
    int range = createRandomPositiveInt();
    double plaintext = (double)createRandomPositiveInt();
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, range);
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
    int range = createRandomPositiveInt();
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, range);
    vector<double> vector2 = randomVector(NUM_OF_SLOTS, range);
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
    int range = createRandomPositiveInt();
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, range);
    vector<double> vector2 = randomVector(NUM_OF_SLOTS, range);
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
    int range = createRandomPositiveInt();
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, range);
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
