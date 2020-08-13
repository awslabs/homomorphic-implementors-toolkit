// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include "../../testutil.h"
#include "CKKSInstance.h"
#include "api/ciphertext.h"
#include "common.h"
#include "gtest/gtest.h"
#include "seal/seal.h"

using namespace std;
using namespace hit;

// Test variables.
const bool VERBOSE = false;
const int RANGE = 16;
const int NUM_OF_SLOTS = 4096;
const int WIDTH = 1;
const double INVALID_NORM = -1;
const int STEPS = 1;

TEST(PlainTextTest, RotateLeft) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> randomVector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> randomVector2;
    randomVector2.reserve(NUM_OF_SLOTS);
    for (int i = 1; i < NUM_OF_SLOTS; i++) {
        randomVector2.push_back(randomVector1[i]);
    }
    randomVector2.push_back(randomVector1[0]);
    ckksInstance->encryptRowVec(randomVector1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->rotate_left(ciphertext1, STEPS);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(randomVector2)), ckksInstance->getExactMaxLogPlainVal());
    // Check Diff2Norm.
    vector<double> randomVector3 = ciphertext2.encoded_pt.data();
    double diff = diff2Norm(randomVector2, randomVector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, RotateRight) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> randomVector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> randomVector2;
    randomVector2.reserve(NUM_OF_SLOTS);
    randomVector2.push_back(randomVector1[NUM_OF_SLOTS - 1]);
    for (int i = 0; i < NUM_OF_SLOTS - 1; i++) {
        randomVector2.push_back(randomVector1[i]);
    }
    ckksInstance->encryptRowVec(randomVector1, WIDTH, ciphertext1);
    ciphertext2 = ckksInstance->evaluator->rotate_right(ciphertext1, STEPS);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(randomVector2)), ckksInstance->getExactMaxLogPlainVal());
    // Check Diff2Norm.
    vector<double> randomVector3 = ciphertext2.encoded_pt.data();
    double diff = diff2Norm(randomVector2, randomVector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, Add) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> randomVector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> randomVector2 = randomVector(NUM_OF_SLOTS, RANGE);
    ckksInstance->encryptRowVec(randomVector1, WIDTH, ciphertext1);
    ckksInstance->encryptRowVec(randomVector2, WIDTH, ciphertext2);
    vector<double> randomVector3(NUM_OF_SLOTS);
    transform(randomVector1.begin(), randomVector1.end(), randomVector2.begin(), randomVector3.begin(), plus<>());
    ciphertext3 = ckksInstance->evaluator->add(ciphertext1, ciphertext2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(randomVector3)), ckksInstance->getExactMaxLogPlainVal());
    // Check Diff2Norm.
    vector<double> randomVector4 = ciphertext3.encoded_pt.data();
    double diff = diff2Norm(randomVector3, randomVector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, AddPlainScalar) {
    double plaintext = (double)createRandomPositiveInt();
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> randomVector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> randomVector2(NUM_OF_SLOTS, plaintext);
    ckksInstance->encryptRowVec(randomVector1, WIDTH, ciphertext1);
    vector<double> randomVector3(NUM_OF_SLOTS);
    transform(randomVector1.begin(), randomVector1.end(), randomVector2.begin(), randomVector3.begin(), plus<>());
    ciphertext2 = ckksInstance->evaluator->add_plain(ciphertext1, plaintext);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(randomVector3)), ckksInstance->getExactMaxLogPlainVal());
    // Check Diff2Norm.
    vector<double> randomVector4 = ciphertext2.encoded_pt.data();
    double diff = diff2Norm(randomVector3, randomVector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, MultiplyPlainScalar) {
    double plaintext = (double)createRandomPositiveInt();
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> randomVector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> randomVector2(NUM_OF_SLOTS, plaintext);
    ckksInstance->encryptRowVec(randomVector1, WIDTH, ciphertext1);
    vector<double> randomVector3(NUM_OF_SLOTS);
    transform(randomVector1.begin(), randomVector1.end(), randomVector2.begin(), randomVector3.begin(), multiplies<>());
    ciphertext2 = ckksInstance->evaluator->multiply_plain(ciphertext1, plaintext);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(randomVector3)), ckksInstance->getExactMaxLogPlainVal());
    // Check Diff2Norm.
    vector<double> randomVector4 = ciphertext2.encoded_pt.data();
    double diff = diff2Norm(randomVector3, randomVector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, MultiplyPlainMattrix) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> randomVector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> randomVector2 = randomVector(NUM_OF_SLOTS, RANGE);
    ckksInstance->encryptRowVec(randomVector1, WIDTH, ciphertext1);
    vector<double> randomVector3(NUM_OF_SLOTS);
    transform(randomVector1.begin(), randomVector1.end(), randomVector2.begin(), randomVector3.begin(), multiplies<>());
    ciphertext2 = ckksInstance->evaluator->multiply_plain(ciphertext1, randomVector2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(randomVector3)), ckksInstance->getExactMaxLogPlainVal());
    // Check Diff2Norm.
    vector<double> randomVector4 = ciphertext2.encoded_pt.data();
    double diff = diff2Norm(randomVector3, randomVector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, Multiply) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> randomVector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> randomVector2 = randomVector(NUM_OF_SLOTS, RANGE);
    ckksInstance->encryptRowVec(randomVector1, WIDTH, ciphertext1);
    ckksInstance->encryptRowVec(randomVector2, WIDTH, ciphertext2);
    vector<double> randomVector3(NUM_OF_SLOTS);
    transform(randomVector1.begin(), randomVector1.end(), randomVector2.begin(), randomVector3.begin(), multiplies<>());
    ciphertext3 = ckksInstance->evaluator->multiply(ciphertext1, ciphertext2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(randomVector3)), ckksInstance->getExactMaxLogPlainVal());
    // Check Diff2Norm.
    vector<double> randomVector4 = ciphertext3.encoded_pt.data();
    double diff = diff2Norm(randomVector3, randomVector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, Square) {
    CKKSInstance *ckksInstance = CKKSInstance::getNewPlaintextInstance(NUM_OF_SLOTS, VERBOSE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> randomVector1 = randomVector(NUM_OF_SLOTS, RANGE);
    ckksInstance->encryptRowVec(randomVector1, WIDTH, ciphertext1);
    vector<double> randomVector2(NUM_OF_SLOTS);
    transform(randomVector1.begin(), randomVector1.end(), randomVector1.begin(), randomVector2.begin(), multiplies<>());
    ciphertext2 = ckksInstance->evaluator->square(ciphertext1);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(randomVector2)), ckksInstance->getExactMaxLogPlainVal());
    // Check Diff2Norm.
    vector<double> randomVector3 = ciphertext2.encoded_pt.data();
    double diff = diff2Norm(randomVector2, randomVector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}
