// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include "../../testutil.h"
#include "gtest/gtest.h"
#include "hit/CKKSInstance.h"
#include "hit/api/ciphertext.h"
#include "hit/common.h"
#include "seal/seal.h"

using namespace std;
using namespace hit;

// Test variables.
const int RANGE = 16;
const int NUM_OF_SLOTS = 4096;
const double INVALID_NORM = -1;
const int STEPS = 1;

TEST(PlainTextTest, RotateLeft) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_plaintext_instance(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2;
    vector2.reserve(NUM_OF_SLOTS);
    for (int i = 1; i < NUM_OF_SLOTS; i++) {
        vector2.push_back(vector1[i]);
    }
    vector2.push_back(vector1[0]);
    ciphertext1 = ckksInstance->encrypt(vector1);
    ciphertext2 = ckksInstance->evaluator->rotate_left(ciphertext1, STEPS);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector2)), ckksInstance->get_exact_max_log_plain_val());
    // Check Diff2Norm.
    vector<double> vector3 = ciphertext2.raw_pt.data();
    double diff = diff2Norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, RotateRight) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_plaintext_instance(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2;
    vector2.reserve(NUM_OF_SLOTS);
    vector2.push_back(vector1[NUM_OF_SLOTS - 1]);
    for (int i = 0; i < NUM_OF_SLOTS - 1; i++) {
        vector2.push_back(vector1[i]);
    }
    ciphertext1 = ckksInstance->encrypt(vector1);
    ciphertext2 = ckksInstance->evaluator->rotate_right(ciphertext1, STEPS);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector2)), ckksInstance->get_exact_max_log_plain_val());
    // Check Diff2Norm.
    vector<double> vector3 = ciphertext2.raw_pt.data();
    double diff = diff2Norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, Negate) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_plaintext_instance(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), negate<>());
    ciphertext1 = ckksInstance->encrypt(vector1);
    ciphertext2 = ckksInstance->evaluator->negate(ciphertext1);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector2)), ckksInstance->get_exact_max_log_plain_val());
    // Check Diff2Norm.
    vector<double> vector3 = ciphertext2.raw_pt.data();
    double diff = diff2Norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, Add) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_plaintext_instance(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = randomVector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckksInstance->encrypt(vector1);
    ciphertext2 = ckksInstance->encrypt(vector2);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), plus<>());
    ciphertext3 = ckksInstance->evaluator->add(ciphertext1, ciphertext2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector3)), ckksInstance->get_exact_max_log_plain_val());
    // Check Diff2Norm.
    vector<double> vector4 = ciphertext3.raw_pt.data();
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, AddPlaintext) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_plaintext_instance(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = randomVector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckksInstance->encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), plus<>());
    ciphertext2 = ckksInstance->evaluator->add_plain(ciphertext1, vector2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector3)), ckksInstance->get_exact_max_log_plain_val());
    // Check Diff2Norm.
    vector<double> vector4 = ciphertext2.raw_pt.data();
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, AddPlainScalar) {
    double plaintext = (double)createRandomPositiveInt();
    CKKSInstance *ckksInstance = CKKSInstance::get_new_plaintext_instance(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2(NUM_OF_SLOTS, plaintext);
    ciphertext1 = ckksInstance->encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), plus<>());
    ciphertext2 = ckksInstance->evaluator->add_plain(ciphertext1, plaintext);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector3)), ckksInstance->get_exact_max_log_plain_val());
    // Check Diff2Norm.
    vector<double> vector4 = ciphertext2.raw_pt.data();
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, Sub) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_plaintext_instance(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = randomVector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckksInstance->encrypt(vector1);
    ciphertext2 = ckksInstance->encrypt(vector2);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), minus<>());
    ciphertext3 = ckksInstance->evaluator->sub(ciphertext1, ciphertext2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector3)), ckksInstance->get_exact_max_log_plain_val());
    // Check Diff2Norm.
    vector<double> vector4 = ciphertext3.raw_pt.data();
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, SubPlaintext) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_plaintext_instance(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = randomVector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckksInstance->encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), minus<>());
    ciphertext2 = ckksInstance->evaluator->sub_plain(ciphertext1, vector2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector3)), ckksInstance->get_exact_max_log_plain_val());
    // Check Diff2Norm.
    vector<double> vector4 = ciphertext2.raw_pt.data();
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, SubPlainScalar) {
    double plaintext = (double)createRandomPositiveInt();
    CKKSInstance *ckksInstance = CKKSInstance::get_new_plaintext_instance(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2(NUM_OF_SLOTS, plaintext);
    ciphertext1 = ckksInstance->encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), minus<>());
    ciphertext2 = ckksInstance->evaluator->sub_plain(ciphertext1, plaintext);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector3)), ckksInstance->get_exact_max_log_plain_val());
    // Check Diff2Norm.
    vector<double> vector4 = ciphertext2.raw_pt.data();
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, MultiplyPlainScalar) {
    double plaintext = (double)createRandomPositiveInt();
    CKKSInstance *ckksInstance = CKKSInstance::get_new_plaintext_instance(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2(NUM_OF_SLOTS, plaintext);
    ciphertext1 = ckksInstance->encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), multiplies<>());
    ciphertext2 = ckksInstance->evaluator->multiply_plain(ciphertext1, plaintext);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector3)), ckksInstance->get_exact_max_log_plain_val());
    // Check Diff2Norm.
    vector<double> vector4 = ciphertext2.raw_pt.data();
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, MultiplyPlainMattrix) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_plaintext_instance(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = randomVector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckksInstance->encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), multiplies<>());
    ciphertext2 = ckksInstance->evaluator->multiply_plain(ciphertext1, vector2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector3)), ckksInstance->get_exact_max_log_plain_val());
    // Check Diff2Norm.
    vector<double> vector4 = ciphertext2.raw_pt.data();
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, Multiply) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_plaintext_instance(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = randomVector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckksInstance->encrypt(vector1);
    ciphertext2 = ckksInstance->encrypt(vector2);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), multiplies<>());
    ciphertext3 = ckksInstance->evaluator->multiply(ciphertext1, ciphertext2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector3)), ckksInstance->get_exact_max_log_plain_val());
    // Check Diff2Norm.
    vector<double> vector4 = ciphertext3.raw_pt.data();
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlainTextTest, Square) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_plaintext_instance(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckksInstance->encrypt(vector1);
    vector<double> vector2(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector1.begin(), vector2.begin(), multiplies<>());
    ciphertext2 = ckksInstance->evaluator->square(ciphertext1);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(lInfNorm(vector2)), ckksInstance->get_exact_max_log_plain_val());
    // Check Diff2Norm.
    vector<double> vector3 = ciphertext2.raw_pt.data();
    double diff = diff2Norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}
