// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include "../../testutil.h"
#include "gtest/gtest.h"
#include "hit/api/evaluator/plaintext.h"
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

TEST(PlaintextTest, RotateLeft) {
    PlaintextEval ckks_instance = PlaintextEval(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2;
    vector2.reserve(NUM_OF_SLOTS);
    for (int i = 1; i < NUM_OF_SLOTS; i++) {
        vector2.push_back(vector1[i]);
    }
    vector2.push_back(vector1[0]);
    ciphertext1 = ckks_instance.encrypt(vector1);
    ciphertext2 = ckks_instance.rotate_left(ciphertext1, STEPS);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(l_inf_norm(vector2)), ckks_instance.get_exact_max_log_plain_val());
    // Check diff2_norm.
    vector<double> vector3 = ciphertext2.plaintext();
    double diff = diff2_norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlaintextTest, RotateRight) {
    PlaintextEval ckks_instance = PlaintextEval(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2;
    vector2.reserve(NUM_OF_SLOTS);
    vector2.push_back(vector1[NUM_OF_SLOTS - 1]);
    for (int i = 0; i < NUM_OF_SLOTS - 1; i++) {
        vector2.push_back(vector1[i]);
    }
    ciphertext1 = ckks_instance.encrypt(vector1);
    ciphertext2 = ckks_instance.rotate_right(ciphertext1, STEPS);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(l_inf_norm(vector2)), ckks_instance.get_exact_max_log_plain_val());
    // Check diff2_norm.
    vector<double> vector3 = ciphertext2.plaintext();
    double diff = diff2_norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlaintextTest, Negate) {
    PlaintextEval ckks_instance = PlaintextEval(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), negate<>());
    ciphertext1 = ckks_instance.encrypt(vector1);
    ciphertext2 = ckks_instance.negate(ciphertext1);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(l_inf_norm(vector2)), ckks_instance.get_exact_max_log_plain_val());
    // Check diff2_norm.
    vector<double> vector3 = ciphertext2.plaintext();
    double diff = diff2_norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlaintextTest, Add) {
    PlaintextEval ckks_instance = PlaintextEval(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = random_vector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckks_instance.encrypt(vector1);
    ciphertext2 = ckks_instance.encrypt(vector2);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), plus<>());
    ciphertext3 = ckks_instance.add(ciphertext1, ciphertext2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(l_inf_norm(vector3)), ckks_instance.get_exact_max_log_plain_val());
    // Check diff2_norm.
    vector<double> vector4 = ciphertext3.plaintext();
    double diff = diff2_norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlaintextTest, AddPlaintext) {
    PlaintextEval ckks_instance = PlaintextEval(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = random_vector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckks_instance.encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), plus<>());
    ciphertext2 = ckks_instance.add_plain(ciphertext1, vector2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(l_inf_norm(vector3)), ckks_instance.get_exact_max_log_plain_val());
    // Check diff2_norm.
    vector<double> vector4 = ciphertext2.plaintext();
    double diff = diff2_norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlaintextTest, AddPlainScalar) {
    double plaintext = (double)create_random_positive_int();
    PlaintextEval ckks_instance = PlaintextEval(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2(NUM_OF_SLOTS, plaintext);
    ciphertext1 = ckks_instance.encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), plus<>());
    ciphertext2 = ckks_instance.add_plain(ciphertext1, plaintext);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(l_inf_norm(vector3)), ckks_instance.get_exact_max_log_plain_val());
    // Check diff2_norm.
    vector<double> vector4 = ciphertext2.plaintext();
    double diff = diff2_norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlaintextTest, Sub) {
    PlaintextEval ckks_instance = PlaintextEval(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = random_vector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckks_instance.encrypt(vector1);
    ciphertext2 = ckks_instance.encrypt(vector2);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), minus<>());
    ciphertext3 = ckks_instance.sub(ciphertext1, ciphertext2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(l_inf_norm(vector3)), ckks_instance.get_exact_max_log_plain_val());
    // Check diff2_norm.
    vector<double> vector4 = ciphertext3.plaintext();
    double diff = diff2_norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlaintextTest, SubPlaintext) {
    PlaintextEval ckks_instance = PlaintextEval(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = random_vector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckks_instance.encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), minus<>());
    ciphertext2 = ckks_instance.sub_plain(ciphertext1, vector2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(l_inf_norm(vector3)), ckks_instance.get_exact_max_log_plain_val());
    // Check diff2_norm.
    vector<double> vector4 = ciphertext2.plaintext();
    double diff = diff2_norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlaintextTest, SubPlainScalar) {
    double plaintext = (double)create_random_positive_int();
    PlaintextEval ckks_instance = PlaintextEval(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2(NUM_OF_SLOTS, plaintext);
    ciphertext1 = ckks_instance.encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), minus<>());
    ciphertext2 = ckks_instance.sub_plain(ciphertext1, plaintext);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(l_inf_norm(vector3)), ckks_instance.get_exact_max_log_plain_val());
    // Check diff2_norm.
    vector<double> vector4 = ciphertext2.plaintext();
    double diff = diff2_norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlaintextTest, MultiplyPlainScalar) {
    double plaintext = (double)create_random_positive_int();
    PlaintextEval ckks_instance = PlaintextEval(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2(NUM_OF_SLOTS, plaintext);
    ciphertext1 = ckks_instance.encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), multiplies<>());
    ciphertext2 = ckks_instance.multiply_plain(ciphertext1, plaintext);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(l_inf_norm(vector3)), ckks_instance.get_exact_max_log_plain_val());
    // Check diff2_norm.
    vector<double> vector4 = ciphertext2.plaintext();
    double diff = diff2_norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlaintextTest, MultiplyPlainMattrix) {
    PlaintextEval ckks_instance = PlaintextEval(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = random_vector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckks_instance.encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), multiplies<>());
    ciphertext2 = ckks_instance.multiply_plain(ciphertext1, vector2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(l_inf_norm(vector3)), ckks_instance.get_exact_max_log_plain_val());
    // Check diff2_norm.
    vector<double> vector4 = ciphertext2.plaintext();
    double diff = diff2_norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlaintextTest, Multiply) {
    PlaintextEval ckks_instance = PlaintextEval(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = random_vector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckks_instance.encrypt(vector1);
    ciphertext2 = ckks_instance.encrypt(vector2);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), multiplies<>());
    ciphertext3 = ckks_instance.multiply(ciphertext1, ciphertext2);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(l_inf_norm(vector3)), ckks_instance.get_exact_max_log_plain_val());
    // Check diff2_norm.
    vector<double> vector4 = ciphertext3.plaintext();
    double diff = diff2_norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(PlaintextTest, Square) {
    PlaintextEval ckks_instance = PlaintextEval(NUM_OF_SLOTS);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckks_instance.encrypt(vector1);
    vector<double> vector2(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector1.begin(), vector2.begin(), multiplies<>());
    ciphertext2 = ckks_instance.square(ciphertext1);
    // Check MaxLogPlainVal.
    ASSERT_EQ(log2(l_inf_norm(vector2)), ckks_instance.get_exact_max_log_plain_val());
    // Check diff2_norm.
    vector<double> vector3 = ciphertext2.plaintext();
    double diff = diff2_norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}
