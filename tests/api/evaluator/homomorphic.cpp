// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include "../../testutil.h"
#include "gtest/gtest.h"
#include "hit/api/evaluator/homomorphic.h"
#include "hit/api/ciphertext.h"
#include "hit/common.h"
#include "hit/sealutils.h"

using namespace std;
using namespace hit;

// Test variables.
const int RANGE = 16;
const int NUM_OF_SLOTS = 4096;
const int ZERO_MULTI_DEPTH = 0;
const int ONE_MULTI_DEPTH = 1;
const int LOG_SCALE = 30;
const double VALUE1 = 4;
const double INVALID_NORM = -1;
const int STEPS = 1;
const vector<double> VECTOR_1(NUM_OF_SLOTS, VALUE1);

TEST(HomomorphicTest, RotateLeft) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
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
    // Check scale and he_level.
    ASSERT_EQ(ciphertext2.he_level(), ZERO_MULTI_DEPTH);
    ASSERT_EQ(ciphertext2.scale(), pow(2, LOG_SCALE));
    // Expect vector is rotated.
    vector<double> vector3 = ckks_instance.decrypt(ciphertext2);
    double diff = diff2_norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, RotateLeft_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1;
    ASSERT_THROW((
                     // Expect invalid_argument is thrown because the rotate step should not be negative.
                     ckks_instance.rotate_left(ciphertext1, -1)),
                 invalid_argument);
}

TEST(HomomorphicTest, RotateRight) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
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
    // Check scale and he_level.
    ASSERT_EQ(ciphertext2.he_level(), ZERO_MULTI_DEPTH);
    ASSERT_EQ(ciphertext2.scale(), pow(2, LOG_SCALE));
    // Expect vector is rotated.
    vector<double> vector3 = ckks_instance.decrypt(ciphertext2);
    double diff = diff2_norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, RotateRight_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1;
    ASSERT_THROW((
                     // Expect invalid_argument is thrown because the rotate step should not be negative.
                     ckks_instance.rotate_right(ciphertext1, -1)),
                 invalid_argument);
}

TEST(HomomorphicTest, Negate) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckks_instance.encrypt(vector1);
    vector<double> vector2(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), negate<>());
    ciphertext3 = ckks_instance.negate(ciphertext1);
    // Check scale and he_level.
    ASSERT_EQ(ciphertext3.he_level(), ZERO_MULTI_DEPTH);
    ASSERT_EQ(ciphertext3.scale(), pow(2, LOG_SCALE));
    // Check vector values.
    vector<double> vector3 = ckks_instance.decrypt(ciphertext3);
    double diff = diff2_norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, Add_Two) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = random_vector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckks_instance.encrypt(vector1);
    ciphertext2 = ckks_instance.encrypt(vector2);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), plus<>());
    ciphertext3 = ckks_instance.add(ciphertext1, ciphertext2);
    // Check scale and he_level.
    ASSERT_EQ(ciphertext3.he_level(), ZERO_MULTI_DEPTH);
    ASSERT_EQ(ciphertext3.scale(), pow(2, LOG_SCALE));
    // Check vector values.
    vector<double> vector4 = ckks_instance.decrypt(ciphertext3);
    double diff = diff2_norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, AddPlainScalar) {
    double plaintext = (double)create_random_positive_int();
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2(NUM_OF_SLOTS, plaintext);
    ciphertext1 = ckks_instance.encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), plus<>());
    ciphertext2 = ckks_instance.add_plain(ciphertext1, plaintext);
    // Check scale and he_level.
    ASSERT_EQ(ciphertext2.he_level(), ZERO_MULTI_DEPTH);
    ASSERT_EQ(ciphertext2.scale(), pow(2, LOG_SCALE));
    // Check vector values.
    vector<double> vector4 = ckks_instance.decrypt(ciphertext2);
    double diff = diff2_norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, AddPlaintext) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = random_vector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckks_instance.encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), plus<>());
    ciphertext2 = ckks_instance.add_plain(ciphertext1, vector2);
    // Check scale and he_level.
    ASSERT_EQ(ciphertext2.he_level(), ZERO_MULTI_DEPTH);
    ASSERT_EQ(ciphertext2.scale(), pow(2, LOG_SCALE));
    // Check vector values.
    vector<double> vector4 = ckks_instance.decrypt(ciphertext2);
    double diff = diff2_norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, Sub_Two) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = random_vector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckks_instance.encrypt(vector1);
    ciphertext2 = ckks_instance.encrypt(vector2);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), minus<>());
    ciphertext3 = ckks_instance.sub(ciphertext1, ciphertext2);
    // Check scale and he_level.
    ASSERT_EQ(ciphertext3.he_level(), ZERO_MULTI_DEPTH);
    ASSERT_EQ(ciphertext3.scale(), pow(2, LOG_SCALE));
    // Check vector values.
    vector<double> vector4 = ckks_instance.decrypt(ciphertext3);
    double diff = diff2_norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, SubPlainScalar) {
    double plaintext = (double)create_random_positive_int();
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2(NUM_OF_SLOTS, plaintext);
    ciphertext1 = ckks_instance.encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), minus<>());
    ciphertext2 = ckks_instance.sub_plain(ciphertext1, plaintext);
    // Check scale and he_level.
    ASSERT_EQ(ciphertext2.he_level(), ZERO_MULTI_DEPTH);
    ASSERT_EQ(ciphertext2.scale(), pow(2, LOG_SCALE));
    // Check vector values.
    vector<double> vector4 = ckks_instance.decrypt(ciphertext2);
    double diff = diff2_norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, SubPlaintext) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = random_vector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckks_instance.encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), minus<>());
    ciphertext2 = ckks_instance.sub_plain(ciphertext1, vector2);
    // Check scale and he_level.
    ASSERT_EQ(ciphertext2.he_level(), ZERO_MULTI_DEPTH);
    ASSERT_EQ(ciphertext2.scale(), pow(2, LOG_SCALE));
    // Check vector values.
    vector<double> vector4 = ckks_instance.decrypt(ciphertext2);
    double diff = diff2_norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, MultiplyPlainScalar) {
    double plaintext = (double)create_random_positive_int();
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2(NUM_OF_SLOTS, plaintext);
    ciphertext1 = ckks_instance.encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), multiplies<>());
    ciphertext2 = ckks_instance.multiply_plain(ciphertext1, plaintext);
    // Check scale and he_level.
    ASSERT_EQ(ciphertext2.he_level(), ONE_MULTI_DEPTH);
    ASSERT_EQ(ciphertext2.scale(), pow(2, LOG_SCALE * 2));
    // Check vector values.
    vector<double> vector4 = ckks_instance.decrypt(ciphertext2);
    double diff = diff2_norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, MultiplyPlainMattrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = random_vector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckks_instance.encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), multiplies<>());
    ciphertext2 = ckks_instance.multiply_plain(ciphertext1, vector2);
    // Check scale and he_level.
    ASSERT_EQ(ciphertext2.he_level(), ONE_MULTI_DEPTH);
    ASSERT_EQ(ciphertext2.scale(), pow(2, LOG_SCALE * 2));
    // Check vector values.
    vector<double> vector4 = ckks_instance.decrypt(ciphertext2);
    double diff = diff2_norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, MultiplyPlainMattrix_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1, 1);
    vector<double> vector2(1, VALUE1 * VALUE1);
    ASSERT_THROW((
                     // Expect invalid_argument is thrown because encoded size does not match plaintext input.
                     ckks_instance.multiply_plain(ciphertext1, vector2)),
                 invalid_argument);
}

TEST(HomomorphicTest, Multiply) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = random_vector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckks_instance.encrypt(vector1);
    ciphertext2 = ckks_instance.encrypt(vector2);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), multiplies<>());
    ciphertext3 = ckks_instance.multiply(ciphertext1, ciphertext2);
    // Check scale and he_level.
    ASSERT_EQ(ciphertext3.he_level(), ONE_MULTI_DEPTH);
    ASSERT_EQ(ciphertext3.scale(), pow(2, LOG_SCALE * 2));
    // Check vector values.
    vector<double> vector4 = ckks_instance.decrypt(ciphertext3);
    double diff = diff2_norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, Constructor_ScaleBelowLowerBounds) {
    ASSERT_THROW((
                     // Expect invalid_argument is thrown because the scale is less than the minimum, 22.
                     HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, 21)),
                 invalid_argument);
}

TEST(HomomorphicTest, Square) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckks_instance.encrypt(vector1);
    vector<double> vector2(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector1.begin(), vector2.begin(), multiplies<>());
    ciphertext2 = ckks_instance.square(ciphertext1);
    // Check scale and he_level.
    ASSERT_EQ(ciphertext2.he_level(), ONE_MULTI_DEPTH);
    ASSERT_EQ(ciphertext2.scale(), pow(2, LOG_SCALE * 2));
    // Check vector values.
    vector<double> vector3 = ckks_instance.decrypt(ciphertext2);
    double diff = diff2_norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, ModDownToLevel) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckks_instance.encrypt(vector1);
    ciphertext2 = ckks_instance.mod_down_to_level(ciphertext1, ZERO_MULTI_DEPTH);
    // Check scale and he_level.
    ASSERT_EQ(ciphertext2.he_level(), ZERO_MULTI_DEPTH);
    uint64_t prime = get_last_prime(ckks_instance.context, ONE_MULTI_DEPTH);
    ASSERT_EQ(ciphertext2.scale(), pow(2, LOG_SCALE * 2) / prime);
    // Check vector values.
    vector<double> vector2 = ckks_instance.decrypt(ciphertext2);
    double diff = diff2_norm(vector1, vector2);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, ModDownToLevel_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ASSERT_THROW((
                     // Expect invalid_argument is thrown when the level is higher.
                     ckks_instance.mod_down_to_level(ciphertext1, ONE_MULTI_DEPTH)),
                 invalid_argument);
}

TEST(HomomorphicTest, ModDownToMin) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckks_instance.encrypt(vector1);
    ciphertext3 = ciphertext1;
    ciphertext2 = ckks_instance.mod_down_to_level(ciphertext1, ZERO_MULTI_DEPTH);
    ckks_instance.mod_down_to_min_inplace(ciphertext1, ciphertext2);
    ckks_instance.mod_down_to_min_inplace(ciphertext2, ciphertext3);
    // Check scale and he_level.
    ASSERT_EQ(ciphertext3.he_level(), ZERO_MULTI_DEPTH);
    uint64_t prime = get_last_prime(ckks_instance.context, ONE_MULTI_DEPTH);
    ASSERT_EQ(ciphertext3.scale(), pow(2, LOG_SCALE * 2) / prime);
    // Check vector values.
    vector<double> vector2 = ckks_instance.decrypt(ciphertext1);
    double diff1 = diff2_norm(vector1, vector2);
    ASSERT_NE(diff1, INVALID_NORM);
    ASSERT_LE(diff1, MAX_NORM);
    vector<double> vector3 = ckks_instance.decrypt(ciphertext3);
    double diff2 = diff2_norm(vector1, vector3);
    ASSERT_NE(diff2, INVALID_NORM);
    ASSERT_LE(diff2, MAX_NORM);
}

TEST(HomomorphicTest, RescaleToNextInPlace) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector1.begin(), vector2.begin(), multiplies<>());
    ciphertext1 = ckks_instance.encrypt(vector1);
    ciphertext2 = ckks_instance.square(ciphertext1);
    ckks_instance.relinearize_inplace(ciphertext2);
    ckks_instance.rescale_to_next_inplace(ciphertext2);
    // Check scale and he_level.
    ASSERT_EQ(ciphertext2.he_level(), ZERO_MULTI_DEPTH);
    uint64_t prime = get_last_prime(ckks_instance.context, ONE_MULTI_DEPTH);
    ASSERT_EQ(ciphertext2.scale(), pow(2, LOG_SCALE * 2) / prime);
    // Check vector values.
    vector<double> vector3 = ckks_instance.decrypt(ciphertext2);
    double diff = diff2_norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}
