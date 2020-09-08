// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include "../../testutil.h"
#include "gtest/gtest.h"
#include "hit/CKKSInstance.h"
#include "hit/api/ciphertext.h"
#include "hit/common.h"
#include "../../testutil.h"

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
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
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
    vector<double> vector3 = ckksInstance->decrypt(ciphertext2);
    // Expect vector is rotated.
    double diff = diff2Norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, RotateLeft_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1;
    ASSERT_THROW((
                     // Expect invalid_argument is thrown because the rotate step should not be negative.
                     ckksInstance->evaluator->rotate_left(ciphertext1, -1)),
                 invalid_argument);
}

TEST(HomomorphicTest, RotateRight) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
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
    vector<double> vector3 = ckksInstance->decrypt(ciphertext2);
    // Expect vector is rotated.
    double diff = diff2Norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, RotateRight_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1;
    ASSERT_THROW((
                     // Expect invalid_argument is thrown because the rotate step should not be negative.
                     ckksInstance->evaluator->rotate_right(ciphertext1, -1)),
                 invalid_argument);
}

TEST(HomomorphicTest, Negate) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckksInstance->encrypt(vector1);
    vector<double> vector2(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), negate<>());
    ciphertext3 = ckksInstance->evaluator->negate(ciphertext1);
    vector<double> vector3 = ckksInstance->decrypt(ciphertext3);
    // Check vector values.
    double diff = diff2Norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, Add_Two) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = randomVector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckksInstance->encrypt(vector1);
    ciphertext2 = ckksInstance->encrypt(vector2);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), plus<>());
    ciphertext3 = ckksInstance->evaluator->add(ciphertext1, ciphertext2);
    vector<double> vector4 = ckksInstance->decrypt(ciphertext3);
    // Check vector values.
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, AddPlainScalar) {
    double plaintext = (double)createRandomPositiveInt();
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2(NUM_OF_SLOTS, plaintext);
    ciphertext1 = ckksInstance->encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), plus<>());
    ciphertext2 = ckksInstance->evaluator->add_plain(ciphertext1, plaintext);
    vector<double> vector4 = ckksInstance->decrypt(ciphertext2);
    // Check vector values.
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, AddPlaintext) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = randomVector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckksInstance->encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), plus<>());
    ciphertext2 = ckksInstance->evaluator->add_plain(ciphertext1, vector2);
    vector<double> vector4 = ckksInstance->decrypt(ciphertext2);
    // Check vector values.
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, Sub_Two) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = randomVector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckksInstance->encrypt(vector1);
    ciphertext2 = ckksInstance->encrypt(vector2);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), minus<>());
    ciphertext3 = ckksInstance->evaluator->sub(ciphertext1, ciphertext2);
    vector<double> vector4 = ckksInstance->decrypt(ciphertext3);
    // Check vector values.
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, SubPlainScalar) {
    double plaintext = (double)createRandomPositiveInt();
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2(NUM_OF_SLOTS, plaintext);
    ciphertext1 = ckksInstance->encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), minus<>());
    ciphertext2 = ckksInstance->evaluator->sub_plain(ciphertext1, plaintext);
    vector<double> vector4 = ckksInstance->decrypt(ciphertext2);
    // Check vector values.
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, SubPlaintext) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = randomVector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckksInstance->encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), minus<>());
    ciphertext2 = ckksInstance->evaluator->sub_plain(ciphertext1, vector2);
    vector<double> vector4 = ckksInstance->decrypt(ciphertext2);
    // Check vector values.
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, MultiplyPlainScalar) {
    double plaintext = (double)createRandomPositiveInt();
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2(NUM_OF_SLOTS, plaintext);
    ciphertext1 = ckksInstance->encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), multiplies<>());
    ciphertext2 = ckksInstance->evaluator->multiply_plain(ciphertext1, plaintext);
    vector<double> vector4 = ckksInstance->decrypt(ciphertext2);
    // Check vector values.
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, MultiplyPlainMattrix) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = randomVector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckksInstance->encrypt(vector1);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), multiplies<>());
    ciphertext2 = ckksInstance->evaluator->multiply_plain(ciphertext1, vector2);
    vector<double> vector4 = ckksInstance->decrypt(ciphertext2);
    // Check vector values.
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, MultiplyPlainMattrix_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1, 1);
    vector<double> vector2(1, VALUE1 * VALUE1);
    ASSERT_THROW((
                     // Expect invalid_argument is thrown because encoded size does not match plaintext input.
                     ckksInstance->evaluator->multiply_plain(ciphertext1, vector2)),
                 invalid_argument);
}

TEST(HomomorphicTest, Multiply) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2 = randomVector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckksInstance->encrypt(vector1);
    ciphertext2 = ckksInstance->encrypt(vector2);
    vector<double> vector3(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector2.begin(), vector3.begin(), multiplies<>());
    ciphertext3 = ckksInstance->evaluator->multiply(ciphertext1, ciphertext2);
    vector<double> vector4 = ckksInstance->decrypt(ciphertext3);
    // Check vector values.
    double diff = diff2Norm(vector3, vector4);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, Constructor_ScaleBelowLowerBounds) {
    ASSERT_THROW((
                     // Expect invalid_argument is thrown because the scale is less than the minimum, 22.
                     CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, 21)),
                 invalid_argument);
}

TEST(HomomorphicTest, Square) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckksInstance->encrypt(vector1);
    vector<double> vector2(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector1.begin(), vector2.begin(), multiplies<>());
    ciphertext2 = ckksInstance->evaluator->square(ciphertext1);
    vector<double> vector3 = ckksInstance->decrypt(ciphertext2);
    // Check vector values.
    double diff = diff2Norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, ModDownToLevel) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckksInstance->encrypt(vector1);
    ciphertext2 = ckksInstance->evaluator->mod_down_to_level(ciphertext1, ZERO_MULTI_DEPTH);
    // Check vector values.
    vector<double> vector2 = ckksInstance->decrypt(ciphertext2);
    double diff = diff2Norm(vector1, vector2);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, ModDownToLevel_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ASSERT_THROW((
                     // Expect invalid_argument is thrown when the level is higher.
                     ckksInstance->evaluator->mod_down_to_level(ciphertext1, ONE_MULTI_DEPTH)),
                 invalid_argument);
}

TEST(HomomorphicTest, ModDownTo) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckksInstance->encrypt(vector1);
    ciphertext2 = ckksInstance->evaluator->mod_down_to_level(ciphertext1, ZERO_MULTI_DEPTH);
    ckksInstance->evaluator->mod_down_to(ciphertext1, ciphertext2);
    // Check vector values.
    vector<double> vector2 = ckksInstance->decrypt(ciphertext1);
    double diff = diff2Norm(vector1, vector2);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}

TEST(HomomorphicTest, ModDownTo_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckksInstance->encrypt(VECTOR_1);
    ciphertext2 = ckksInstance->evaluator->mod_down_to_level(ciphertext1, ZERO_MULTI_DEPTH);
    ASSERT_THROW((
                     // Expect invalid_argument is thrown when the level is higher.
                     ckksInstance->evaluator->mod_down_to(ciphertext2, ciphertext1)),
                 invalid_argument);
}

TEST(HomomorphicTest, ModDownToMin) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    ciphertext1 = ckksInstance->encrypt(vector1);
    ciphertext3 = ciphertext1;
    ciphertext2 = ckksInstance->evaluator->mod_down_to_level(ciphertext1, ZERO_MULTI_DEPTH);
    ckksInstance->evaluator->mod_down_to_min_inplace(ciphertext1, ciphertext2);
    ckksInstance->evaluator->mod_down_to_min_inplace(ciphertext2, ciphertext3);
    // Check vector values.
    vector<double> vector2 = ckksInstance->decrypt(ciphertext1);
    double diff1 = diff2Norm(vector1, vector2);
    ASSERT_NE(diff1, INVALID_NORM);
    ASSERT_LE(diff1, MAX_NORM);
    vector<double> vector3 = ckksInstance->decrypt(ciphertext3);
    double diff2 = diff2Norm(vector1, vector3);
    ASSERT_NE(diff2, INVALID_NORM);
    ASSERT_LE(diff2, MAX_NORM);
}

TEST(HomomorphicTest, RescaleToNextInPlace) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    vector<double> vector2(NUM_OF_SLOTS);
    transform(vector1.begin(), vector1.end(), vector1.begin(), vector2.begin(), multiplies<>());
    ciphertext1 = ckksInstance->encrypt(vector1);
    ciphertext2 = ckksInstance->evaluator->square(ciphertext1);
    ckksInstance->evaluator->relinearize_inplace(ciphertext2);
    ckksInstance->evaluator->rescale_to_next_inplace(ciphertext2);
    // Check vector values.
    vector<double> vector3 = ckksInstance->decrypt(ciphertext2);
    double diff = diff2Norm(vector2, vector3);
    ASSERT_NE(diff, INVALID_NORM);
    ASSERT_LE(diff, MAX_NORM);
}
