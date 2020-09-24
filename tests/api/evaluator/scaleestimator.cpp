// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include "../../testutil.h"
#include "gtest/gtest.h"
#include "hit/api/evaluator/scaleestimator.h"
#include "hit/api/ciphertext.h"
#include "hit/common.h"
#include "hit/sealutils.h"
#include "seal/seal.h"

using namespace std;
using namespace hit;

// Test variables.
const int DEFAULT_LOG_SCALE = 30;
const int NUM_OF_SLOTS = 4096;
const int ZERO_MULTI_DEPTH = 0;
const int ONE_MULTI_DEPTH = 1;
const int TWO_MULTI_DEPTH = 2;
const double VALUE = 4;
const double PLAIN_TEXT = 2;
const int STEPS = 1;
const vector<double> VECTOR_1(NUM_OF_SLOTS, VALUE);

TEST(ScaleEstimatorTest, RotateLeft) {
    ScaleEstimator ckks_instance = ScaleEstimator(NUM_OF_SLOTS, ZERO_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    double estimatedMaxLogScale = ckks_instance.get_estimated_max_log_scale();
    ciphertext2 = ckks_instance.rotate_left(ciphertext1, STEPS);
    // Expect estimatedMaxLogScale does not change.
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance.get_estimated_max_log_scale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, RotateRight) {
    ScaleEstimator ckks_instance = ScaleEstimator(NUM_OF_SLOTS, ZERO_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    double estimatedMaxLogScale = ckks_instance.get_estimated_max_log_scale();
    ciphertext2 = ckks_instance.rotate_right(ciphertext1, STEPS);
    // Expect estimatedMaxLogScale does not change.
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance.get_estimated_max_log_scale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, Negate) {
    ScaleEstimator ckks_instance = ScaleEstimator(NUM_OF_SLOTS, ZERO_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    double estimatedMaxLogScale = ckks_instance.get_estimated_max_log_scale();
    ciphertext2 = ckks_instance.negate(ciphertext1);
    // Expect estimatedMaxLogScale does not change.
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance.get_estimated_max_log_scale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, AddPlaintext) {
    ScaleEstimator ckks_instance = ScaleEstimator(NUM_OF_SLOTS, ZERO_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.add_plain(ciphertext1, VECTOR_1);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE + l_inf_norm(VECTOR_1));
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance.get_estimated_max_log_scale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, AddPlainScalar) {
    ScaleEstimator ckks_instance = ScaleEstimator(NUM_OF_SLOTS, ZERO_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.add_plain(ciphertext1, PLAIN_TEXT);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE + PLAIN_TEXT);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance.get_estimated_max_log_scale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, Add) {
    ScaleEstimator ckks_instance = ScaleEstimator(NUM_OF_SLOTS, ZERO_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.encrypt(VECTOR_1);
    ciphertext3 = ckks_instance.add(ciphertext1, ciphertext2);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE + VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance.get_estimated_max_log_scale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, SubPlaintext) {
    ScaleEstimator ckks_instance = ScaleEstimator(NUM_OF_SLOTS, ZERO_MULTI_DEPTH);
    vector<double> randomVector1 = random_vector(NUM_OF_SLOTS, VALUE);
    vector<double> randomVector2 = random_vector(NUM_OF_SLOTS, VALUE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(randomVector1);
    ciphertext2 = ckks_instance.sub_plain(ciphertext1, randomVector2);
    // Expect estimatedMaxLogScale is changed.
    vector<double> result(NUM_OF_SLOTS);
    transform(randomVector1.begin(), randomVector1.end(), randomVector2.begin(), result.begin(), minus<>());
    double maxlInf = max(l_inf_norm(result), l_inf_norm(randomVector1));
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(maxlInf);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance.get_estimated_max_log_scale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, SubPlainScalar) {
    ScaleEstimator ckks_instance = ScaleEstimator(NUM_OF_SLOTS, ZERO_MULTI_DEPTH);
    vector<double> randomVector1 = random_vector(NUM_OF_SLOTS, VALUE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(randomVector1);
    ciphertext2 = ckks_instance.sub_plain(ciphertext1, VALUE);
    vector<double> result(NUM_OF_SLOTS);
    transform(randomVector1.begin(), randomVector1.end(), VECTOR_1.begin(), result.begin(), minus<>());
    // Expect estimatedMaxLogScale is changed.
    double maxlInf = max(l_inf_norm(result), l_inf_norm(randomVector1));
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(maxlInf);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance.get_estimated_max_log_scale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, Sub) {
    ScaleEstimator ckks_instance = ScaleEstimator(NUM_OF_SLOTS, ZERO_MULTI_DEPTH);
    vector<double> randomVector1 = random_vector(NUM_OF_SLOTS, VALUE);
    vector<double> randomVector2 = random_vector(NUM_OF_SLOTS, VALUE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance.encrypt(randomVector1);
    ciphertext2 = ckks_instance.encrypt(randomVector2);
    ciphertext3 = ckks_instance.sub(ciphertext1, ciphertext2);
    vector<double> result(NUM_OF_SLOTS);
    transform(randomVector1.begin(), randomVector1.end(), randomVector2.begin(), result.begin(), minus<>());
    // Expect estimatedMaxLogScale is changed.
    double maxlInf = max(max(l_inf_norm(result), l_inf_norm(randomVector1)), l_inf_norm(randomVector2));
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(maxlInf);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance.get_estimated_max_log_scale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, MultiplyPlainScalar) {
    ScaleEstimator ckks_instance = ScaleEstimator(NUM_OF_SLOTS, ONE_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.multiply_plain(ciphertext1, PLAIN_TEXT);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE * PLAIN_TEXT);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance.get_estimated_max_log_scale());
    ASSERT_EQ(ONE_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, MultiplyPlainMattrix) {
    ScaleEstimator ckks_instance = ScaleEstimator(NUM_OF_SLOTS, ONE_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.multiply_plain(ciphertext1, VECTOR_1);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE * VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance.get_estimated_max_log_scale());
    ASSERT_EQ(ONE_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, Multiply) {
    ScaleEstimator ckks_instance = ScaleEstimator(NUM_OF_SLOTS, ONE_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.encrypt(VECTOR_1);
    ciphertext3 = ckks_instance.multiply(ciphertext1, ciphertext2);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE * VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance.get_estimated_max_log_scale());
    ASSERT_EQ(ONE_MULTI_DEPTH, ciphertext3.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2), ciphertext3.scale());
}

TEST(ScaleEstimatorTest, Square) {
    ScaleEstimator ckks_instance = ScaleEstimator(NUM_OF_SLOTS, ONE_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.square(ciphertext1);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE * VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance.get_estimated_max_log_scale());
    ASSERT_EQ(ONE_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, ReduceLevelTo) {
    ScaleEstimator ckks_instance = ScaleEstimator(NUM_OF_SLOTS, ONE_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    uint64_t prime = get_last_prime(ckks_instance.context, ciphertext1.he_level());
    ciphertext2 = ckks_instance.reduce_level_to(ciphertext1, ZERO_MULTI_DEPTH);
    // Check estimatedMaxLogScale.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance.get_estimated_max_log_scale());
    // Expect he_level is decreased.
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    // Check scale.
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2) / prime, ciphertext2.scale());
}

// TODO: investigate why previous impl can still pass this test.
TEST(ScaleEstimatorTest, ReduceLevelTo_MultiDepthIsTwo) {
    ScaleEstimator ckks_instance = ScaleEstimator(NUM_OF_SLOTS, TWO_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1, TWO_MULTI_DEPTH);
    ciphertext3 = ckks_instance.encrypt(VECTOR_1, ZERO_MULTI_DEPTH);
    ciphertext2 = ckks_instance.reduce_level_to(ciphertext1, ZERO_MULTI_DEPTH);
    // Expect he_level is decreased.
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    // Check scale.
    ASSERT_EQ(ciphertext3.scale(), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, ReduceLevelToMin) {
    ScaleEstimator ckks_instance = ScaleEstimator(NUM_OF_SLOTS, ONE_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext3 = ciphertext1;
    uint64_t prime = get_last_prime(ckks_instance.context, ciphertext1.he_level());
    ciphertext2 = ckks_instance.reduce_level_to(ciphertext1, ZERO_MULTI_DEPTH);
    ckks_instance.reduce_level_to_min_inplace(ciphertext1, ciphertext2);
    // Check estimatedMaxLogScale.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance.get_estimated_max_log_scale());
    // Expect he_level is decreased.
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext1.he_level());
    // Check scale.
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2) / prime, ciphertext1.scale());
    // Test reduce_level_to_min_inplace symmetric.
    ckks_instance.reduce_level_to_min_inplace(ciphertext2, ciphertext3);
    // Check estimatedMaxLogScale.
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance.get_estimated_max_log_scale());
    // Expect he_level is decreased.
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext3.he_level());
    // Check scale.
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2) / prime, ciphertext3.scale());
}

TEST(ScaleEstimatorTest, RescaleToNextInPlace) {
    ScaleEstimator ckks_instance = ScaleEstimator(NUM_OF_SLOTS, ONE_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance.encrypt(VECTOR_1);
    ciphertext2 = ckks_instance.square(ciphertext1);
    uint64_t prime = get_last_prime(ckks_instance.context, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2), ciphertext2.scale());
    ckks_instance.rescale_to_next_inplace(ciphertext2);
    // Check scale.
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2) / prime, ciphertext2.scale());
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE * VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance.get_estimated_max_log_scale());
}
