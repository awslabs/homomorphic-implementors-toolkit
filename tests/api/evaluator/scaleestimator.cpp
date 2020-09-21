// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include "../../testutil.h"
#include "gtest/gtest.h"
#include "hit/CKKSInstance.h"
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
    CKKSInstance *ckks_instance = CKKSInstance::get_new_scaleestimator_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance->encrypt(VECTOR_1);
    double estimatedMaxLogScale = ckks_instance->get_estimated_max_log_scale();
    ciphertext2 = ckks_instance->evaluator->rotate_left(ciphertext1, STEPS);
    // Expect estimatedMaxLogScale does not change.
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance->get_estimated_max_log_scale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, RotateRight) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_scaleestimator_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance->encrypt(VECTOR_1);
    double estimatedMaxLogScale = ckks_instance->get_estimated_max_log_scale();
    ciphertext2 = ckks_instance->evaluator->rotate_right(ciphertext1, STEPS);
    // Expect estimatedMaxLogScale does not change.
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance->get_estimated_max_log_scale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, Negate) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_scaleestimator_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance->encrypt(VECTOR_1);
    double estimatedMaxLogScale = ckks_instance->get_estimated_max_log_scale();
    ciphertext2 = ckks_instance->evaluator->negate(ciphertext1);
    // Expect estimatedMaxLogScale does not change.
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance->get_estimated_max_log_scale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, AddPlaintext) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_scaleestimator_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance->encrypt(VECTOR_1);
    ciphertext2 = ckks_instance->evaluator->add_plain(ciphertext1, VECTOR_1);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE + l_inf_norm(VECTOR_1));
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance->get_estimated_max_log_scale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, AddPlainScalar) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_scaleestimator_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance->encrypt(VECTOR_1);
    ciphertext2 = ckks_instance->evaluator->add_plain(ciphertext1, PLAIN_TEXT);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE + PLAIN_TEXT);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance->get_estimated_max_log_scale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, Add) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_scaleestimator_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance->encrypt(VECTOR_1);
    ciphertext2 = ckks_instance->encrypt(VECTOR_1);
    ciphertext3 = ckks_instance->evaluator->add(ciphertext1, ciphertext2);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE + VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance->get_estimated_max_log_scale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, SubPlaintext) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_scaleestimator_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH);
    vector<double> randomVector1 = random_vector(NUM_OF_SLOTS, VALUE);
    vector<double> randomVector2 = random_vector(NUM_OF_SLOTS, VALUE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance->encrypt(randomVector1);
    ciphertext2 = ckks_instance->evaluator->sub_plain(ciphertext1, randomVector2);
    // Expect estimatedMaxLogScale is changed.
    vector<double> result(NUM_OF_SLOTS);
    transform(randomVector1.begin(), randomVector1.end(), randomVector2.begin(), result.begin(), minus<>());
    double maxlInf = max(l_inf_norm(result), l_inf_norm(randomVector1));
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(maxlInf);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance->get_estimated_max_log_scale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, SubPlainScalar) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_scaleestimator_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH);
    vector<double> randomVector1 = random_vector(NUM_OF_SLOTS, VALUE);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance->encrypt(randomVector1);
    ciphertext2 = ckks_instance->evaluator->sub_plain(ciphertext1, VALUE);
    vector<double> result(NUM_OF_SLOTS);
    transform(randomVector1.begin(), randomVector1.end(), VECTOR_1.begin(), result.begin(), minus<>());
    // Expect estimatedMaxLogScale is changed.
    double maxlInf = max(l_inf_norm(result), l_inf_norm(randomVector1));
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(maxlInf);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance->get_estimated_max_log_scale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, Sub) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_scaleestimator_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH);
    vector<double> randomVector1 = random_vector(NUM_OF_SLOTS, VALUE);
    vector<double> randomVector2 = random_vector(NUM_OF_SLOTS, VALUE);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance->encrypt(randomVector1);
    ciphertext2 = ckks_instance->encrypt(randomVector2);
    ciphertext3 = ckks_instance->evaluator->sub(ciphertext1, ciphertext2);
    vector<double> result(NUM_OF_SLOTS);
    transform(randomVector1.begin(), randomVector1.end(), randomVector2.begin(), result.begin(), minus<>());
    // Expect estimatedMaxLogScale is changed.
    double maxlInf = max(max(l_inf_norm(result), l_inf_norm(randomVector1)), l_inf_norm(randomVector2));
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(maxlInf);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance->get_estimated_max_log_scale());
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, MultiplyPlainScalar) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_scaleestimator_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance->encrypt(VECTOR_1);
    ciphertext2 = ckks_instance->evaluator->multiply_plain(ciphertext1, PLAIN_TEXT);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE * PLAIN_TEXT);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance->get_estimated_max_log_scale());
    ASSERT_EQ(ONE_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, MultiplyPlainMattrix) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_scaleestimator_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance->encrypt(VECTOR_1);
    ciphertext2 = ckks_instance->evaluator->multiply_plain(ciphertext1, VECTOR_1);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE * VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance->get_estimated_max_log_scale());
    ASSERT_EQ(ONE_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, Multiply) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_scaleestimator_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance->encrypt(VECTOR_1);
    ciphertext2 = ckks_instance->encrypt(VECTOR_1);
    ciphertext3 = ckks_instance->evaluator->multiply(ciphertext1, ciphertext2);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE * VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance->get_estimated_max_log_scale());
    ASSERT_EQ(ONE_MULTI_DEPTH, ciphertext3.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2), ciphertext3.scale());
}

TEST(ScaleEstimatorTest, Square) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_scaleestimator_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance->encrypt(VECTOR_1);
    ciphertext2 = ckks_instance->evaluator->square(ciphertext1);
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE * VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance->get_estimated_max_log_scale());
    ASSERT_EQ(ONE_MULTI_DEPTH, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, ModDownToLevel) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_scaleestimator_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2;
    ciphertext1 = ckks_instance->encrypt(VECTOR_1);
    uint64_t prime = get_last_prime(ckks_instance->context, ciphertext1.he_level());
    ciphertext2 = ckks_instance->evaluator->mod_down_to_level(ciphertext1, ZERO_MULTI_DEPTH);
    // Check estimatedMaxLogScale.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance->get_estimated_max_log_scale());
    // Expect he_level is decreased.
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    // Check scale.
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2) / prime, ciphertext2.scale());
}

// TODO: investigate why previous impl can still pass this test.
TEST(ScaleEstimatorTest, ModDownToLevel_MultiDepthIsTwo) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_scaleestimator_instance(NUM_OF_SLOTS, TWO_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance->encrypt(VECTOR_1, TWO_MULTI_DEPTH);
    ciphertext3 = ckks_instance->encrypt(VECTOR_1, ZERO_MULTI_DEPTH);
    ciphertext2 = ckks_instance->evaluator->mod_down_to_level(ciphertext1, ZERO_MULTI_DEPTH);
    // Expect he_level is decreased.
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext2.he_level());
    // Check scale.
    ASSERT_EQ(ciphertext3.scale(), ciphertext2.scale());
}

TEST(ScaleEstimatorTest, ModDownToMin) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_scaleestimator_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance->encrypt(VECTOR_1);
    ciphertext3 = ciphertext1;
    uint64_t prime = get_last_prime(ckks_instance->context, ciphertext1.he_level());
    ciphertext2 = ckks_instance->evaluator->mod_down_to_level(ciphertext1, ZERO_MULTI_DEPTH);
    ckks_instance->evaluator->mod_down_to_min_inplace(ciphertext1, ciphertext2);
    // Check estimatedMaxLogScale.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance->get_estimated_max_log_scale());
    // Expect he_level is decreased.
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext1.he_level());
    // Check scale.
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2) / prime, ciphertext1.scale());
    // Test mod_down_to_min_inplace symmetric.
    ckks_instance->evaluator->mod_down_to_min_inplace(ciphertext2, ciphertext3);
    // Check estimatedMaxLogScale.
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance->get_estimated_max_log_scale());
    // Expect he_level is decreased.
    ASSERT_EQ(ZERO_MULTI_DEPTH, ciphertext3.he_level());
    // Check scale.
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2) / prime, ciphertext3.scale());
}

TEST(ScaleEstimatorTest, RescaleToNextInPlace) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_scaleestimator_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH);
    CKKSCiphertext ciphertext1, ciphertext2, ciphertext3;
    ciphertext1 = ckks_instance->encrypt(VECTOR_1);
    ciphertext2 = ckks_instance->evaluator->square(ciphertext1);
    uint64_t prime = get_last_prime(ckks_instance->context, ciphertext2.he_level());
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2), ciphertext2.scale());
    ckks_instance->evaluator->rescale_to_next_inplace(ciphertext2);
    // Check scale.
    ASSERT_EQ(pow(2, DEFAULT_LOG_SCALE * 2) / prime, ciphertext2.scale());
    // Expect estimatedMaxLogScale is changed.
    double estimatedMaxLogScale = PLAINTEXT_LOG_MAX - log2(VALUE * VALUE);
    ASSERT_EQ(estimatedMaxLogScale, ckks_instance->get_estimated_max_log_scale());
}
