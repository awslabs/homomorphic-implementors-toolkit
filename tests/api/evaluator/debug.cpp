// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include "../../testutil.h"
#include "gtest/gtest.h"
#include "hit/hit.h"

using namespace std;
using namespace hit;

// Test variables.
const int RANGE = 16;
const int NUM_OF_SLOTS = 4096;
const int ONE_MULTI_DEPTH = 1;
const int LOG_SCALE = 30;

TEST(DebugTest, Serialization) {
    DebugEval ckks_instance1 = DebugEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);

    // serialize instance to files
    stringstream paramsStream(ios::in | ios::out | ios::binary);
    stringstream galoisKeyStream(ios::in | ios::out | ios::binary);
    stringstream relinKeyStream(ios::in | ios::out | ios::binary);
    stringstream secretKeyStream(ios::in | ios::out | ios::binary);
    ckks_instance1.save(paramsStream, galoisKeyStream, relinKeyStream, secretKeyStream);

    DebugEval ckks_instance2 = DebugEval(paramsStream, galoisKeyStream, relinKeyStream, secretKeyStream);

    vector<double> vector_input = random_vector(NUM_OF_SLOTS, RANGE);
    CKKSCiphertext ciphertext = ckks_instance2.encrypt(vector_input);
    ckks_instance2.square_inplace(ciphertext);
    ckks_instance2.relinearize_inplace(ciphertext);
    ckks_instance2.rescale_to_next_inplace(ciphertext);
    vector<double> vector_output = ckks_instance2.decrypt(ciphertext);
    vector<double> expected_output(NUM_OF_SLOTS);
    transform(vector_input.begin(), vector_input.end(), vector_input.begin(), expected_output.begin(), multiplies<>());
    ASSERT_LE(relative_error(expected_output, vector_output), MAX_NORM);
}
