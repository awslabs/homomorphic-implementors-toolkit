// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/api/ciphertext.h"

#include <iostream>

#include "../testutil.h"
#include "gtest/gtest.h"
#include "hit/api/evaluator/homomorphic.h"
#include "hit/common.h"

using namespace std;
using namespace hit;

// Test variables.
const int RANGE = 16;
const int NUM_OF_SLOTS = 4096;
const int ZERO_MULTI_DEPTH = 0;
const int LOG_SCALE = 40;

// encrypt a random message, serialize it, deserialize it, and decrypt.
// ensure that the decrypted message is the same as the original plaintext.
TEST(CKKSCiphertextTest, Serialization) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);

    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    CKKSCiphertext ciphertext1 = ckks_instance.encrypt(vector1);
    hit::protobuf::Ciphertext *ciphertext1_proto = ciphertext1.serialize();

    CKKSCiphertext ciphertext2(ckks_instance.context, *ciphertext1_proto);
    vector<double> vector2 = ckks_instance.decrypt(ciphertext2);
    ASSERT_LT(relative_error(vector1, vector2), MAX_NORM);
}
