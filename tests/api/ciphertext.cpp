// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/api/ciphertext.h"

#include <iostream>

#include "../testutil.h"
#include "gtest/gtest.h"
#include "hit/CKKSInstance.h"
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
TEST(SerializationTest, CKKSCiphertext) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);

    vector<double> vector1 = random_vector(NUM_OF_SLOTS, RANGE);
    CKKSCiphertext ciphertext1 = ckks_instance->encrypt(vector1);
    hit::protobuf::Ciphertext *ciphertext1_proto = ciphertext1.save();

    CKKSCiphertext ciphertext2(ckks_instance->context, *ciphertext1_proto);
    vector<double> vector2 = ckks_instance->decrypt(ciphertext2);
    ASSERT_LT(diff2_norm(vector1, vector2), MAX_NORM);
}
