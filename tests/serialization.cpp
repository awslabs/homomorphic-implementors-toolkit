// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include "gtest/gtest.h"
#include "hit/CKKSInstance.h"
#include "hit/api/ciphertext.h"
#include "hit/common.h"
#include "testutil.h"

using namespace std;
using namespace hit;

// Test variables.
const int RANGE = 16;
const int NUM_OF_SLOTS = 4096;
const int ZERO_MULTI_DEPTH = 0;
const int LOG_SCALE = 40;

// encrypt a random message, serialize it, deserialize it, and decrypt.
// ensure that the decrypted message is the same as the original plaintext.
TEST(SerializationTest, Homomorphic_CKKSCiphertext) {
	CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);

    vector<double> vector1 = randomVector(NUM_OF_SLOTS, RANGE);
    CKKSCiphertext ciphertext1 = ckksInstance->encrypt(vector1);
    hit::protobuf::Ciphertext *ciphertext1_proto = ciphertext1.save();

    CKKSCiphertext ciphertext2(ckksInstance->context, *ciphertext1_proto);
    vector<double> vector2 = ckksInstance->decrypt(ciphertext2);
    ASSERT_LT(diff2Norm(vector1, vector2), MAX_NORM);
}
