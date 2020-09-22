// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/api/linearalgebra/linearalgebra.h"

#include <iostream>

#include "../../testutil.h"
#include "gtest/gtest.h"
#include "hit/CKKSInstance.h"
#include "hit/api/ciphertext.h"
#include "hit/common.h"
#include "hit/sealutils.h"

using namespace std;
using namespace hit;

const int NUM_OF_SLOTS = 4096;
const int ZERO_MULTI_DEPTH = 0;
const int LOG_SCALE = 45;

TEST(EncryptMatrixTest, Serialization) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    auto laInst = LinearAlgebra(*ckks_instance);
    EncodingUnit unit1 = laInst.make_unit(64);
    Matrix plaintext = random_mat(64, 64);
    EncryptedMatrix ct1 = laInst.encrypt_matrix(plaintext, unit1);
    EncryptedMatrix ct2 = EncryptedMatrix(ckks_instance->context, *ct1.serialize());
    ASSERT_EQ(ct1.height(), ct2.height());
    ASSERT_EQ(ct1.width(), ct2.width());
    ASSERT_EQ(ct1.encoding_unit(), ct2.encoding_unit());
    Matrix output = laInst.decrypt(ct2);
    ASSERT_LT(diff2_norm(plaintext.data(), output.data()), MAX_NORM);
}
