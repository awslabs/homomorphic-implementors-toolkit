// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/api/linearalgebra/linearalgebra.h"

#include <iostream>

#include "gtest/gtest.h"
#include "hit/CKKSInstance.h"

using namespace std;
using namespace hit;

const int NUM_OF_SLOTS = 4096;
const int ZERO_MULTI_DEPTH = 0;
const int LOG_SCALE = 45;

TEST(EncodingUnitTest, Serialization) {
    CKKSInstance *ckks_instance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    int unit1_height = 64;
    auto laInst = LinearAlgebra(*ckks_instance);
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    EncodingUnit unit2 = EncodingUnit(*unit1.serialize());
    ASSERT_EQ(unit1, unit2);
}
