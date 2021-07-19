// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "rotations.h"

#include <glog/logging.h>

#include <iomanip>

#include "../../common.h"

using namespace std;

namespace hit {

    RotationSet::RotationSet(int num_slots) : num_slots_(num_slots) {
    }

    CKKSCiphertext RotationSet::encrypt(const vector<double> &coeffs) {
        return encrypt(coeffs, -1);
    }

    CKKSCiphertext RotationSet::encrypt(const vector<double> &, int level) {
        CKKSCiphertext destination;
        destination.he_level_ = level;
        destination.num_slots_ = num_slots_;
        destination.initialized = true;

        return destination;
    }

    int RotationSet::num_slots() const {
        return num_slots_;
    }

    vector<int> RotationSet::needed_rotations() const {
        return vector<int>(rotations.begin(), rotations.end());
    }

    void RotationSet::rotate_right_inplace_internal(CKKSCiphertext &, int k) {
        scoped_lock lock(mutex_);
        rotations.insert(-k);
    }

    void RotationSet::rotate_left_inplace_internal(CKKSCiphertext &, int k) {
        scoped_lock lock(mutex_);
        rotations.insert(k);
    }
}  // namespace hit