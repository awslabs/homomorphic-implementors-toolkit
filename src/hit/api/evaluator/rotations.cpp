// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "rotations.h"

#include <glog/logging.h>

#include <iomanip>

#include "../../common.h"

using namespace std;

namespace hit {

    RotationSet::RotationSet(int num_slots, int post_btp_lvl) : num_slots_(num_slots) {
        post_boostrapping_level = post_btp_lvl;
        post_bootstrapping_scale = pow(2, default_scale_bits);
    }

    CKKSCiphertext RotationSet::encrypt(const vector<double> &coeffs) {
        // ciphertext level doesn't matter for this evaluator
        return encrypt(coeffs, 0);
    }

    CKKSCiphertext RotationSet::encrypt(const vector<double> &, int level) {
        return CKKSCiphertext(num_slots_, level, pow(2, default_scale_bits));
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
