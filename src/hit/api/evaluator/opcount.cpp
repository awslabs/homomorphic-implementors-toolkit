// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "opcount.h"

#include <glog/logging.h>

#include <iomanip>

using namespace std;
using namespace seal;
namespace hit {

    CKKSCiphertext OpCount::encrypt(const vector<double>&, int level) {
        {
            scoped_lock lock(mutex_);
            encryptions_++;
        }
        CKKSCiphertext destination;
        destination.he_level_ = level;
        destination.num_slots_ = num_slots_;
        destination.initialized = true;

        return destination;
    }

    void OpCount::print_op_count() const {
        shared_lock lock(mutex_);
        LOG(INFO) << "Multiplications: " << multiplies_;
        LOG(INFO) << "ReduceLevelMuls: " << reduce_level_muls_;
        LOG(INFO) << "Additions: " << additions_;
        LOG(INFO) << "Negations: " << negations_;
        LOG(INFO) << "Rotations: " << rotations_;
        LOG(INFO) << "ReduceLevels: " << reduce_levels_;
        LOG(INFO) << "Encryptions: " << encryptions_;
        LOG(INFO) << "Rescales: " << rescales_;
        LOG(INFO) << "Relinearizations: " << relins_;
    }

    void OpCount::rotate_right_inplace_internal(CKKSCiphertext&, int) {
        count_rotation_ops();
    }

    void OpCount::rotate_left_inplace_internal(CKKSCiphertext&, int) {
        count_rotation_ops();
    }

    void OpCount::negate_inplace_internal(CKKSCiphertext&) {
        scoped_lock lock(mutex_);
        negations_++;
    }

    void OpCount::add_inplace_internal(CKKSCiphertext&, const CKKSCiphertext&) {
        count_addition_ops();
    }

    void OpCount::add_plain_inplace_internal(CKKSCiphertext&, double) {
        count_addition_ops();
    }

    void OpCount::add_plain_inplace_internal(CKKSCiphertext&, const vector<double>&) {
        count_addition_ops();
    }

    void OpCount::sub_inplace_internal(CKKSCiphertext&, const CKKSCiphertext&) {
        count_addition_ops();
    }

    void OpCount::sub_plain_inplace_internal(CKKSCiphertext&, double) {
        count_addition_ops();
    }

    void OpCount::sub_plain_inplace_internal(CKKSCiphertext&, const vector<double>&) {
        count_addition_ops();
    }

    void OpCount::multiply_inplace_internal(CKKSCiphertext&, const CKKSCiphertext&) {
        count_multiple_ops();
    }

    void OpCount::multiply_plain_inplace_internal(CKKSCiphertext&, double) {
        count_multiple_ops();
    }

    void OpCount::multiply_plain_inplace_internal(CKKSCiphertext&, const vector<double>&) {
        count_multiple_ops();
    }

    void OpCount::square_inplace_internal(CKKSCiphertext&) {
        count_multiple_ops();
    }

    void OpCount::reduce_level_to_inplace_internal(CKKSCiphertext &ct, int level) {
        scoped_lock lock(mutex_);
        if (ct.he_level() - level > 0) {
            reduce_levels_++;
        }
        reduce_level_muls_ += (ct.he_level() - level);
    }

    void OpCount::rescale_to_next_inplace_internal(CKKSCiphertext&) {
        scoped_lock lock(mutex_);
        rescales_++;
    }

    void OpCount::relinearize_inplace_internal(CKKSCiphertext&) {
        scoped_lock lock(mutex_);
        relins_++;
    }
}  // namespace hit
