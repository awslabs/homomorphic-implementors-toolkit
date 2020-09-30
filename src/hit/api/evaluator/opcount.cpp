// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "opcount.h"

#include <glog/logging.h>

#include <iomanip>

using namespace std;
using namespace seal;
namespace hit {

    OpCount::OpCount() : CKKSEvaluator() {
        depth_finder = new DepthFinder();
    }

    OpCount::~OpCount() {
        delete depth_finder;
    }

    void OpCount::reset() {
        {
            scoped_lock lock(mutex_);
            multiplies_ = 0;
            additions_ = 0;
            negations_ = 0;
            rotations_ = 0;
            reduce_levels_ = 0;
            reduce_level_muls_ = 0;
            encryptions_ = 0;
        }
        depth_finder->reset();
    }

    CKKSCiphertext OpCount::encrypt(const vector<double>&, int level) {
        {
            scoped_lock lock(mutex_);
            encryptions_++;
        }
        if (level == -1) {
            level = 0;
        }

        CKKSCiphertext destination;
        destination.he_level_ = level;
        destination.num_slots_ = 4096;
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
        LOG(INFO) << "Encryptions: " << encryption_count_;
    }

    void OpCount::rotate_right_inplace_internal(CKKSCiphertext &ct, int steps) {
        count_rotation_ops();
        depth_finder->rotate_right_inplace_internal(ct, steps);
    }

    void OpCount::rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) {
        count_rotation_ops();
        depth_finder->rotate_left_inplace_internal(ct, steps);
    }

    void OpCount::negate_inplace_internal(CKKSCiphertext &ct) {
        {
            scoped_lock lock(mutex_);
            negations_++;
        }
        depth_finder->negate_inplace_internal(ct);
    }

    void OpCount::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        count_addition_ops();
        depth_finder->add_inplace_internal(ct1, ct2);
    }

    void OpCount::add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        count_addition_ops();
        depth_finder->add_plain_inplace_internal(ct, scalar);
    }

    void OpCount::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        count_addition_ops();
        depth_finder->add_plain_inplace_internal(ct, plain);
    }

    void OpCount::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        count_addition_ops();
        depth_finder->sub_inplace_internal(ct1, ct2);
    }

    void OpCount::sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        count_addition_ops();
        depth_finder->sub_plain_inplace_internal(ct, scalar);
    }

    void OpCount::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        count_addition_ops();
        depth_finder->sub_plain_inplace_internal(ct, plain);
    }

    void OpCount::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        count_multiple_ops();
        depth_finder->multiply_inplace_internal(ct1, ct2);
    }

    void OpCount::multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        count_multiple_ops();
        depth_finder->multiply_plain_inplace_internal(ct, scalar);
    }

    void OpCount::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        count_multiple_ops();
        depth_finder->multiply_plain_inplace_internal(ct, plain);
    }

    void OpCount::square_inplace_internal(CKKSCiphertext &ct) {
        count_multiple_ops();
        depth_finder->square_inplace_internal(ct);
    }

    void OpCount::reduce_level_to_inplace_internal(CKKSCiphertext &ct, int level) {
        {
            scoped_lock lock(mutex_);
            if (ct.he_level() - level > 0) {
                reduce_levels_++;
            }
            reduce_level_muls_ += (ct.he_level() - level);
        }
        depth_finder->reduce_level_to_inplace_internal(ct, level);
    }

    void OpCount::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        depth_finder->rescale_to_next_inplace_internal(ct);
    }

    void OpCount::relinearize_inplace_internal(CKKSCiphertext &ct) {
        depth_finder->relinearize_inplace_internal(ct);
    }
}  // namespace hit
