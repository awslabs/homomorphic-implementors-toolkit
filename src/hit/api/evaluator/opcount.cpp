// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "opcount.h"

#include <glog/logging.h>

#include <iomanip>

using namespace std;
using namespace seal;
namespace hit {

    OpCount::OpCount(const shared_ptr<SEALContext> &context) : CKKSEvaluator(context) {
        dfEval = new DepthFinder(context);
    }

    OpCount::~OpCount() {
        delete dfEval;
    }

    void OpCount::reset_internal() {
        {
            scoped_lock lock(mutex_);
            multiplies = 0;
            additions = 0;
            negations = 0;
            rotations = 0;
            modDowns = 0;
            modDownMuls = 0;
        }
        dfEval->reset_internal();
    }

    void OpCount::print_op_count() const {
        shared_lock lock(mutex_);
        LOG(INFO) << "Multiplications: " << multiplies;
        LOG(INFO) << "ModDownMuls: " << modDownMuls;
        LOG(INFO) << "Additions: " << additions;
        LOG(INFO) << "Negations: " << negations;
        LOG(INFO) << "Rotations: " << rotations;
        LOG(INFO) << "ModDownTos: " << modDowns;
    }

    int OpCount::get_multiplicative_depth() const {
        return dfEval->get_multiplicative_depth();
    }

    void OpCount::rotate_right_inplace_internal(CKKSCiphertext &ct, int steps) {
        count_rotation_ops();
        dfEval->rotate_right_inplace_internal(ct, steps);
    }

    void OpCount::rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) {
        count_rotation_ops();
        dfEval->rotate_left_inplace_internal(ct, steps);
    }

    void OpCount::negate_inplace_internal(CKKSCiphertext &ct) {
        {
            scoped_lock lock(mutex_);
            negations++;
        }
        dfEval->negate_inplace_internal(ct);
    }

    void OpCount::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        count_addition_ops();
        dfEval->add_inplace_internal(ct1, ct2);
    }

    void OpCount::add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        count_addition_ops();
        dfEval->add_plain_inplace_internal(ct, scalar);
    }

    void OpCount::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        count_addition_ops();
        dfEval->add_plain_inplace_internal(ct, plain);
    }

    void OpCount::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        count_addition_ops();
        dfEval->sub_inplace_internal(ct1, ct2);
    }

    void OpCount::sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        count_addition_ops();
        dfEval->sub_plain_inplace_internal(ct, scalar);
    }

    void OpCount::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        count_addition_ops();
        dfEval->sub_plain_inplace_internal(ct, plain);
    }

    void OpCount::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        count_multiple_ops();
        dfEval->multiply_inplace_internal(ct1, ct2);
    }

    void OpCount::multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        count_multiple_ops();
        dfEval->multiply_plain_inplace_internal(ct, scalar);
    }

    void OpCount::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        count_multiple_ops();
        dfEval->multiply_plain_inplace_internal(ct, plain);
    }

    void OpCount::square_inplace_internal(CKKSCiphertext &ct) {
        count_multiple_ops();
        dfEval->square_inplace_internal(ct);
    }

    void OpCount::mod_down_to_level_inplace_internal(CKKSCiphertext &ct, int level) {
        {
            scoped_lock lock(mutex_);
            if (ct.he_level() - level > 0) {
                modDowns++;
            }
            modDownMuls += (ct.he_level() - level);
        }
        dfEval->mod_down_to_level_inplace_internal(ct, level);
    }

    void OpCount::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        dfEval->rescale_to_next_inplace_internal(ct);
    }

    void OpCount::relinearize_inplace_internal(CKKSCiphertext &ct) {
        dfEval->relinearize_inplace_internal(ct);
    }
}  // namespace hit
