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
        multiplies = 0;
        additions = 0;
        negations = 0;
        rotations = 0;
        modDowns = 0;
        modDownMuls = 0;

        dfEval->reset_internal();
    }

    void OpCount::print_op_count() const {
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
        rotations++;
        dfEval->rotate_right_inplace_internal(ct, steps);
    }

    void OpCount::rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) {
        rotations++;
        dfEval->rotate_left_inplace_internal(ct, steps);
    }

    void OpCount::negate_inplace_internal(CKKSCiphertext &ct) {
        negations++;
        dfEval->negate_inplace_internal(ct);
    }

    void OpCount::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        additions++;
        dfEval->add_inplace_internal(ct1, ct2);
    }

    void OpCount::add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        additions++;
        dfEval->add_plain_inplace_internal(ct, scalar);
    }

    void OpCount::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        additions++;
        dfEval->add_plain_inplace_internal(ct, plain);
    }

    void OpCount::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        additions++;
        dfEval->sub_inplace_internal(ct1, ct2);
    }

    void OpCount::sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        additions++;
        dfEval->sub_plain_inplace_internal(ct, scalar);
    }

    void OpCount::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        additions++;
        dfEval->sub_plain_inplace_internal(ct, plain);
    }

    void OpCount::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        multiplies++;
        dfEval->multiply_inplace_internal(ct1, ct2);
    }

    void OpCount::multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        multiplies++;
        dfEval->multiply_plain_inplace_internal(ct, scalar);
    }

    void OpCount::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        multiplies++;
        dfEval->multiply_plain_inplace_internal(ct, plain);
    }

    void OpCount::square_inplace_internal(CKKSCiphertext &ct) {
        multiplies++;
        dfEval->square_inplace_internal(ct);
    }

    void OpCount::mod_down_to_min_inplace_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) {
        if (abs(ct1.he_level() - ct2.he_level()) > 0) {
            modDowns++;
        }
        modDownMuls += abs(ct1.he_level() - ct2.he_level());
        dfEval->mod_down_to_min_inplace_internal(ct1, ct2);
    }

    void OpCount::mod_down_to_level_inplace_internal(CKKSCiphertext &ct, int level) {
        if (ct.he_level() - level > 0) {
            modDowns++;
        }
        modDownMuls += (ct.he_level() - level);
        dfEval->mod_down_to_level_inplace_internal(ct, level);
    }

    void OpCount::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        dfEval->rescale_to_next_inplace_internal(ct);
    }

    void OpCount::relinearize_inplace_internal(CKKSCiphertext &ct) {
        dfEval->relinearize_inplace_internal(ct);
    }
}  // namespace hit
