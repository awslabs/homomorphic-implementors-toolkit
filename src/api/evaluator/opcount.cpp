// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "opcount.h"

#include <iomanip>

using namespace std;
using namespace seal;
namespace hit {

    OpCount::OpCount(const shared_ptr<SEALContext> &context, bool verbose) : CKKSEvaluator(context, verbose) {
        dfEval = new DepthFinder(context, verbose);
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

    void OpCount::printOpCount() const {
        cout << endl << "Multiplications: " << multiplies << endl;
        cout << "ModDownMuls: " << modDownMuls << endl;
        cout << "Additions: " << additions << endl;
        cout << "Negations: " << negations << endl;
        cout << "Rotations: " << rotations << endl;
        cout << "ModDownTos: " << modDowns << endl << endl;
    }

    int OpCount::getMultiplicativeDepth() const {
        return dfEval->getMultiplicativeDepth();
    }

    CKKSCiphertext OpCount::rotate_right_internal(const CKKSCiphertext &ct, int steps) {
        rotations++;
        return dfEval->rotate_right_internal(ct, steps);
    }

    CKKSCiphertext OpCount::rotate_left_internal(const CKKSCiphertext &ct, int steps) {
        rotations++;
        return dfEval->rotate_left_internal(ct, steps);
    }

    CKKSCiphertext OpCount::negate_internal(const CKKSCiphertext &ct) {
        negations++;
        return dfEval->negate_internal(ct);
    }

    CKKSCiphertext OpCount::add_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        additions++;
        return dfEval->add_internal(ct1, ct2);
    }

    CKKSCiphertext OpCount::add_plain_internal(const CKKSCiphertext &ct, double scalar) {
        additions++;
        return dfEval->add_plain_internal(ct, scalar);
    }

    CKKSCiphertext OpCount::add_plain_internal(const CKKSCiphertext &ct, const vector<double> &plain) {
        additions++;
        return dfEval->add_plain_internal(ct, plain);
    }

    CKKSCiphertext OpCount::sub_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        additions++;
        return dfEval->sub_internal(ct1, ct2);
    }

    CKKSCiphertext OpCount::sub_plain_internal(const CKKSCiphertext &ct, double scalar) {
        additions++;
        return dfEval->sub_plain_internal(ct, scalar);
    }

    CKKSCiphertext OpCount::sub_plain_internal(const CKKSCiphertext &ct, const vector<double> &plain) {
        additions++;
        return dfEval->sub_plain_internal(ct, plain);
    }

    CKKSCiphertext OpCount::multiply_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        multiplies++;
        return dfEval->multiply_internal(ct1, ct2);
    }

    CKKSCiphertext OpCount::multiply_plain_internal(const CKKSCiphertext &ct, double scalar) {
        multiplies++;
        return dfEval->multiply_plain_internal(ct, scalar);
    }

    CKKSCiphertext OpCount::multiply_plain_internal(const CKKSCiphertext &ct, const vector<double> &plain) {
        multiplies++;
        return dfEval->multiply_plain_internal(ct, plain);
    }

    CKKSCiphertext OpCount::square_internal(const CKKSCiphertext &ct) {
        multiplies++;
        return dfEval->square_internal(ct);
    }

    CKKSCiphertext OpCount::mod_down_to_internal(const CKKSCiphertext &ct, const CKKSCiphertext &target) {
        if (ct.he_level - target.he_level > 0) {
            modDowns++;
        }
        modDownMuls += (ct.he_level - target.he_level);
        return dfEval->mod_down_to_internal(ct, target);
    }

    void OpCount::mod_down_to_min_inplace_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) {
        if (abs(ct1.he_level - ct2.he_level) > 0) {
            modDowns++;
        }
        modDownMuls += abs(ct1.he_level - ct2.he_level);
        dfEval->mod_down_to_min_inplace_internal(ct1, ct2);
    }

    CKKSCiphertext OpCount::mod_down_to_level_internal(const CKKSCiphertext &ct, int level) {
        if (ct.he_level - level > 0) {
            modDowns++;
        }
        modDownMuls += (ct.he_level - level);
        return dfEval->mod_down_to_level_internal(ct, level);
    }

    CKKSCiphertext OpCount::rescale_to_next_internal(const CKKSCiphertext &ct) {
        return dfEval->rescale_to_next_internal(ct);
    }

    void OpCount::relinearize_inplace_internal(CKKSCiphertext &ct) {
        dfEval->relinearize_inplace_internal(ct);
    }
}  // namespace hit
