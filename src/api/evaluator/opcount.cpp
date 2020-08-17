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
        rotations = 0;
        modDowns = 0;
        modDownMuls = 0;

        dfEval->reset_internal();
    }

    void OpCount::printOpCount() const {
        cout << endl << "Multiplications: " << multiplies << endl;
        cout << "ModDownMuls: " << modDownMuls << endl;
        cout << "Additions: " << additions << endl;
        cout << "Rotations: " << rotations << endl;
        cout << "ModDownTos: " << modDowns << endl << endl;
    }

    int OpCount::getMultiplicativeDepth() const {
        return dfEval->getMultiplicativeDepth();
    }

    CKKSCiphertext OpCount::rotate_vector_right_internal(const CKKSCiphertext &ct, int steps) {
        dfEval->rotate_vector_right_internal(ct, steps);
        rotations++;
        return ct;
    }

    CKKSCiphertext OpCount::rotate_vector_left_internal(const CKKSCiphertext &ct, int steps) {
        dfEval->rotate_vector_left_internal(ct, steps);
        rotations++;
        return ct;
    }

    CKKSCiphertext OpCount::add_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        dfEval->add_internal(ct1, ct2);
        additions++;
        return ct1;
    }

    CKKSCiphertext OpCount::add_plain_scalar_internal(const CKKSCiphertext &ct, double scalar) {
        dfEval->add_plain_scalar_internal(ct, scalar);
        additions++;
        return ct;
    }

    CKKSCiphertext OpCount::multiply_plain_scalar_internal(const CKKSCiphertext &ct, double scalar) {
        dfEval->multiply_plain_scalar_internal(ct, scalar);
        multiplies++;
        return ct;
    }

    CKKSCiphertext OpCount::multiply_plain_mat_internal(const CKKSCiphertext &ct, const vector<double> &plain) {
        dfEval->multiply_plain_mat_internal(ct, plain);
        multiplies++;
        return ct;
    }

    CKKSCiphertext OpCount::multiply_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        dfEval->multiply_internal(ct1, ct2);
        multiplies++;
        return ct1;
    }

    CKKSCiphertext OpCount::square_internal(const CKKSCiphertext &ct) {
        dfEval->square_internal(ct);
        multiplies++;
        return ct;
    }

    void OpCount::modDownTo_internal(CKKSCiphertext &ct, const CKKSCiphertext &target) {
        if (ct.he_level - target.he_level > 0) {
            modDowns++;
        }
        modDownMuls += (ct.he_level - target.he_level);
        dfEval->modDownTo_internal(ct, target);
    }

    void OpCount::modDownToMin_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) {
        if (abs(ct1.he_level - ct2.he_level) > 0) {
            modDowns++;
        }
        modDownMuls += abs(ct1.he_level - ct2.he_level);
        dfEval->modDownToMin_internal(ct1, ct2);
    }

    CKKSCiphertext OpCount::modDownToLevel_internal(const CKKSCiphertext &ct, int level) {
        if (ct.he_level - level > 0) {
            modDowns++;
        }
        modDownMuls += (ct.he_level - level);
        CKKSCiphertext y = dfEval->modDownToLevel_internal(ct, level);
        return y;
    }

    void OpCount::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        dfEval->rescale_to_next_inplace_internal(ct);
    }

    void OpCount::relinearize_inplace_internal(CKKSCiphertext &ct) {
        dfEval->relinearize_inplace_internal(ct);
    }
}  // namespace hit
