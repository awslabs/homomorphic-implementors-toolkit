// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* This file offers default implementation for most functions in the
 * CKKSEvaluator interface.
 */

#include "evaluator.h"

#include <glog/logging.h>

#include <utility>

#include "../common.h"

using namespace std;
using namespace seal;

namespace hit {

    CKKSEvaluator::CKKSEvaluator(shared_ptr<SEALContext> context) : context(move(context)) {
    }

    CKKSEvaluator::~CKKSEvaluator() = default;

    void CKKSEvaluator::reset() {
        reset_internal();
    }

    CKKSCiphertext CKKSEvaluator::rotate_right(const CKKSCiphertext &ct, int steps) {
        CKKSCiphertext output = ct;
        rotate_right_inplace(output, steps);
        return output;
    }

    void CKKSEvaluator::rotate_right_inplace(CKKSCiphertext &ct, int steps) {
        if (steps < 0) {
            throw invalid_argument("ERROR: rotate_right must have a positive number of steps.");
        }
        VLOG(LOG_VERBOSE) << "Rotate " << abs(steps) << " steps right.";
        rotate_right_inplace_internal(ct, steps);
    }

    CKKSCiphertext CKKSEvaluator::rotate_left(const CKKSCiphertext &ct, int steps) {
        CKKSCiphertext output = ct;
        rotate_left_inplace(output, steps);
        return output;
    }

    void CKKSEvaluator::rotate_left_inplace(CKKSCiphertext &ct, int steps) {
        if (steps < 0) {
            throw invalid_argument("ERROR: rotate_left must have a positive number of steps.");
        }
        VLOG(LOG_VERBOSE) << "Rotate " << abs(steps) << " steps left.";
        rotate_left_inplace_internal(ct, steps);
    }

    CKKSCiphertext CKKSEvaluator::negate(const CKKSCiphertext &ct) {
        CKKSCiphertext output = ct;
        negate_inplace(output);
        return output;
    }

    void CKKSEvaluator::negate_inplace(CKKSCiphertext &ct) {
        VLOG(LOG_VERBOSE) << "Negate";
        negate_inplace_internal(ct);
    }

    CKKSCiphertext CKKSEvaluator::add(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        VLOG(LOG_VERBOSE) << "Add ciphertexts";

        CKKSCiphertext temp = ct1;
        add_inplace_internal(temp, ct2);
        return temp;
    }

    void CKKSEvaluator::add_inplace(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        ct1 = add(ct1, ct2);
    }

    CKKSCiphertext CKKSEvaluator::add_plain(const CKKSCiphertext &ct, double scalar) {
        CKKSCiphertext output = ct;
        add_plain_inplace(output, scalar);
        return output;
    }

    void CKKSEvaluator::add_plain_inplace(CKKSCiphertext &ct, double scalar) {
        VLOG(LOG_VERBOSE) << "Add scalar " << scalar << " to ciphertext";
        add_plain_inplace_internal(ct, scalar);
    }

    CKKSCiphertext CKKSEvaluator::add_plain(const CKKSCiphertext &ct, const vector<double> &plain) {
        CKKSCiphertext output = ct;
        add_plain_inplace(output, plain);
        return output;
    }

    void CKKSEvaluator::add_plain_inplace(CKKSCiphertext &ct, const vector<double> &plain) {
        VLOG(LOG_VERBOSE) << "Add plaintext to ciphertext";
        return add_plain_inplace_internal(ct, plain);
    }

    CKKSCiphertext CKKSEvaluator::add_many(vector<CKKSCiphertext> &cts) {
        if (cts.empty()) {
            throw invalid_argument("add_many: vector may not be empty.");
        }

        CKKSCiphertext dest = cts[0];
        for (int i = 1; i < cts.size(); i++) {
            add_inplace(dest, cts[i]);
        }
        return dest;
    }

    CKKSCiphertext CKKSEvaluator::sub(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        VLOG(LOG_VERBOSE) << "Subtract ciphertexts";

        CKKSCiphertext temp = ct1;
        sub_inplace_internal(temp, ct2);
        return temp;
    }

    void CKKSEvaluator::sub_inplace(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        ct1 = sub(ct1, ct2);
    }

    CKKSCiphertext CKKSEvaluator::sub_plain(const CKKSCiphertext &ct, double scalar) {
        CKKSCiphertext output = ct;
        sub_plain_inplace(output, scalar);
        return output;
    }

    void CKKSEvaluator::sub_plain_inplace(CKKSCiphertext &ct, double scalar) {
        VLOG(LOG_VERBOSE) << "Subtract scalar " << scalar << " from ciphertext";
        sub_plain_inplace_internal(ct, scalar);
    }

    CKKSCiphertext CKKSEvaluator::sub_plain(const CKKSCiphertext &ct, const vector<double> &plain) {
        CKKSCiphertext output = ct;
        sub_plain_inplace(output, plain);
        return output;
    }

    void CKKSEvaluator::sub_plain_inplace(CKKSCiphertext &ct, const vector<double> &plain) {
        VLOG(LOG_VERBOSE) << "Subtract plaintext from ciphertext";
        sub_plain_inplace_internal(ct, plain);
    }

    CKKSCiphertext CKKSEvaluator::multiply(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        VLOG(LOG_VERBOSE) << "Multiply ciphertexts";

        CKKSCiphertext temp = ct1;
        multiply_inplace_internal(temp, ct2);
        return temp;
    }

    void CKKSEvaluator::multiply_inplace(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        ct1 = multiply(ct1, ct2);
    }

    CKKSCiphertext CKKSEvaluator::multiply_plain(const CKKSCiphertext &ct, double scalar) {
        CKKSCiphertext output = ct;
        multiply_plain_inplace(output, scalar);
        return output;
    }

    void CKKSEvaluator::multiply_plain_inplace(CKKSCiphertext &ct, double scalar) {
        VLOG(LOG_VERBOSE) << "Multiply ciphertext by scalar " << scalar;
        multiply_plain_inplace_internal(ct, scalar);
    }

    CKKSCiphertext CKKSEvaluator::multiply_plain(const CKKSCiphertext &ct, const vector<double> &plain) {
        CKKSCiphertext output = ct;
        multiply_plain_inplace(output, plain);
        return output;
    }

    void CKKSEvaluator::multiply_plain_inplace(CKKSCiphertext &ct, const vector<double> &plain) {
        VLOG(LOG_VERBOSE) << "Multiply by plaintext";
        if (ct.num_slots() != plain.size()) {
            throw invalid_argument(
                "CKKSEvaluator::multiply_plain: encoded size does not match plaintext input. Expected " +
                to_string(ct.num_slots()) + ", got " + to_string(plain.size()));
        }
        return multiply_plain_inplace_internal(ct, plain);
    }

    CKKSCiphertext CKKSEvaluator::square(const CKKSCiphertext &ct) {
        CKKSCiphertext output = ct;
        square_inplace(output);
        return output;
    }

    void CKKSEvaluator::square_inplace(CKKSCiphertext &ct) {
        VLOG(LOG_VERBOSE) << "Square ciphertext";
        square_inplace_internal(ct);
    }

    CKKSCiphertext CKKSEvaluator::mod_down_to(const CKKSCiphertext &ct, const CKKSCiphertext &target) {
        CKKSCiphertext output = ct;
        mod_down_to_inplace(output, target);
        return output;
    }

    void CKKSEvaluator::mod_down_to_inplace(CKKSCiphertext &ct, const CKKSCiphertext &target) {
        VLOG(LOG_VERBOSE) << "Decreasing HE level to match target";
        mod_down_to_inplace_internal(ct, target);
    }

    void CKKSEvaluator::mod_down_to_min_inplace(CKKSCiphertext &ct1, CKKSCiphertext &ct2) {
        VLOG(LOG_VERBOSE) << "Equalizing HE levels";
        mod_down_to_min_inplace_internal(ct1, ct2);
    }

    CKKSCiphertext CKKSEvaluator::mod_down_to_level(const CKKSCiphertext &ct, int level) {
        CKKSCiphertext output = ct;
        mod_down_to_level_inplace(output, level);
        return output;
    }

    void CKKSEvaluator::mod_down_to_level_inplace(CKKSCiphertext &ct, int level) {
        VLOG(LOG_VERBOSE) << "Decreasing HE level to " << level;
        mod_down_to_level_inplace_internal(ct, level);
    }

    CKKSCiphertext CKKSEvaluator::rescale_to_next(const CKKSCiphertext &ct) {
        CKKSCiphertext output = ct;
        rescale_to_next_inplace(output);
        return output;
    }

    void CKKSEvaluator::rescale_to_next_inplace(CKKSCiphertext &ct) {
        VLOG(LOG_VERBOSE) << "Rescaling ciphertext";
        rescale_to_next_inplace_internal(ct);
    }

    void CKKSEvaluator::relinearize_inplace(CKKSCiphertext &ct) {
        VLOG(LOG_VERBOSE) << "Relinearizing ciphertext";
        relinearize_inplace_internal(ct);
    }

    ContextDataPtr CKKSEvaluator::getContextData(const CKKSCiphertext &ct) {
        // get the context_data for this ciphertext level
        // but do not use the ciphertext itself! Use the he_level,
        // in case we are not doing ciphertext computations
        auto context_data = context->first_context_data();
        while (context_data->chain_index() > ct.he_level()) {
            // Step forward in the chain.
            context_data = context_data->next_context_data();
        }
        return context_data;
    }
}  // namespace hit
