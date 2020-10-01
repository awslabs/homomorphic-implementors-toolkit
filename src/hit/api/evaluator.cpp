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

    vector<double> CKKSEvaluator::decrypt(const CKKSCiphertext&, bool) const {
        throw invalid_argument("decrypt can only be called with Homomorphic or Debug evaluators");
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
        if(ct.needs_relin()) {
            throw invalid_argument("Input to rotate_right must be a linear ciphertext");
        }
        VLOG(LOG_VERBOSE) << "Rotate " << abs(steps) << " steps right.";
        rotate_right_inplace_internal(ct, steps);
        print_stats(ct);
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
        if(ct.needs_relin()) {
            throw invalid_argument("Input to rotate_left must be a linear ciphertext");
        }
        VLOG(LOG_VERBOSE) << "Rotate " << abs(steps) << " steps left.";
        rotate_left_inplace_internal(ct, steps);
        print_stats(ct);
    }

    CKKSCiphertext CKKSEvaluator::negate(const CKKSCiphertext &ct) {
        CKKSCiphertext output = ct;
        negate_inplace(output);
        return output;
    }

    void CKKSEvaluator::negate_inplace(CKKSCiphertext &ct) {
        VLOG(LOG_VERBOSE) << "Negate";
        negate_inplace_internal(ct);
        print_stats(ct);
    }

    CKKSCiphertext CKKSEvaluator::add(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        CKKSCiphertext temp = ct1;
        add_inplace(temp, ct2);
        return temp;
    }

    void CKKSEvaluator::add_inplace(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        VLOG(LOG_VERBOSE) << "Add ciphertexts";
        if(ct1.scale() != ct2.scale()) {
            throw invalid_argument("Inputs to add must have the same scale");
        }
        if(ct1.he_level() != ct2.he_level()) {
            throw invalid_argument("Arguments to add must be at the same level: " +
                                   to_string(ct1.he_level()) + " != " + to_string(ct2.he_level()));
        }
        add_inplace_internal(ct1, ct2);
        print_stats(ct1);
    }

    CKKSCiphertext CKKSEvaluator::add_plain(const CKKSCiphertext &ct, double scalar) {
        CKKSCiphertext output = ct;
        add_plain_inplace(output, scalar);
        return output;
    }

    void CKKSEvaluator::add_plain_inplace(CKKSCiphertext &ct, double scalar) {
        VLOG(LOG_VERBOSE) << "Add scalar " << scalar << " to ciphertext";
        add_plain_inplace_internal(ct, scalar);
        print_stats(ct);
    }

    CKKSCiphertext CKKSEvaluator::add_plain(const CKKSCiphertext &ct, const vector<double> &plain) {
        CKKSCiphertext output = ct;
        add_plain_inplace(output, plain);
        return output;
    }

    void CKKSEvaluator::add_plain_inplace(CKKSCiphertext &ct, const vector<double> &plain) {
        VLOG(LOG_VERBOSE) << "Add plaintext to ciphertext";
        if(plain.size() != ct.num_slots()) {
            throw invalid_argument("Public argument to add_plain must have exactly as many coefficients as the ciphertext has plaintext slots.");
        }
        add_plain_inplace_internal(ct, plain);
        print_stats(ct);
    }

    CKKSCiphertext CKKSEvaluator::add_many(const vector<CKKSCiphertext> &cts) {
        if (cts.empty()) {
            throw invalid_argument("add_many: vector may not be empty.");
        }
        VLOG(LOG_VERBOSE) << "Add ciphertext vector of size " << cts.size();

        CKKSCiphertext dest = cts[0];
        for (int i = 1; i < cts.size(); i++) {
            if(cts[i].scale() != dest.scale()) {
                throw invalid_argument("Inputs to add+_many must have the same scale");
            }
            if(cts[i].he_level() != dest.he_level()) {
                throw invalid_argument("Arguments to add_many must be at the same level: " +
                                       to_string(cts[i].he_level()) + " != " + to_string(dest.he_level()));
            }
            add_inplace_internal(dest, cts[i]);
        }
        print_stats(dest);
        return dest;
    }

    CKKSCiphertext CKKSEvaluator::sub(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        CKKSCiphertext temp = ct1;
        sub_inplace(temp, ct2);
        return temp;
    }

    void CKKSEvaluator::sub_inplace(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        VLOG(LOG_VERBOSE) << "Subtract ciphertexts";
        if(ct1.scale() != ct2.scale()) {
            throw invalid_argument("Inputs to add must have the same scale");
        }
        if(ct1.he_level() != ct2.he_level()) {
            throw invalid_argument("Arguments to sub must be at the same level: " +
                                   to_string(ct1.he_level()) + " != " + to_string(ct2.he_level()));
        }
        sub_inplace_internal(ct1, ct2);
        print_stats(ct1);
    }

    CKKSCiphertext CKKSEvaluator::sub_plain(const CKKSCiphertext &ct, double scalar) {
        CKKSCiphertext output = ct;
        sub_plain_inplace(output, scalar);
        return output;
    }

    void CKKSEvaluator::sub_plain_inplace(CKKSCiphertext &ct, double scalar) {
        VLOG(LOG_VERBOSE) << "Subtract scalar " << scalar << " from ciphertext";
        sub_plain_inplace_internal(ct, scalar);
        print_stats(ct);
    }

    CKKSCiphertext CKKSEvaluator::sub_plain(const CKKSCiphertext &ct, const vector<double> &plain) {
        CKKSCiphertext output = ct;
        sub_plain_inplace(output, plain);
        return output;
    }

    void CKKSEvaluator::sub_plain_inplace(CKKSCiphertext &ct, const vector<double> &plain) {
        VLOG(LOG_VERBOSE) << "Subtract plaintext from ciphertext";
        if(plain.size() != ct.num_slots()) {
            throw invalid_argument("Public argument to sub_plain must have exactly as many coefficients as the ciphertext has plaintext slots.");
        }
        sub_plain_inplace_internal(ct, plain);
        print_stats(ct);
    }

    CKKSCiphertext CKKSEvaluator::multiply(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        CKKSCiphertext temp = ct1;
        multiply_inplace(temp, ct2);
        return temp;
    }

    void CKKSEvaluator::multiply_inplace(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        VLOG(LOG_VERBOSE) << "Multiply ciphertexts";
        if(ct1.needs_relin() || ct2.needs_relin()) {
            throw invalid_argument("Arguments to multiply must be linear ciphertexts");
        }
        if(ct1.he_level() != ct2.he_level()) {
            throw invalid_argument("Arguments to multiply must be at the same level: " +
                                   to_string(ct1.he_level()) + " != " + to_string(ct2.he_level()));
        }
        if(ct1.needs_rescale() || ct2.needs_rescale() || ct1.scale() != ct2.scale()) {
            throw invalid_argument("Arguments to multiply must have the same nominal scale");
        }
        multiply_inplace_internal(ct1, ct2);
        ct1.needs_rescale_ = true;
        ct1.needs_relin_ = true;
        ct1.scale_ *= ct1.scale_;
        print_stats(ct1);
    }

    CKKSCiphertext CKKSEvaluator::multiply_plain(const CKKSCiphertext &ct, double scalar) {
        CKKSCiphertext output = ct;
        multiply_plain_inplace(output, scalar);
        return output;
    }

    void CKKSEvaluator::multiply_plain_inplace(CKKSCiphertext &ct, double scalar) {
        VLOG(LOG_VERBOSE) << "Multiply ciphertext by scalar " << scalar;
        if(ct.needs_rescale()) {
            throw invalid_argument("Argument to multiply_plain must have nominal scale");
        }
        multiply_plain_inplace_internal(ct, scalar);
        ct.needs_rescale_ = true;
        ct.scale_ *= ct.scale_;
        print_stats(ct);
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
        if(ct.needs_rescale()) {
            throw invalid_argument("Argument to multiply_plain must have nominal scale");
        }
        multiply_plain_inplace_internal(ct, plain);
        ct.needs_rescale_ = true;
        ct.scale_ *= ct.scale_;
        print_stats(ct);
    }

    CKKSCiphertext CKKSEvaluator::square(const CKKSCiphertext &ct) {
        CKKSCiphertext output = ct;
        square_inplace(output);
        return output;
    }

    void CKKSEvaluator::square_inplace(CKKSCiphertext &ct) {
        VLOG(LOG_VERBOSE) << "Square ciphertext";
        if(ct.needs_relin()) {
            throw invalid_argument("Argument to square must be a linear ciphertext");
        }
        if(ct.needs_rescale()) {
            throw invalid_argument("Argument to square must have nominal scale");
        }
        square_inplace_internal(ct);
        ct.needs_rescale_ = true;
        ct.needs_relin_ = true;
        ct.scale_ *= ct.scale_;
        print_stats(ct);
    }

    CKKSCiphertext CKKSEvaluator::reduce_level_to(const CKKSCiphertext &ct, const CKKSCiphertext &target) {
        return reduce_level_to(ct, target.he_level());
    }

    void CKKSEvaluator::reduce_level_to_inplace(CKKSCiphertext &ct, const CKKSCiphertext &target) {
        reduce_level_to_inplace(ct, target.he_level());
    }

    void CKKSEvaluator::reduce_level_to_min_inplace(CKKSCiphertext &ct1, CKKSCiphertext &ct2) {
        if (ct1.he_level() > ct2.he_level()) {
            reduce_level_to_inplace(ct1, ct2.he_level());
        } else if (ct1.he_level() < ct2.he_level()) {
            reduce_level_to_inplace(ct2, ct1.he_level());
        }
    }

    CKKSCiphertext CKKSEvaluator::reduce_level_to(const CKKSCiphertext &ct, int level) {
        CKKSCiphertext output = ct;
        reduce_level_to_inplace(output, level);
        return output;
    }

    void CKKSEvaluator::reduce_level_to_inplace(CKKSCiphertext &ct, int level) {
        VLOG(LOG_VERBOSE) << "Decreasing HE level to " << level;
        if(ct.he_level() < level) {
            throw invalid_argument("Input to reduce_level_to is already below the target level");
        }
        if(ct.needs_relin()) {
            throw invalid_argument("Argument to reduce_level_to must be a linear ciphertext");
        }
        if(ct.needs_rescale()) {
            throw invalid_argument("Argument to reduce_level_to must have nominal scale");
        }
        reduce_level_to_inplace_internal(ct, level);
        // updates he_level and scale
        reduce_metadata_to_level(ct, level);
        print_stats(ct);
    }

    CKKSCiphertext CKKSEvaluator::rescale_to_next(const CKKSCiphertext &ct) {
        CKKSCiphertext output = ct;
        rescale_to_next_inplace(output);
        return output;
    }

    void CKKSEvaluator::rescale_to_next_inplace(CKKSCiphertext &ct) {
        VLOG(LOG_VERBOSE) << "Rescaling ciphertext";
        if(!ct.needs_rescale()) {
            throw invalid_argument("Argument to rescale_to_next_inplace must have squared scale");
        }
        rescale_to_next_inplace_internal(ct);
        rescale_metata_to_next(ct);
        print_stats(ct);
    }

    void CKKSEvaluator::relinearize_inplace(CKKSCiphertext &ct) {
        VLOG(LOG_VERBOSE) << "Relinearizing ciphertext";
        if(!ct.needs_relin()) {
            throw invalid_argument("Argument to relinearize_inplace must be a linear ciphertext");
        }
        relinearize_inplace_internal(ct);
        ct.needs_relin_ = false;
        print_stats(ct);
    }

    void CKKSEvaluator::reduce_metadata_to_level(CKKSCiphertext &ct, int level) {
        while (ct.he_level() > level) {
            ct.scale_ *= ct.scale();
            ct.needs_rescale_ = true;
            rescale_metata_to_next(ct);
        }
    }

    void CKKSEvaluator::rescale_metata_to_next(CKKSCiphertext &ct) {
        uint64_t prime = get_last_prime_internal(ct);
        ct.he_level_--;
        ct.scale_ /= prime;
        ct.needs_rescale_ = false;
    }

    // default implementation for evaluators which don't use SEAL
    uint64_t CKKSEvaluator::get_last_prime_internal(const CKKSCiphertext &ct) const {
        if(ct.needs_rescale()) {
            return sqrt(ct.scale());
        }
        return ct.scale();
    }

    void CKKSEvaluator::rotate_right_inplace_internal(CKKSCiphertext&, int) { };
    void CKKSEvaluator::rotate_left_inplace_internal(CKKSCiphertext&, int) { };
    void CKKSEvaluator::negate_inplace_internal(CKKSCiphertext&) { };
    void CKKSEvaluator::add_inplace_internal(CKKSCiphertext&, const CKKSCiphertext&) { };
    void CKKSEvaluator::add_plain_inplace_internal(CKKSCiphertext&, double) { };
    void CKKSEvaluator::add_plain_inplace_internal(CKKSCiphertext&, const vector<double>&) { };
    void CKKSEvaluator::sub_inplace_internal(CKKSCiphertext&, const CKKSCiphertext&) { };
    void CKKSEvaluator::sub_plain_inplace_internal(CKKSCiphertext&, double) { };
    void CKKSEvaluator::sub_plain_inplace_internal(CKKSCiphertext&, const vector<double>&) { };
    void CKKSEvaluator::multiply_inplace_internal(CKKSCiphertext&, const CKKSCiphertext&) { };
    void CKKSEvaluator::multiply_plain_inplace_internal(CKKSCiphertext&, double) { };
    void CKKSEvaluator::multiply_plain_inplace_internal(CKKSCiphertext&, const vector<double>&) { };
    void CKKSEvaluator::square_inplace_internal(CKKSCiphertext&) { };
    void CKKSEvaluator::reduce_level_to_inplace_internal(CKKSCiphertext&, int) { };
    void CKKSEvaluator::rescale_to_next_inplace_internal(CKKSCiphertext&) { };
    void CKKSEvaluator::relinearize_inplace_internal(CKKSCiphertext&) { };
    void CKKSEvaluator::print_stats(const CKKSCiphertext&) const { };
}  // namespace hit
