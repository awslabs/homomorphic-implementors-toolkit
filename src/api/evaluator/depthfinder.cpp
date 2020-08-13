// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "depthfinder.h"

using namespace std;
using namespace seal;

namespace hit {

    DepthFinder::DepthFinder(const shared_ptr<SEALContext> &context, bool verbose)
        : CKKSEvaluator(context, verbose), multiplicativeDepth(0) {
    }

    DepthFinder::~DepthFinder() = default;

    void DepthFinder::reset_internal() {
        multiplicativeDepth = 0;
    }

    // print some debug info
    void DepthFinder::print_stats(
        const CKKSCiphertext &ct) const {  // NOLINT(readability-convert-member-functions-to-static)
        cout << "    + Level: " << ct.he_level << endl;
    }

    CKKSCiphertext DepthFinder::rotate_right_internal(const CKKSCiphertext &ct, int) {
        VERBOSE(print_stats(ct));
        return ct;
    }

    CKKSCiphertext DepthFinder::rotate_left_internal(const CKKSCiphertext &ct, int) {
        VERBOSE(print_stats(ct));
        return ct;
    }

    CKKSCiphertext DepthFinder::negate_internal(const CKKSCiphertext &ct) {
        VERBOSE(print_stats(ct));
        return ct;
    }

    CKKSCiphertext DepthFinder::add_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // check that ciphertexts are at the same level to avoid an obscure SEAL error
        if (ct1.he_level != ct2.he_level) {
            stringstream buffer;
            buffer << "PPLR: Error in DepthFinder::add: input levels do not match: " << ct1.he_level
                   << " != " << ct2.he_level;
            throw invalid_argument(buffer.str());
        }
        VERBOSE(print_stats(ct1));
        return ct1;
    }

    CKKSCiphertext DepthFinder::add_plain_internal(const CKKSCiphertext &ct, double) {
        VERBOSE(print_stats(ct));
        return ct;
    }

    CKKSCiphertext DepthFinder::add_plain_internal(const CKKSCiphertext &ct, const vector<double> &) {
        VERBOSE(print_stats(ct));
        return ct;
    }

    CKKSCiphertext DepthFinder::sub_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // check that ciphertexts are at the same level to avoid an obscure SEAL error
        if (ct1.he_level != ct2.he_level) {
            stringstream buffer;
            buffer << "PPLR: Error in DepthFinder::sub: input levels do not match: " << ct1.he_level
                   << " != " << ct2.he_level;
            throw invalid_argument(buffer.str());
        }
        VERBOSE(print_stats(ct1));
        return ct1;
    }

    CKKSCiphertext DepthFinder::sub_plain_internal(const CKKSCiphertext &ct, double) {
        VERBOSE(print_stats(ct));
        return ct;
    }

    CKKSCiphertext DepthFinder::sub_plain_internal(const CKKSCiphertext &ct, const vector<double> &) {
        VERBOSE(print_stats(ct));
        return ct;
    }

    CKKSCiphertext DepthFinder::multiply_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // check that ciphertexts are at the same level to avoid an obscure SEAL error
        if (ct1.he_level != ct2.he_level) {
            stringstream buffer;
            buffer << "PPLR: Error in DepthFinder::multiply: input levels do not match: " << ct1.he_level
                   << " != " << ct2.he_level;
            throw invalid_argument(buffer.str());
        }
        VERBOSE(print_stats(ct1));
        return ct1;
    }

    CKKSCiphertext DepthFinder::multiply_plain_internal(const CKKSCiphertext &ct, double) {
        VERBOSE(print_stats(ct));
        return ct;
    }

    CKKSCiphertext DepthFinder::multiply_plain_internal(const CKKSCiphertext &ct, const vector<double> &) {
        VERBOSE(print_stats(ct));
        return ct;
    }

    CKKSCiphertext DepthFinder::square_internal(const CKKSCiphertext &ct) {
        VERBOSE(print_stats(ct));
        return ct;
    }

    CKKSCiphertext DepthFinder::mod_down_to_internal(const CKKSCiphertext &ct, const CKKSCiphertext &target) {
        CKKSCiphertext dest = ct;
        if (dest.he_level >= target.he_level) {
            dest.he_level = target.he_level;
        } else {
            throw invalid_argument("ct level is below target level");
        }
        VERBOSE(print_stats(dest));
        return dest;
    }

    void DepthFinder::mod_down_to_min_inplace_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) {
        int minLevel = min(ct1.he_level, ct2.he_level);
        ct1.he_level = minLevel;
        ct2.he_level = minLevel;
        // doesn't matter which input I print stats for since we only
        // print the level, and both have the same level at this point.
        VERBOSE(print_stats(ct1));
    }

    CKKSCiphertext DepthFinder::mod_down_to_level_internal(const CKKSCiphertext &ct, int level) {
        CKKSCiphertext ct_out = ct;
        if (ct.he_level >= level) {
            ct_out.he_level = level;
        } else {
            throw invalid_argument("x level is below target level");
        }
        VERBOSE(print_stats(ct_out));
        return ct_out;
    }

    CKKSCiphertext DepthFinder::rescale_to_next_internal(const CKKSCiphertext &ct) {
        CKKSCiphertext dest = ct;
        int topHELevel = context->first_context_data()->chain_index();
        dest.he_level--;
        multiplicativeDepth = max(multiplicativeDepth, topHELevel - dest.he_level);
        VERBOSE(print_stats(dest));
        return dest;
    }

    void DepthFinder::relinearize_inplace_internal(CKKSCiphertext &) {
    }

    int DepthFinder::getMultiplicativeDepth() const {
        return multiplicativeDepth;
    }
}  // namespace hit
