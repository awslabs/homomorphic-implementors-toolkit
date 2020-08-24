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
    void DepthFinder::print_stats( // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
        const CKKSCiphertext &ct) const {  // NOLINT(readability-convert-member-functions-to-static)
        cout << "    + Level: " << ct.he_level << endl;
    }

    void DepthFinder::rotate_right_inplace_internal(CKKSCiphertext &ct, int) {
        VERBOSE(print_stats(ct));
    }

    void DepthFinder::rotate_left_inplace_internal(CKKSCiphertext &ct, int) {
        VERBOSE(print_stats(ct));
    }

    void DepthFinder::negate_inplace_internal(CKKSCiphertext &ct) {
        VERBOSE(print_stats(ct));
    }

    void DepthFinder::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // check that ciphertexts are at the same level to avoid an obscure SEAL error
        if (ct1.he_level != ct2.he_level) {
            stringstream buffer;
            buffer << "Error in DepthFinder::add: input levels do not match: " << ct1.he_level
                   << " != " << ct2.he_level;
            throw invalid_argument(buffer.str());
        }
        VERBOSE(print_stats(ct1));
    }

    void DepthFinder::add_plain_inplace_internal(CKKSCiphertext &ct, double) {
        VERBOSE(print_stats(ct));
    }

    void DepthFinder::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &) {
        VERBOSE(print_stats(ct));
    }

    void DepthFinder::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // check that ciphertexts are at the same level to avoid an obscure SEAL error
        if (ct1.he_level != ct2.he_level) {
            stringstream buffer;
            buffer << "Error in DepthFinder::sub: input levels do not match: " << ct1.he_level
                   << " != " << ct2.he_level;
            throw invalid_argument(buffer.str());
        }
        VERBOSE(print_stats(ct1));
    }

    void DepthFinder::sub_plain_inplace_internal(CKKSCiphertext &ct, double) {
        VERBOSE(print_stats(ct));
    }

    void DepthFinder::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &) {
        VERBOSE(print_stats(ct));
    }

    void DepthFinder::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // check that ciphertexts are at the same level to avoid an obscure SEAL error
        if (ct1.he_level != ct2.he_level) {
            stringstream buffer;
            buffer << "Error in DepthFinder::multiply: input levels do not match: " << ct1.he_level
                   << " != " << ct2.he_level;
            throw invalid_argument(buffer.str());
        }
        VERBOSE(print_stats(ct1));
    }

    void DepthFinder::multiply_plain_inplace_internal(CKKSCiphertext &ct, double) {
        VERBOSE(print_stats(ct));
    }

    void DepthFinder::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &) {
        VERBOSE(print_stats(ct));
    }

    void DepthFinder::square_inplace_internal(CKKSCiphertext &ct) {
        VERBOSE(print_stats(ct));
    }

    void DepthFinder::mod_down_to_inplace_internal(CKKSCiphertext &ct, const CKKSCiphertext &target) {
        if (ct.he_level >= target.he_level) {
            ct.he_level = target.he_level;
        } else {
            throw invalid_argument("ct level is below target level");
        }
        VERBOSE(print_stats(ct));
    }

    void DepthFinder::mod_down_to_min_inplace_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) {
        int minLevel = min(ct1.he_level, ct2.he_level);
        ct1.he_level = minLevel;
        ct2.he_level = minLevel;
        // doesn't matter which input I print stats for since we only
        // print the level, and both have the same level at this point.
        VERBOSE(print_stats(ct1));
    }

    void DepthFinder::mod_down_to_level_inplace_internal(CKKSCiphertext &ct, int level) {
        if (ct.he_level >= level) {
            ct.he_level = level;
        } else {
            throw invalid_argument("x level is below target level");
        }
        VERBOSE(print_stats(ct));
    }

    void DepthFinder::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        int topHELevel = context->first_context_data()->chain_index();
        ct.he_level--;
        /* The DepthFinder is always created as a "depth 0" evaluator, meaning that with
         * the current implementation in CKKSInstance, topHELevel is *always* 0.
         * There are two possible scenarios.
         *  1. All calls to encrypt*() use an implicit level.
         *     In this case, all CTs are have he_level = 0, so reducing the level
         *     results in a negative he_level. Then 0-negative = positive, which accurately
         *     tracks the computation depth.
         *  2. Alternatively, some calls to encrypt may set explicit encryption levels.
         *     In this case, ciphertexts are encrypted with a positive level, meaning
         *     0-positive is never larger than the base multiplicativeDepth of 0. Instead,
         *     we use the outer `max` to account for explicitly-leveled ciphertexts.
         */
        multiplicativeDepth = max(max(multiplicativeDepth, topHELevel - ct.he_level), ct.he_level + 1);
        VERBOSE(print_stats(ct));
    }

    void DepthFinder::relinearize_inplace_internal(CKKSCiphertext &) {
    }

    int DepthFinder::get_multiplicative_depth() const {
        return multiplicativeDepth;
    }
}  // namespace hit
