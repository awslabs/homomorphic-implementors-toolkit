// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "depthfinder.h"

#include <glog/logging.h>

#include "../../common.h"

using namespace std;
using namespace seal;

namespace hit {

    DepthFinder::DepthFinder(const shared_ptr<SEALContext> &context) : top_he_level_(context->first_context_data()->chain_index()) {
    }

    void DepthFinder::reset_internal() {
        scoped_lock lock(mutex_);
        multiplicative_depth_ = 0;
    }

    CKKSCiphertext DepthFinder::encrypt(const std::vector<double>&, int level) {
        if (level == -1) {
            level = top_he_level_;
        }

        CKKSCiphertext destination;
        destination.he_level_ = level;
        destination.num_slots_ = 4096; // TODO: problematic if the depth of the function depends on the number of slots
        destination.initialized = true;

        return destination;
    }

    std::vector<double> DepthFinder::decrypt(const CKKSCiphertext&) const {
        throw invalid_argument("CKKSInstance: You cannot call decrypt with the DepthFinder evaluator!");
    }

    // print some debug info
    void DepthFinder::print_stats(         // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
        const CKKSCiphertext &ct) const {  // NOLINT(readability-convert-member-functions-to-static)
        VLOG(LOG_VERBOSE) << "    + Level: " << ct.he_level();
    }

    void DepthFinder::rotate_right_inplace_internal(CKKSCiphertext &ct, int) {
        print_stats(ct);
    }

    void DepthFinder::rotate_left_inplace_internal(CKKSCiphertext &ct, int) {
        print_stats(ct);
    }

    void DepthFinder::negate_inplace_internal(CKKSCiphertext &ct) {
        print_stats(ct);
    }

    void DepthFinder::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // check that ciphertexts are at the same level to avoid an obscure SEAL error
        if (ct1.he_level() != ct2.he_level()) {
            stringstream buffer;
            buffer << "Error in DepthFinder::add: input levels do not match: " << ct1.he_level()
                   << " != " << ct2.he_level();
            throw invalid_argument(buffer.str());
        }
        print_stats(ct1);
    }

    void DepthFinder::add_plain_inplace_internal(CKKSCiphertext &ct, double) {
        print_stats(ct);
    }

    void DepthFinder::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &) {
        print_stats(ct);
    }

    void DepthFinder::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // check that ciphertexts are at the same level to avoid an obscure SEAL error
        if (ct1.he_level() != ct2.he_level()) {
            stringstream buffer;
            buffer << "Error in DepthFinder::sub: input levels do not match: " << ct1.he_level()
                   << " != " << ct2.he_level();
            throw invalid_argument(buffer.str());
        }
        print_stats(ct1);
    }

    void DepthFinder::sub_plain_inplace_internal(CKKSCiphertext &ct, double) {
        print_stats(ct);
    }

    void DepthFinder::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &) {
        print_stats(ct);
    }

    void DepthFinder::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // check that ciphertexts are at the same level to avoid an obscure SEAL error
        if (ct1.he_level() != ct2.he_level()) {
            stringstream buffer;
            buffer << "Error in DepthFinder::multiply: input levels do not match: " << ct1.he_level()
                   << " != " << ct2.he_level();
            throw invalid_argument(buffer.str());
        }
        print_stats(ct1);
    }

    void DepthFinder::multiply_plain_inplace_internal(CKKSCiphertext &ct, double) {
        print_stats(ct);
    }

    void DepthFinder::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &) {
        print_stats(ct);
    }

    void DepthFinder::square_inplace_internal(CKKSCiphertext &ct) {
        print_stats(ct);
    }

    void DepthFinder::mod_down_to_level_inplace_internal(CKKSCiphertext &ct, int level) {
        if (ct.he_level() >= level) {
            ct.he_level_ = level;
        } else {
            throw invalid_argument("x level is below target level");
        }
        print_stats(ct);
    }

    void DepthFinder::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        ct.he_level_--;
        /* The DepthFinder is always created as a "depth 0" evaluator, meaning that with
         * the current implementation in CKKSInstance, top_he_level_ is *always* 0.
         * There are two possible scenarios.
         *  1. All calls to encrypt*() use an implicit level.
         *     In this case, all CTs are have he_level = 0, so reducing the level
         *     results in a negative he_level. Then 0-negative = positive, which accurately
         *     tracks the computation depth.
         *  2. Alternatively, some calls to encrypt may set explicit encryption levels.
         *     In this case, ciphertexts are encrypted with a positive level, meaning
         *     0-positive is never larger than the base multiplicative_depth_ of 0. Instead,
         *     we use the outer `max` to account for explicitly-leveled ciphertexts.
         */
        {
            scoped_lock lock(mutex_);
            multiplicative_depth_ = max(max(multiplicative_depth_, top_he_level_ - ct.he_level()), ct.he_level() + 1);
        }
        print_stats(ct);
    }

    void DepthFinder::relinearize_inplace_internal(CKKSCiphertext &) {
    }

    int DepthFinder::get_multiplicative_depth() const {
        shared_lock lock(mutex_);
        return multiplicative_depth_;
    }
}  // namespace hit
