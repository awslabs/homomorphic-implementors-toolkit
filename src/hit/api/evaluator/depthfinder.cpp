// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "depthfinder.h"

#include <glog/logging.h>

#include "../../common.h"

using namespace std;
using namespace seal;

namespace hit {

    CKKSCiphertext DepthFinder::encrypt(const vector<double>&, int level) {
        if (encryption_mode_ == FIRST_ENCRYPT) {
            if (level == -1) {
                encryption_mode_ = IMPLICIT_LEVEL;
            }
            else {
                encryption_mode_ = EXPLICIT_LEVEL;
            }
        }

        if (level < -1) {
            LOG(FATAL) << "Encryption level must be non-negative, got " << level;
        }

        if (level == -1 && encryption_mode_ == EXPLICIT_LEVEL) {
            LOG(FATAL) << "You have previously called `encrypt` with an explicit encryption level; you cannot use the default level now with the DepthFinder evaluator.";
        }
        if (level != -1 && encryption_mode_ == IMPLICIT_LEVEL) {
            LOG(FATAL) << "You have previously called `encrypt` without an explicit encryption level; you cannot use explicit levels now with the DepthFinder evaluator.";
        }

        if (level == -1) {
            level = top_he_level_; // a default level
        }

        CKKSCiphertext destination;
        destination.he_level_ = level;
        // Using a default num_slots_ is potentially problematic if the depth of
        // the function depends on the number of slots. This seems like an unusual
        // situation, so its doesn't seem worth fixing.
        destination.num_slots_ = num_slots_;
        destination.initialized = true;

        return destination;
    }

    // print some debug info
    void DepthFinder::print_stats(         // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
        const CKKSCiphertext &ct) const {  // NOLINT(readability-convert-member-functions-to-static)
        VLOG(VLOG_EVAL) << "    + Level: " << ct.he_level();
    }

    int DepthFinder::num_slots() const {
        return num_slots_;
    }

    void DepthFinder::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        /* The DepthFinder is always created as a "depth 0" evaluator, meaning that with
         * the current implementation, top_he_level_ is *always* 0.
         * There are two possible scenarios.
         *  1. All calls to encrypt() use an implicit encryption level (encryption_mode_=IMPLICIT_LEVEL)
         *     In this case, all CTs start with he_level = 0, so reducing the level
         *     results in a negative he_level. Then zero minus a negative number is positive, which accurately
         *     tracks the computation depth.
         *  2. All calls to encrypt() use an explicit encryption level (encryption_mode_=EXPLICIT_LEVEL)
         *     In this case, ciphertexts are encrypted with a positive level, meaning
         *     zero minus a positive number is never larger than the base multiplicative_depth_ of 0. Instead,
         *     we use the outer `max` to account for explicitly-leveled ciphertexts.
         */
        {
            scoped_lock lock(mutex_);
            multiplicative_depth_ = max(max(multiplicative_depth_, top_he_level_ - ct.he_level() + 1), ct.he_level());
        }
    }

    int DepthFinder::get_multiplicative_depth() const {
        shared_lock lock(mutex_);
        return multiplicative_depth_;
    }
}  // namespace hit
