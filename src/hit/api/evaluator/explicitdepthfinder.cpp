// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "explicitdepthfinder.h"

#include <glog/logging.h>

#include "../../common.h"

using namespace std;

namespace hit {

    CKKSCiphertext ExplicitDepthFinder::encrypt(const vector<double> &) {
        LOG_AND_THROW_STREAM("ExplicitDepthFinder does not define encrypt() with an implicit level");
    }

    CKKSCiphertext ExplicitDepthFinder::encrypt(const vector<double> &, int level) {
        if (level < 0) {
            LOG_AND_THROW_STREAM("Explicit encryption level must be non-negative, got " << level);
        }

        {
            shared_lock lock(mutex_);
            max_contiguous_depth = max(max_contiguous_depth, level);
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
    void ExplicitDepthFinder::print_stats(  // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
        const CKKSCiphertext &ct) {         // NOLINT(readability-convert-member-functions-to-static)
        VLOG(VLOG_EVAL) << "    + Explicit Level: " << ct.he_level();
    }

    int ExplicitDepthFinder::num_slots() const {
        return num_slots_;
    }

    void ExplicitDepthFinder::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        if (ct.he_level() == 0) {
            LOG_AND_THROW_STREAM("Cannot rescale a level 0 ciphertext.");
        }
        // CT level is adjusted in CKKSEvaluator::rescale_metata_to_next
    }

    int ExplicitDepthFinder::get_multiplicative_depth() const {
        shared_lock lock(mutex_);

        // max_contiguous_depth is set based on the maximum encryption level. Actual number of levels in the HE params
        // may be more than this, i.e., this is a lower bound.

        return max_contiguous_depth;
    }
}  // namespace hit
