// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "implicitdepthfinder.h"

#include <glog/logging.h>

#include "../../common.h"

using namespace std;

namespace hit {

    CKKSCiphertext ImplicitDepthFinder::encrypt(const vector<double> &) {
        CKKSCiphertext destination;
        destination.he_level_ = 0;  // a default level
        // Using a default num_slots_ is potentially problematic if the depth of
        // the function depends on the number of slots. This seems like an unusual
        // situation, so its doesn't seem worth fixing.
        destination.num_slots_ = num_slots_;
        destination.initialized = true;
        return destination;
    }

    CKKSCiphertext ImplicitDepthFinder::encrypt(const std::vector<double> &, int) {
        LOG_AND_THROW_STREAM("ImplicitDepthFinder does not define encrypt() with an explicit level");
    }

    // print some debug info
    void ImplicitDepthFinder::print_stats(  // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
        const CKKSCiphertext &ct) {         // NOLINT(readability-convert-member-functions-to-static)
        VLOG(VLOG_EVAL) << "    + Implicit Level: " << ct.he_level();
    }

    int ImplicitDepthFinder::num_slots() const {
        return num_slots_;
    }

    void ImplicitDepthFinder::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        /* The ImplicitDepthFinder is always created as a "depth 0" evaluator, meaning that with
         * the current implementation, the default (implicit) level is *always* 0.
         * All CTs start with he_level = 0, so reducing the level results in a negative he_level.
         * Then zero minus a negative number is positive, which accurately tracks the computation depth.
         */
        scoped_lock lock(mutex_);
        max_contiguous_depth = max(max_contiguous_depth, 1 - ct.he_level());
        // CT level is adjusted in CKKSEvaluator::rescale_metata_to_next
    }

    int ImplicitDepthFinder::get_multiplicative_depth() const {
        shared_lock lock(mutex_);
        return max_contiguous_depth;
    }
}  // namespace hit
