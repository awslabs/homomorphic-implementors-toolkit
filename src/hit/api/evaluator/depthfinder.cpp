// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "depthfinder.h"

#include <glog/logging.h>

#include "../../common.h"

using namespace std;

namespace hit {

    DepthFinder::DepthFinder(int post_btp_lvl) {
        post_boostrapping_level = post_btp_lvl;
        post_bootstrapping_scale = pow(2, default_scale_bits);
    }

    CKKSCiphertext DepthFinder::encrypt(const vector<double> &coeffs) {
        return encrypt(coeffs, 0);
    }

    CKKSCiphertext DepthFinder::encrypt(const vector<double> &, int level) {
        if (level < 0) {
            LOG_AND_THROW_STREAM("Explicit encryption level must be non-negative, got " << level);
        }

        if (post_boostrapping_level > 0 && level > post_boostrapping_level) {
            LOG_AND_THROW_STREAM("Explicit encryption level must be smaller than the post-boostrapping level, got "
                                 << level);
        }

        CKKSCiphertext destination;
        destination.he_level_ = level;
        // Using a default num_slots_ is potentially problematic if the depth of
        // the function depends on the number of slots. This seems like an unusual
        // situation, so its doesn't seem worth fixing.
        destination.num_slots_ = num_slots_;
        destination.initialized = true;
        destination.scale_ = pow(2, default_scale_bits);

        return destination;
    }

    // print some debug info
    void DepthFinder::print_stats(   // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
        const CKKSCiphertext &ct) {  // NOLINT(readability-convert-member-functions-to-static)
        VLOG(VLOG_EVAL) << "    +  Level: " << ct.he_level();
    }

    int DepthFinder::num_slots() const {
        return num_slots_;
    }

    void DepthFinder::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        scoped_lock lock(mutex_);
        circuit_depth = max(circuit_depth + 1, ct.implicit_depth + 1);
        // CT level is adjusted in CKKSEvaluator::rescale_metata_to_next
    }

    void DepthFinder::bootstrap_inplace_internal(CKKSCiphertext &ct, bool rescale_for_bootstrapping) {
        // if rescale_for_bootstrapping, bootstrapping will implicitly consume one additional level to rescale the
        // ciphertext first, ensure that if explict levels are set, we aren't already at level 0
        if (rescale_for_bootstrapping && ct.he_level() == 0) {
            LOG_AND_THROW_STREAM("Cannot rescale a level 0 ciphertext for bootstrapping");
        }
        // CT bootstrapped_ is adjusted in CKKSEvaluator::bootstrap
    }

    int DepthFinder::get_multiplicative_depth() const {
        shared_lock lock(mutex_);

        // max_contiguous_depth is set based on the maximum encryption level. Actual number of levels in the HE params
        // may be more than this, i.e., this is a lower bound.

        return circuit_depth;
    }
}  // namespace hit
