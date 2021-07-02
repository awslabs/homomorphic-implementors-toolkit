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

    void ImplicitDepthFinder::set_bootstrap_depth(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        if (ct1.bootstrapped() != ct2.bootstrapped()) {
            // levels will not be aligned.
            const CKKSCiphertext &bootstrapped_ct = ct1.bootstrapped() ? ct1 : ct2;
            const CKKSCiphertext &fresh_ct = ct1.bootstrapped() ? ct2 : ct1;

            int btp_levels = bootstrapped_ct.he_level() - fresh_ct.he_level();
            if (bootstrap_depth_ < 0) {
                // we have not yet set the bootstrap_depth_
                if (btp_levels >= 0) {
                    bootstrap_depth_ = btp_levels;
                } else {
                    LOG_AND_THROW_STREAM("Internal error: btp_levels is < 0: " << btp_levels);
                }
            } else {
                // we have previously set the bootstrap_depth_; make sure we get the same value.
                if (bootstrap_depth_ != btp_levels) {
                    LOG_AND_THROW_STREAM("Circuit error: bootstrap_depth_ is was previously set to "
                                         << bootstrap_depth_ << ", but now is " << btp_levels);
                }
            }
        }
    }

    void ImplicitDepthFinder::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        set_bootstrap_depth(ct1, ct2);
    }

    void ImplicitDepthFinder::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        set_bootstrap_depth(ct1, ct2);
    }

    void ImplicitDepthFinder::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        set_bootstrap_depth(ct1, ct2);
    }

    void ImplicitDepthFinder::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        /* The ImplicitDepthFinder is always created as a "depth 0" evaluator, meaning that with
         * the current implementation, the default (implicit) level is *always* 0.
         * All CTs start with he_level = 0, so reducing the level results in a negative he_level.
         * Then zero minus a negative number is positive, which accurately tracks the computation depth.
         */
        {
            scoped_lock lock(mutex_);
            if (ct.bootstrapped()) {
                post_bootstrap_depth_ = max(post_bootstrap_depth_, 1 - ct.he_level());
            } else {
                total_param_levels = max(total_param_levels, 1 - ct.he_level());
            }
        }
        // CT level is adjusted in CKKSEvaluator::rescale_metata_to_next
    }

    CKKSCiphertext ImplicitDepthFinder::bootstrap_internal(const CKKSCiphertext &ct, bool rescale_for_bootstrapping) {
        CKKSCiphertext bootstrapped_ct = ct;

        if (ct.bootstrapped()) {
            // this ciphertext has already been bootstrapped
            scoped_lock lock(mutex_);
            post_bootstrap_depth_ =
                max(post_bootstrap_depth_, static_cast<int>(rescale_for_bootstrapping) - ct.he_level());
        } else {
            // this ciphertext has already been bootstrapped
            scoped_lock lock(mutex_);
            total_param_levels = max(total_param_levels, static_cast<int>(rescale_for_bootstrapping) - ct.he_level());
        }
        // CT bootstrapped_ is adjusted in CKKSEvaluator::bootstrap
        bootstrapped_ct.he_level_ = 0;
        uses_bootstrapping = true;
        return bootstrapped_ct;
    }

    CircuitDepthResults ImplicitDepthFinder::get_multiplicative_depth() const {
        shared_lock lock(mutex_);
        struct CircuitDepthResults result;

        // bootstrap_depth_, if set, indicates the minimum number of bootstrapping levels
        //   If set, this value is exact.
        // post_bootstrap_depth_ is a lower bound on the number of post-bootstrapping levels
        // total_param_levels is a lower bound on the total number of levels

        result.uses_bootstrapping = uses_bootstrapping;
        result.min_bootstrap_depth = max(bootstrap_depth_, total_param_levels - post_bootstrap_depth_);
        result.min_post_boostrap_depth = max(total_param_levels - bootstrap_depth_, post_bootstrap_depth_);
        return result;
    }
}  // namespace hit
