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

    // sets the HE level of the output of a binary operation
    // When both inputs have been bootstrapped or when both inputs have *not* been bootstrapped,
    // CKKSEvaluator throws and error if the HE levels of the inputs are not identical. However,
    // when one input has been bootstrapped and one has not, their levels will necessarily be
    // unequal. This function handles that case and ensures accurate tracking of the computation
    // depth in the presence of bootstrapping.
    void ImplicitDepthFinder::set_bootstrap_depth(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        if (ct1.bootstrapped() != ct2.bootstrapped()) { 
            scoped_lock lock(mutex_);
            // levels will not be aligned.
            // create references to the bootstrapped and non-bootstrapped (fresh) ciphertexts
            const CKKSCiphertext &bootstrapped_ct = ct1.bootstrapped() ? ct1 : ct2;
            const CKKSCiphertext &fresh_ct = ct1.bootstrapped() ? ct2 : ct1;

            // An operation that combines a bootstrapped and non-bootstrapped ciphertext gives us
            // explicit information about how many levels are devoted to bootstrapping. A freshly
            // bootstrapped CT has (relative) level 0, so we can use the level of the non-bootstrapped ciphertext
            // (relative to a *different* 0) to determine the depth of the bootstrapping circuit. 
            // The difference between the HE levels of the inputs yields the depth of the bootstrapping
            // circuit.
            int btp_levels = bootstrapped_ct.he_level() - fresh_ct.he_level();
            // If we have not yet observed this relationship before, set it now.
            if (bootstrap_depth_ < 0) {
                // we have not yet set the bootstrap_depth_, which should be >= 0.
                if (btp_levels >= 0) {
                    bootstrap_depth_ = btp_levels;
                } else {
                    LOG_AND_THROW_STREAM("Internal error: btp_levels is < 0: " << btp_levels);
                }
            } else {
                // we have previously set the bootstrap_depth_; make sure we get the same value.
                // There is only one "right" relationship
                if (bootstrap_depth_ != btp_levels) {
                    LOG_AND_THROW_STREAM("Circuit error: bootstrap_depth_ is was previously set to "
                                         << bootstrap_depth_ << ", but now is " << btp_levels);
                }
            }
            // we set the `bootstrapped` flag to true if exactly one input has been bootstrapped,
            // so set the he_level of the output accordingly
            ct1.he_level_ = bootstrapped_ct.he_level();
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
        scoped_lock lock(mutex_);
        if (ct.bootstrapped()) {
            post_bootstrap_depth_ = max(post_bootstrap_depth_, 1 - ct.he_level());
        } else {
            max_contiguous_depth = max(max_contiguous_depth, 1 - ct.he_level());
        }
        // CT level is adjusted in CKKSEvaluator::rescale_metata_to_next
    }

    CKKSCiphertext ImplicitDepthFinder::bootstrap_internal(const CKKSCiphertext &ct, bool rescale_for_bootstrapping) {
        CKKSCiphertext bootstrapped_ct = ct;
        scoped_lock lock(mutex_);
        if (ct.bootstrapped()) {
            // this ciphertext has already been bootstrapped
            post_bootstrap_depth_ =
                max(post_bootstrap_depth_, static_cast<int>(rescale_for_bootstrapping) - ct.he_level());
        } else {
            // this ciphertext has already been bootstrapped
            max_contiguous_depth =
                max(max_contiguous_depth, static_cast<int>(rescale_for_bootstrapping) - ct.he_level());
        }
        // CT bootstrapped_ is adjusted in CKKSEvaluator::bootstrap
        bootstrapped_ct.he_level_ = 0;
        uses_bootstrapping = true;
        return bootstrapped_ct;
    }

    int ImplicitDepthFinder::get_param_bootstrap_depth() const {
        shared_lock lock(mutex_);

        // if `bootstrap_depth_` is set, it is exact
        // by contrast, `max_contiguous_depth - post_bootstrap_depth_`
        // is a lower bound on the depth of the bootstrapping circuit.
        // Thus, if `bootstrap_depth_` is set, it is exact, it must be >= `max_contiguous_depth - post_bootstrap_depth_`
        if (bootstrap_depth_ >= 0 && bootstrap_depth_ < max_contiguous_depth - post_bootstrap_depth_) {
            LOG_AND_THROW_STREAM("Internal error: explicit bootstrap_depth is smaller than implicit bootstrap depth.");
        }

        return uses_bootstrapping ? max(bootstrap_depth_, max_contiguous_depth - post_bootstrap_depth_) : 0;
    }

    int ImplicitDepthFinder::get_param_eval_depth() const {
        shared_lock lock(mutex_);
        int btp_depth = get_param_bootstrap_depth();
        return max(max_contiguous_depth - btp_depth, post_bootstrap_depth_);
    }
}  // namespace hit
