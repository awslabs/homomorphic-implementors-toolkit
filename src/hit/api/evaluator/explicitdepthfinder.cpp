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

        max_contiguous_depth = max(max_contiguous_depth, level);

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

    // sets the HE level of the output of a binary operation
    // When both inputs have been bootstrapped or when both inputs have *not* been bootstrapped,
    // CKKSEvaluator throws and error if the HE levels of the inputs are not identical. However,
    // when one input has been bootstrapped and one has not, their levels will necessarily be
    // unequal. This function handles that case and ensures accurate tracking of the computation
    // depth in the presence of bootstrapping.
    void ExplicitDepthFinder::set_explicit_post_bootstrap_depth(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // This function only handles the case where the bootstrapped() status is different; the case where
        // they are the same is handled by CKKSEvaluator
        if (ct1.bootstrapped() != ct2.bootstrapped()) {
            // levels will not be aligned.
            // create references to the bootstrapped and non-bootstrapped (fresh) ciphertexts
            const CKKSCiphertext &bootstrapped_ct = ct1.bootstrapped() ? ct1 : ct2;
            const CKKSCiphertext &fresh_ct = ct1.bootstrapped() ? ct2 : ct1;

            // An operation that combines a bootstrapped and non-bootstrapped ciphertext gives us
            // explicit information about how many levels are devoted to bootstrapping. A freshly
            // bootstrapped CT has (relative) level 0, so we can use the level of the non-bootstrapped ciphertext
            // to determine the absolute level of a freshly-bootstrapped ciphertext. Note that the
            // fresh ciphertext has a non-negative level that decreases from the explicit encryption
            // level, while the bootstrapped ciphertext has a non-positive level that starts at 0 and
            // decreases. Thus their difference yields the absolute level of a bootstrapped ciphertext.
            int explicit_bootstrap_lvl = fresh_ct.he_level() - bootstrapped_ct.he_level();
            // If we have not yet observed this relationship before, set it now.
            if (explicit_post_bootstrap_depth_ < 0) {
                // we have not yet set the explicit_post_bootstrap_depth_, which should be >= 0.
                if (explicit_bootstrap_lvl >= 0) {
                    explicit_post_bootstrap_depth_ = explicit_bootstrap_lvl;
                } else {
                    LOG_AND_THROW_STREAM("Internal error: explicit_bootstrap_lvl is < 0: " << explicit_bootstrap_lvl);
                }
            } else {
                // we have previously set the explicit_post_bootstrap_depth_; make sure we get the same value this time.
                // There is only one "right" relationship
                if (explicit_post_bootstrap_depth_ != explicit_bootstrap_lvl) {
                    LOG_AND_THROW_STREAM("Circuit error: explicit_post_bootstrap_depth_ is was previously set to "
                                         << explicit_post_bootstrap_depth_ << ", but now is "
                                         << explicit_bootstrap_lvl);
                }
            }
            // we set the `bootstrapped` flag to true if exactly one input has been bootstrapped,
            // so set the he_level of the output accordingly
            ct1.he_level_ = bootstrapped_ct.he_level();
        }
    }

    void ExplicitDepthFinder::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        set_explicit_post_bootstrap_depth(ct1, ct2);
    }

    void ExplicitDepthFinder::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        set_explicit_post_bootstrap_depth(ct1, ct2);
    }

    void ExplicitDepthFinder::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        set_explicit_post_bootstrap_depth(ct1, ct2);
    }

    void ExplicitDepthFinder::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        if (!ct.bootstrapped_ && ct.he_level() == 0) {
            LOG_AND_THROW_STREAM("Cannot rescale a level 0 ciphertext.");
        }

        /* The ExplicitDepthFinder sets max_contiguous_depth on encryption. Here, we just need to track
         * the number of post-bootstrapping levels. Bootstrapped ciphertexts have an implicit level,
         * meaning it starts at 0 and goes down. Thus, if the input ciphertext has he_level -1, we have
         * already rescaled once after bootstrapping, and we are about to do so again. That means that
         * the post_bootstrap_depth is (at least) 2 = 1 - (-1).
         */
        if (ct.bootstrapped()) {
            scoped_lock lock(mutex_);
            implicit_post_bootstrap_depth_ = max(implicit_post_bootstrap_depth_, 1 - ct.he_level());
        }
        // CT level is adjusted in CKKSEvaluator::rescale_metata_to_next
    }

    CKKSCiphertext ExplicitDepthFinder::bootstrap_internal(const CKKSCiphertext &ct, bool rescale_for_bootstrapping) {
        // if rescale_for_bootstrapping, bootstrapping will implicitly consume one additional level to rescale the
        // ciphertext first, ensure that if explict levels are set, we aren't already at level 0
        if (rescale_for_bootstrapping && ct.he_level() == 0) {
            LOG_AND_THROW_STREAM("Cannot rescale a level 0 ciphertext for bootstrapping");
        }

        // see comment in rescale_to_next_inplace_internal for explanation of arithmetic,
        // and note that rescale_for_bootstrapping is either 0 or 1.
        if (ct.bootstrapped()) {
            scoped_lock lock(mutex_);
            implicit_post_bootstrap_depth_ =
                max(implicit_post_bootstrap_depth_, static_cast<int>(rescale_for_bootstrapping) - ct.he_level());
        }
        uses_bootstrapping = true;
        // CT bootstrapped_ is adjusted in CKKSEvaluator::bootstrap
        CKKSCiphertext bootstrapped_ct = ct;
        bootstrapped_ct.he_level_ = 0;
        return bootstrapped_ct;
    }

    int ExplicitDepthFinder::get_param_bootstrap_depth() const {
        shared_lock lock(mutex_);

        return max_contiguous_depth - get_param_eval_depth();
    }

    int ExplicitDepthFinder::get_param_eval_depth() const {
        shared_lock lock(mutex_);

        // max_contiguous_depth is set based on the maximum encryption level. Actual number of levels in the HE params
        // may be more than this, i.e., this is a lower bound. explicit_post_bootstrap_depth_, if set, defines exactly
        // how many post-boostrapping levels the parameters need.
        // The implicit_post_bootstrap_depth_, which is based on the number of rescales post-bootstrapping and/or
        // the level at which a bootstrapped ciphertext is re-bootstrapped, must be <=
        // explicit_post_bootstrap_depth_

        if (explicit_post_bootstrap_depth_ >= 0 && implicit_post_bootstrap_depth_ > explicit_post_bootstrap_depth_) {
            LOG_AND_THROW_STREAM("explicit_post_bootstrap_depth_ < implicit_post_bootstrap_depth_: "
                                 << explicit_post_bootstrap_depth_ << " < " << implicit_post_bootstrap_depth_);
        }
        return uses_bootstrapping ? max(implicit_post_bootstrap_depth_, explicit_post_bootstrap_depth_) : max_contiguous_depth;
    }
}  // namespace hit
