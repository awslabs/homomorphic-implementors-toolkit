// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../../common.h"
#include "../ciphertext.h"
#include "../evaluator.h"

namespace hit {

    /* This evaluator's sole purpose is to compute the
     * multiplicative depth of a computation.
     *
     * There is an implicit assumption that the multiplicative depth
     * does not depend on the homomorphic parameters. When using this
     * evaluator, either all calls to encrypt must supply an explicit
     * encryption level, or all calls to encrypt must *not* supply
     * an encryption level. Having some calls which specify a level
     * and some which do not is not permitted.
     */
    class ExplicitDepthFinder : public CKKSEvaluator {
       public:
        ExplicitDepthFinder() = default;

        /* For documentation on the API, see ../evaluator.h */
        ~ExplicitDepthFinder() override = default;

        ExplicitDepthFinder(const ExplicitDepthFinder &) = delete;
        ExplicitDepthFinder &operator=(const ExplicitDepthFinder &) = delete;
        ExplicitDepthFinder(ExplicitDepthFinder &&) = delete;
        ExplicitDepthFinder &operator=(ExplicitDepthFinder &&) = delete;

        CKKSCiphertext encrypt(const std::vector<double> &coeffs) override;  // throws an error
        CKKSCiphertext encrypt(const std::vector<double> &coeffs, int level) override;

        /* Return the multiplicative depth of this computation.
         * Must be called after performing the target computation.
         * Not available for all concrete evaluators.
         */
        CircuitDepthResults get_multiplicative_depth() const;

        int num_slots() const override;

       protected:
        void add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) override;

        void sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) override;

        void multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) override;

        void rescale_to_next_inplace_internal(CKKSCiphertext &ct) override;

        CKKSCiphertext bootstrap_internal(const CKKSCiphertext &ct, bool rescale_for_bootstrapping) override;

       private:
        const int num_slots_ = 4096;
        // We can't make this value `const` even though ExplicitDepthFinder
        // doesn't update it. The reason is that ExplicitDepthFinder works when
        // top_he_level_ is 0, but other evaluators which depend on
        // ExplicitDepthFinder (like ScaleEstimator) have to update this value
        // to work correctly.
        int explicit_post_bootstrap_depth_ = -1;
        int implicit_post_bootstrap_depth_ = 0;
        int total_param_levels = 0;
        bool uses_bootstrapping = false;

        void print_stats(const CKKSCiphertext &ct) override;
        void set_explicit_post_bootstrap_depth(CKKSCiphertext &ct1, const CKKSCiphertext &ct2);

        friend class ScaleEstimator;
        friend class OpCount;
    };
}  // namespace hit
