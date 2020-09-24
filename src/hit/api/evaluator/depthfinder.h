// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../ciphertext.h"
#include "../evaluator.h"
#include "seal/context.h"
#include "seal/seal.h"

namespace hit {

    /* This evaluator's sole purpose is to compute the
     * multiplicative depth of a computation.
     *
     * There is an implicit assumption that the multiplicative depth
     * does not depend on the homomorphic parameters.
     */
    class DepthFinder : public CKKSEvaluator {
       public:

        DepthFinder() = default;

        explicit DepthFinder(const std::shared_ptr<seal::SEALContext> &context);

        /* For documentation on the API, see ../evaluator.h */
        ~DepthFinder() override = default;

        DepthFinder(const DepthFinder &) = delete;
        DepthFinder &operator=(const DepthFinder &) = delete;
        DepthFinder(DepthFinder &&) = delete;
        DepthFinder &operator=(DepthFinder &&) = delete;

        CKKSCiphertext encrypt(const std::vector<double> &coeffs, int level = -1) override;

        /* Return the multiplicative depth of this computation.
         * Must be called after performing the target computation.
         * Not available for all concrete evaluators.
         */
        int get_multiplicative_depth() const;

       protected:
        void rotate_right_inplace_internal(CKKSCiphertext &ct, int steps) override;

        void rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) override;

        void negate_inplace_internal(CKKSCiphertext &ct) override;

        void add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) override;

        void add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) override;

        void add_plain_inplace_internal(CKKSCiphertext &ct, const std::vector<double> &plain) override;

        void sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) override;

        void sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) override;

        void sub_plain_inplace_internal(CKKSCiphertext &ct, const std::vector<double> &plain) override;

        void multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) override;

        void multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) override;

        void multiply_plain_inplace_internal(CKKSCiphertext &ct, const std::vector<double> &plain) override;

        void square_inplace_internal(CKKSCiphertext &ct) override;

        void reduce_level_to_inplace_internal(CKKSCiphertext &ct, int level) override;

        void rescale_to_next_inplace_internal(CKKSCiphertext &ct) override;

        void relinearize_inplace_internal(CKKSCiphertext &ct) override;

        // reuse this evaluator for another computation
        void reset_internal() override;

       private:
        int multiplicative_depth_ = 0;
        // We can't make this value `const` even though DepthFinder
        // doesn't update it. The reason is that DepthFinder works when
        // top_he_level_ is 0, but other evaluators which depend on
        // DepthFinder (like ScaleEstimator) have to update this value
        // to work correctly.
        int top_he_level_ = 0;

        void print_stats(const CKKSCiphertext &ct) const;

        friend class ScaleEstimator;
        friend class OpCount;
    };
}  // namespace hit
