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
     */
    class DepthFinder : public CKKSEvaluator {
       public:
        DepthFinder(const std::shared_ptr<seal::SEALContext> &context, bool verbose);

        /* For documentation on the API, see ../evaluator.h */
        ~DepthFinder() override;

        DepthFinder(const DepthFinder &) = delete;
        DepthFinder &operator=(const DepthFinder &) = delete;
        DepthFinder(DepthFinder &&) = delete;
        DepthFinder &operator=(DepthFinder &&) = delete;

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

        void mod_down_to_inplace_internal(CKKSCiphertext &ct, const CKKSCiphertext &target) override;

        void mod_down_to_min_inplace_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) override;

        void mod_down_to_level_inplace_internal(CKKSCiphertext &ct, int level) override;

        void rescale_to_next_inplace_internal(CKKSCiphertext &ct) override;

        void relinearize_inplace_internal(CKKSCiphertext &ct) override;

        // reuse this evaluator for another computation
        void reset_internal() override;

       private:
        int multiplicativeDepth;

        void print_stats(const CKKSCiphertext &ct) const;

        friend class ScaleEstimator;
        friend class OpCount;
    };
}  // namespace hit