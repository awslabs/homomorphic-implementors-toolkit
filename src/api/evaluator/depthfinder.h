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
        int getMultiplicativeDepth() const;

       protected:
        CKKSCiphertext rotate_right_internal(const CKKSCiphertext &ct, int steps) override;

        CKKSCiphertext rotate_left_internal(const CKKSCiphertext &ct, int steps) override;

        CKKSCiphertext negate_internal(const CKKSCiphertext &ct) override;

        CKKSCiphertext add_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) override;

        CKKSCiphertext add_plain_internal(const CKKSCiphertext &ct, double scalar) override;

        CKKSCiphertext add_plain_internal(const CKKSCiphertext &ct, const std::vector<double> &plain) override;

        CKKSCiphertext sub_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) override;

        CKKSCiphertext sub_plain_internal(const CKKSCiphertext &ct, double scalar) override;

        CKKSCiphertext sub_plain_internal(const CKKSCiphertext &ct, const std::vector<double> &plain) override;

        CKKSCiphertext multiply_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) override;

        CKKSCiphertext multiply_plain_internal(const CKKSCiphertext &ct, double scalar) override;

        CKKSCiphertext multiply_plain_internal(const CKKSCiphertext &ct, const std::vector<double> &plain) override;

        CKKSCiphertext square_internal(const CKKSCiphertext &ct) override;

        CKKSCiphertext mod_down_to_internal(const CKKSCiphertext &ct, const CKKSCiphertext &target) override;

        void mod_down_to_min_inplace_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) override;

        CKKSCiphertext mod_down_to_level_internal(const CKKSCiphertext &ct, int level) override;

        CKKSCiphertext rescale_to_next_internal(const CKKSCiphertext &ct) override;

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
