// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../ciphertext.h"
#include "../evaluator.h"
#include "depthfinder.h"
#include "plaintext.h"
#include "seal/context.h"
#include "seal/seal.h"

namespace hit {

    /* This evaluator estimates the optimal CKKS scale to use for a computation.
     * Along the way, it tracks the scale of ciphertexts as well as their
     * theoretical maximum value.
     */
    class ScaleEstimator : public CKKSEvaluator {
       public:
        ScaleEstimator(const std::shared_ptr<seal::SEALContext> &context, int poly_deg, double baseScale);

        /* For documentation on the API, see ../evaluator.h */
        ~ScaleEstimator() override;

        ScaleEstimator(const ScaleEstimator &) = delete;
        ScaleEstimator &operator=(const ScaleEstimator &) = delete;
        ScaleEstimator(ScaleEstimator &&) = delete;
        ScaleEstimator &operator=(ScaleEstimator &&) = delete;

        // primarily used to indicate the maximum value for each *input* to the function.
        // For circuits which are a no-op, this function is the only way the evaluator
        // can learn the maximum plaintext values, and thereby appropriately restrict the scale.
        void update_plaintext_max_val(double x);

        // return the base-2 log of the maximum plaintext value in the computation
        // this is useful for putting an upper bound on the scale parameter
        double get_exact_max_log_plain_val() const;

        // return the base-2 log of the maximum scale that can be used for this
        // computation. Using a scale larger than this will result in the plaintext
        // exceeding SEAL's maximum size, and using a scale smaller than this value
        // will unnecessarily reduce precision of the computation.
        double get_estimated_max_log_scale() const;

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

        void mod_down_to_level_inplace_internal(CKKSCiphertext &ct, int level) override;

        void rescale_to_next_inplace_internal(CKKSCiphertext &ct) override;

        void relinearize_inplace_internal(CKKSCiphertext &ct) override;

        // reuse this evaluator for another computation
        void reset_internal() override;

       private:
        PlaintextEval *ptEval;
        DepthFinder *dfEval;

        void print_stats(const CKKSCiphertext &ct);
        void update_max_log_scale(const CKKSCiphertext &ct);
        double estimatedMaxLogScale;
        const double baseScale;
        int poly_deg;

        friend class DebugEval;
    };
}  // namespace hit
