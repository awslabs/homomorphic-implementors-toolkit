// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../ciphertext.h"
#include "../evaluator.h"
#include "depthfinder.h"
#include "homomorphic.h"
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
        /* The number of slots is a proxy for the dimension of the underlying cyclotomic ring.
         * This limits the maximum size of the plaintext vector to `num_slots`, and also limits
         * the maximum size of the modulus. For a fixed multiplicative depth, this imposes a
         * corresponding limit on the scale, and thus the precision, of the computation.
         * There's no good way to know what value to use here without generating some parameters
         * first. Reasonable values include 4096, 8192, or 16384.
         * `multiplicative_depth` is the multiplicative depth of the circuit you wish to evaluate.
         * You can use the DepthFinder evaluator to compute this.
         */
        ScaleEstimator(int num_slots, int multiplicative_depth);

        /* For documentation on the API, see ../evaluator.h */
        ~ScaleEstimator() override;

        ScaleEstimator(const ScaleEstimator &) = delete;
        ScaleEstimator &operator=(const ScaleEstimator &) = delete;
        ScaleEstimator(ScaleEstimator &&) = delete;
        ScaleEstimator &operator=(ScaleEstimator &&) = delete;

        // return the base-2 log of the maximum scale that can be used for this
        // computation. Using a scale larger than this will result in the plaintext
        // exceeding SEAL's maximum size, and using a scale smaller than this value
        // will unnecessarily reduce precision of the computation.
        double get_estimated_max_log_scale() const;

        CKKSCiphertext encrypt(const std::vector<double> &coeffs, int level = -1) override;

        std::shared_ptr<seal::SEALContext> context;

        int num_slots() const override;

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

       private:
        const int log_scale_ = 0;
        const int num_slots_ = 0;
        ScaleEstimator(int num_slots, const HomomorphicEval &homom_eval);
        bool has_shared_params_ = false;

        PlaintextEval *plaintext_eval;

        double estimated_max_log_scale_;

        // This helper function squares the scale of the input and then updates
        // the max_log_scale.
        void temp_square_scale(CKKSCiphertext &ct);
        void print_stats(const CKKSCiphertext &ct) const override;
        void update_max_log_scale(const CKKSCiphertext &ct);

        uint64_t get_last_prime_internal(const CKKSCiphertext &ct) const override;

        // primarily used to indicate the maximum value for each *input* to the function.
        // For circuits which are a no-op, this function is the only way the evaluator
        // can learn the maximum plaintext values, and thereby appropriately restrict the scale.
        void update_plaintext_max_val(const std::vector<double> &coeffs);

        friend class DebugEval;
    };
}  // namespace hit
