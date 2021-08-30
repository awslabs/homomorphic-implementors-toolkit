// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../ciphertext.h"
#include "../evaluator.h"

namespace hit {
    /* This evaluator tracks the plaintext computation */
    class PlaintextEval : public CKKSEvaluator {
       public:
        /* The number of slots is a proxy for the dimension of the underlying cyclotomic ring.
         * This limits the maximum size of the plaintext vector to `num_slots`, and also limits
         * the maximum size of the modulus. For a fixed multiplicative depth, this imposes a
         * corresponding limit on the scale, and thus the precision, of the computation.
         * There's no good way to know what value to use here without generating some parameters
         * first. Reasonable values include 4096, 8192, or 16384.
         */
        explicit PlaintextEval(int num_slots, int post_btp_lvl = -1);

        /* For documentation on the API, see ../evaluator.h */
        ~PlaintextEval() override = default;

        PlaintextEval(const PlaintextEval &) = delete;
        PlaintextEval &operator=(const PlaintextEval &) = delete;
        PlaintextEval(PlaintextEval &&) = delete;
        PlaintextEval &operator=(PlaintextEval &&) = delete;

        // Return the base-2 log of the maximum plaintext value in the computation.
        // This is useful for putting an upper bound on the scale parameter.
        double get_exact_max_log_plain_val() const;

        CKKSCiphertext encrypt(const std::vector<double> &coeffs) override;
        CKKSCiphertext encrypt(const std::vector<double> &coeffs, int level) override;

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

        int num_slots() const override;

       private:
        const int num_slots_ = 0;

        void update_max_log_plain_val(const CKKSCiphertext &ct);

        void print_stats(const CKKSCiphertext &ct) override;

        double plaintext_max_log_ = -100;

        friend class ScaleEstimator;
    };
}  // namespace hit
