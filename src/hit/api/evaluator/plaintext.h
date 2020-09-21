// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../ciphertext.h"
#include "../evaluator.h"
#include "seal/context.h"
#include "seal/seal.h"

namespace hit {

    /* This evaluator tracks the plaintext computation */
    class PlaintextEval : public CKKSEvaluator {
       public:
        explicit PlaintextEval(const std::shared_ptr<seal::SEALContext> &context);

        /* For documentation on the API, see ../evaluator.h */
        ~PlaintextEval() override;

        PlaintextEval(const PlaintextEval &) = delete;
        PlaintextEval &operator=(const PlaintextEval &) = delete;
        PlaintextEval(PlaintextEval &&) = delete;
        PlaintextEval &operator=(PlaintextEval &&) = delete;

        // return the base-2 log of the maximum plaintext value in the computation
        // this is useful for putting an upper bound on the scale parameter
        double get_exact_max_log_plain_val() const;

        // primarily used to indicate the maximum value for each *input* to the function.
        // For circuits which are a no-op, this function is the only way the evaluator
        // can learn the maximum plaintext values.
        void update_plaintext_max_val(double x);

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
        void update_max_log_plain_val(const CKKSCiphertext &ct);

        void print_stats(const CKKSCiphertext &ct) const;

        double plaintext_max_log_;

        friend class ScaleEstimator;
    };
}  // namespace hit
