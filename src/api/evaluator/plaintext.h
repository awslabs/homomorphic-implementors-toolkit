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
        PlaintextEval(const std::shared_ptr<seal::SEALContext> &context, bool verbose);

        /* For documentation on the API, see ../evaluator.h */
        ~PlaintextEval() override;

        PlaintextEval(const PlaintextEval &) = delete;
        PlaintextEval &operator=(const PlaintextEval &) = delete;
        PlaintextEval(PlaintextEval &&) = delete;
        PlaintextEval &operator=(PlaintextEval &&) = delete;

        // return the base-2 log of the maximum plaintext value in the computation
        // this is useful for putting an upper bound on the scale parameter
        double getExactMaxLogPlainVal() const;

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

        CKKSCiphertext multiply_plain_mat_internal(const CKKSCiphertext &ct, const std::vector<double> &plain) override;

        CKKSCiphertext multiply_plain_internal(const CKKSCiphertext &ct, double scalar) override;

        CKKSCiphertext multiply_plain_internal(const CKKSCiphertext &ct, const std::vector<double> &plain) override;

        CKKSCiphertext square_internal(const CKKSCiphertext &ct) override;

        CKKSCiphertext mod_down_to_internal(const CKKSCiphertext &ct, const CKKSCiphertext &target) override;

        void mod_down_to_min_inplace_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) override;

        CKKSCiphertext mod_down_to_level_internal(const CKKSCiphertext &ct, int level) override;

        CKKSCiphertext rescale_to_next_internal(const CKKSCiphertext &ct) override;

        void rescale_to_next_inplace_internal(CKKSCiphertext &ct) override;

        void relinearize_inplace_internal(CKKSCiphertext &ct) override;

        // reuse this evaluator for another computation
        void reset_internal() override;

       private:
        void updateMaxLogPlainVal(const CKKSCiphertext &ct);

        void print_stats(const CKKSCiphertext &ct) const;

        double ptMaxLog;

        friend class ScaleEstimator;
    };
}  // namespace hit
