// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../ciphertext.h"
#include "../evaluator.h"
#include "depthfinder.h"
#include "seal/context.h"
#include "seal/seal.h"

namespace hit {

    /* This evaluator tracks the plaintext computation */
    class OpCount : public CKKSEvaluator {
       public:
        explicit OpCount(const std::shared_ptr<seal::SEALContext> &context);

        /* For documentation on the API, see ../evaluator.h */
        ~OpCount() override;

        OpCount(const OpCount &) = delete;
        OpCount &operator=(const OpCount &) = delete;
        OpCount(OpCount &&) = delete;
        OpCount &operator=(OpCount &&) = delete;

        /* Print the total number of operations performed in this computation. */
        void print_op_count() const;

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

        void mod_down_to_level_inplace_internal(CKKSCiphertext &ct, int level) override;

        void rescale_to_next_inplace_internal(CKKSCiphertext &ct) override;

        void relinearize_inplace_internal(CKKSCiphertext &ct) override;

        // reuse this evaluator for another computation
        void reset_internal() override;

       private:
        int multiplies = 0;
        int additions = 0;
        int negations = 0;
        int rotations = 0;
        int modDowns = 0;
        int modDownMuls = 0;

        inline void count_multiple_ops() {
            std::scoped_lock lock(mutex_);
            multiplies++;
        }

        inline void count_addition_ops() {
            std::scoped_lock lock(mutex_);
            additions++;
        }

        inline void count_rotation_ops() {
            std::scoped_lock lock(mutex_);
            rotations++;
        }

        DepthFinder *dfEval;
    };
}  // namespace hit
