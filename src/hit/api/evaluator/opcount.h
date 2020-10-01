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
        OpCount() = default;

        /* For documentation on the API, see ../evaluator.h */
        ~OpCount() override = default;

        OpCount(const OpCount &) = delete;
        OpCount &operator=(const OpCount &) = delete;
        OpCount(OpCount &&) = delete;
        OpCount &operator=(OpCount &&) = delete;

        /* Print the total number of operations performed in this computation. */
        void print_op_count() const;

        CKKSCiphertext encrypt(const std::vector<double> &coeffs, int level = -1) override;

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

       private:
        int multiplies_ = 0;
        int additions_ = 0;
        int negations_ = 0;
        int rotations_ = 0;
        int reduce_levels_ = 0;
        int reduce_level_muls_ = 0;
        int encryptions_ = 0;
        int rescales_ = 0;
        int relins_ = 0;
        const int num_slots_ = 4096;

        inline void count_multiple_ops() {
            std::scoped_lock lock(mutex_);
            multiplies_++;
        }

        inline void count_addition_ops() {
            std::scoped_lock lock(mutex_);
            additions_++;
        }

        inline void count_rotation_ops() {
            std::scoped_lock lock(mutex_);
            rotations_++;
        }
    };
}  // namespace hit
