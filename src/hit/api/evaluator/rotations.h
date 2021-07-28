// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <set>
#include <vector>

#include "../ciphertext.h"
#include "../evaluator.h"

namespace hit {

    /* This evaluator tracks the plaintext computation to determine the set of explicit
     * rotations performed by the circuit. The output of `needed_rotations` is a vector
     * suitable for the `galois_steps` argument of the HomomorphicEvaluator or DebugEvaluator
     * constructors
     */
    class RotationSet : public CKKSEvaluator {
       public:
        explicit RotationSet(int num_slots);

        /* For documentation on the API, see ../evaluator.h */
        ~RotationSet() override = default;

        RotationSet(const RotationSet &) = delete;
        RotationSet &operator=(const RotationSet &) = delete;
        RotationSet(RotationSet &&) = delete;
        RotationSet &operator=(RotationSet &&) = delete;

        /* Return the total number of operations performed in this computation. */
        std::vector<int> needed_rotations() const;

        CKKSCiphertext encrypt(const std::vector<double> &coeffs) override;
        CKKSCiphertext encrypt(const std::vector<double> &coeffs, int level) override;

       protected:
        void rotate_right_inplace_internal(CKKSCiphertext &ct, int k) override;

        void rotate_left_inplace_internal(CKKSCiphertext &ct, int k) override;

        int num_slots() const override;

       private:
        std::set<int> rotations;
        int num_slots_;
    };
}  // namespace hit
