// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../ciphertext.h"
#include "../evaluator.h"
#include "homomorphic.h"
#include "scaleestimator.h"

namespace hit {

    /* This is the full debug evaluator. It combines all of the
     * other evaluators, thereby tracking all information
     * from DepthFinder, PlaintextEval, and ScaleEstimator,
     * as well as performing the ciphertext operations.
     */

    class DebugEval : public CKKSEvaluator {
       public:
        /* The `use_seal_params` flag allows you to restrict to SEAL parameters, or to use larger
         * rings. The SEAL paramters are designed to achieve 128-bits of security, while setting
         * `use_seal_params` to false allows you to set parameters which may not achieve 128-bits
         * of security.
         */
        DebugEval(int num_slots, int multiplicative_depth, int log_scale, bool use_seal_params = true,
                  const std::vector<int> &galois_steps = std::vector<int>());

        DebugEval(std::istream &params_stream, std::istream &galois_key_stream, std::istream &relin_key_stream,
                  std::istream &secret_key_stream);

        /* For documentation on the API, see ../evaluator.h */
        ~DebugEval() override;

        DebugEval(const DebugEval &) = delete;
        DebugEval &operator=(const DebugEval &) = delete;
        DebugEval(DebugEval &&) = delete;
        DebugEval &operator=(DebugEval &&) = delete;

        void save(std::ostream &params_stream, std::ostream &galois_key_stream, std::ostream &relin_key_stream,
                  std::ostream &secret_key_stream);

        CKKSCiphertext encrypt(const std::vector<double> &coeffs) override;
        CKKSCiphertext encrypt(const std::vector<double> &coeffs, int level) override;

        /* A warning will show in log if you decrypt when the ciphertext is not at level 0
         * Usually, decrypting a ciphertext not at level 0 indicates you are doing something
         * inefficient. However for testing purposes, it may be useful, so you will want to
         * suppress the warning.
         */
        std::vector<double> decrypt(const CKKSCiphertext &encrypted) override;
        std::vector<double> decrypt(const CKKSCiphertext &encrypted, bool suppress_warnings) override;

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

        void relinearize_inplace_internal(CKKSCiphertext &ct) override;

       private:
        uint64_t get_last_prime_internal(const CKKSCiphertext &ct) const override;

        HomomorphicEval *homomorphic_eval;
        ScaleEstimator *scale_estimator;

        void print_stats(const CKKSCiphertext &ct) override;
        void constructor_common(int num_slots);
        void print_parameters();
        int totalModBitCount();
    };
}  // namespace hit
