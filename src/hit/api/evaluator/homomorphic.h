// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../ciphertext.h"
#include "../evaluator.h"
#include "seal/context.h"
#include "seal/seal.h"

namespace hit {

    /* This evaluator is a thin wrapper around
     * SEAL's evaluator API. It actually does
     * computation on SEAL ciphertexts.
     */
    class HomomorphicEval : public CKKSEvaluator {
       public:
        /* This provides the 'production' evaluator, which just offers an improved
         * API without debug information.
         *
         * All of these parameters contain only public information. The GaloisKeys
         * and RelinKeys are part of the CKKS scheme's "evaluation keys".
         *
         * update_metadata indicates whether this evaluator should update ciphertext metadata or not
         * When HomomorphicEval is used alone, update_metadata should be true.
         * When HomomorphicEval is used as a sub-evaluator (e.g., as a component of the Debug evaluator) where
         * other sub-evaluators compute the metadata, then update_metadata should be false.
         *
         * The `use_seal_params` flag allows you to restrict to SEAL parameters, or to use larger
         * rings. The SEAL paramters are designed to achieve 128-bits of security, while setting
         * `use_seal_params` to false allows you to set parameters which may not achieve 128-bits
         * of security.
         */
        HomomorphicEval(int num_slots, int multiplicative_depth, int log_scale, bool use_seal_params = true,
                        const std::vector<int> &galois_steps = std::vector<int>());

        /* An evaluation instance */
        HomomorphicEval(std::istream &params_stream, std::istream &galois_key_stream,
                        std::istream &relin_key_stream);

        /* A full instance */
        HomomorphicEval(std::istream &params_stream, std::istream &galois_key_stream,
                        std::istream &relin_key_stream, std::istream &secret_key_stream);

        /* For documentation on the API, see ../evaluator.h */
        ~HomomorphicEval() override;

        HomomorphicEval(const HomomorphicEval &) = delete;
        HomomorphicEval &operator=(const HomomorphicEval &) = delete;
        HomomorphicEval(HomomorphicEval &&) = delete;
        HomomorphicEval &operator=(HomomorphicEval &&) = delete;

        // set secret_key_stream to nullptr to serialize an evaluation-only instance
        void save(std::ostream &params_stream, std::ostream &galois_key_stream, std::ostream &relin_key_stream,
                  std::ostream *secret_key_stream);

        CKKSCiphertext encrypt(const std::vector<double> &coeffs, int level = -1) override;

        /* A warning will show in log if you decrypt when the ciphertext is not at level 0
         * Usually, decrypting a ciphertext not at level 0 indicates you are doing something
         * inefficient. However for testing purposes, it may be useful, so you will want to
         * suppress the warning.
         * TODO: log level?
         */
        std::vector<double> decrypt(const CKKSCiphertext &encrypted) const override;

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

        /* WARNING: Multiplying by 0 results in non-constant time behavior! Only multiply by 0 if the scalar is truly
         * public. */
        void multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) override;

        void multiply_plain_inplace_internal(CKKSCiphertext &ct, const std::vector<double> &plain) override;

        void square_inplace_internal(CKKSCiphertext &ct) override;

        void reduce_level_to_inplace_internal(CKKSCiphertext &ct, int level) override;

        void rescale_to_next_inplace_internal(CKKSCiphertext &ct) override;

        void relinearize_inplace_internal(CKKSCiphertext &ct) override;

       private:

        uint64_t get_last_prime_internal(const CKKSCiphertext &ct) const override;

        void deserialize_common(std::istream &params_stream);

        friend class DebugEval;
    };
}  // namespace hit
