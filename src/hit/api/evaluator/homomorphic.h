// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../../common.h"
#include "../ciphertext.h"
#include "../evaluator.h"
#include "../params.h"

namespace hit {

    /* This evaluator is a thin wrapper around
     * SEAL's evaluator API. It actually does
     * computation on SEAL ciphertexts.
     */
    class HomomorphicEval : public CKKSEvaluator {
       public:
        /* Construct a homomorphic evaluator instance for the provided scheme parameters.
         * This will generate keys for encryption, decryption, and relinearization in all cases.
         * Additionally, generates rotation (Galois) keys for the shifts provided in the galois_steps
         * vector. For example, if your circuit calls `rotate_left(ct, 2)` and `rotate_right(ct, 3)`,
         * you should ensure that `galois_steps` includes [2, -3] (right shifts are negative). Including
         * unnecessary shifts results in longer key generation time and larger keys, while not including
         * all explicit rotations will result in a runtime error. You can use the RotationSet evaluator
         * to compute the necessary and sufficient `galois_steps` vector for your circuit.
         */
        explicit HomomorphicEval(const CKKSParams &params, const std::vector<int> &galois_steps = std::vector<int>());

        /* See comment above. */
        HomomorphicEval(int num_slots, int max_ct_level, int log_scale,
                        const std::vector<int> &galois_steps = std::vector<int>(), bool use_standard_params = true);

        /* An evaluation-only instance (decryption not available). */
        HomomorphicEval(std::istream &params_stream, std::istream &galois_key_stream, std::istream &relin_key_stream);

        /* A full instance capable of encryption, decryption, and evaluation. */
        HomomorphicEval(std::istream &params_stream, std::istream &galois_key_stream, std::istream &relin_key_stream,
                        std::istream &secret_key_stream);

        /* For documentation on the API, see ../evaluator.h */
        ~HomomorphicEval() override;

        HomomorphicEval(const HomomorphicEval &) = delete;
        HomomorphicEval &operator=(const HomomorphicEval &) = delete;
        HomomorphicEval(HomomorphicEval &&) = delete;
        HomomorphicEval &operator=(HomomorphicEval &&) = delete;

        // set secret_key_stream to nullptr to serialize an evaluation-only instance
        void save(std::ostream &params_stream, std::ostream &galois_key_stream, std::ostream &relin_key_stream,
                  std::ostream *secret_key_stream);

        CKKSCiphertext encrypt(const std::vector<double> &coeffs) override;
        CKKSCiphertext encrypt(const std::vector<double> &coeffs, int level) override;

        /* A warning will show in log if you decrypt when the ciphertext is not at level 0
         * Usually, decrypting a ciphertext not at level 0 indicates you are doing something
         * inefficient. However you may want to suppress the warning for testing either by
         * setting suppress_warnings=true or by setting the log level to 0.
         */
        std::vector<double> decrypt(const CKKSCiphertext &encrypted) override;
        std::vector<double> decrypt(const CKKSCiphertext &encrypted, bool suppress_warnings) override;

        std::shared_ptr<HEContext> context;

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
        seal::CKKSEncoder *backend_encoder = nullptr;  // no default constructor
        seal::Evaluator *backend_evaluator = nullptr;  // no default constructor
        seal::Encryptor *backend_encryptor = nullptr;  // no default constructor
        seal::Decryptor *backend_decryptor = nullptr;  // no default constructor
        seal::PublicKey pk;
        seal::SecretKey sk;
        seal::GaloisKeys galois_keys;
        seal::RelinKeys relin_keys;
        bool standard_params_;

        uint64_t get_last_prime_internal(const CKKSCiphertext &ct) const override;
        void deserializeEvalKeys(const timepoint &start, std::istream &galois_key_stream,
                                 std::istream &relin_key_stream);

        void deserialize_common(std::istream &params_stream);

        friend class DebugEval;
        friend class ScaleEstimator;
    };
}  // namespace hit
