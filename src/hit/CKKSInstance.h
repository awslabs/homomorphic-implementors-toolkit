// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "hit/protobuf/ckksparams.pb.h"
#include "seal/context.h"
#include "seal/seal.h"
#include "api/ciphertext.h"

namespace hit {

    /* Wraps SEAL boilerplate into a single object that
     * holds keys, encoders, encryptors, decryptors,
     * and other SEAL objects.
     * The intention is to use this API for encryption
     * and decryption, and to use the CKKSEvaluator
     * for evaluation.
     */

    enum Mode { OPCOUNT, DEPTH, PLAINTEXT, SCALE, NORMAL, DEBUG, EVALUATION, NONEVALUATION };

    class CKKSInstance {
       public:
        CKKSInstance() = default;

        ~CKKSInstance() = default;

        // Encrypt a (full-dimensional) vector of coefficients. If an encryption level (integer >= 0) is not specified,
        // the ciphertext will be encrypted at the highest level allowed by the parameters.
        virtual CKKSCiphertext encrypt(const std::vector<double> &coeffs, int level) = 0;


        virtual std::vector<double> decrypt(const CKKSCiphertext &ct) const;

        std::shared_ptr<seal::SEALContext> context;
        seal::EncryptionParameters *params = nullptr;
        seal::CKKSEncoder *encoder = nullptr;
        int log_scale_;

        CKKSInstance(const CKKSInstance &) = delete;
        CKKSInstance &operator=(const CKKSInstance &) = delete;
        CKKSInstance(CKKSInstance &&) = delete;
        CKKSInstance &operator=(CKKSInstance &&) = delete;

       protected:
        // instances without
        int gen_modulus_vec(int numPrimes, std::vector<int> &modulusVector) const;
        void set_max_val(const std::vector<double> &plain);
        void shared_param_init(int num_slots, int multiplicative_depth, int log_scale_in, bool use_seal_params);
        hit::protobuf::CKKSParams save_ckks_params();

        seal::Evaluator *seal_evaluator;
        seal::Encryptor *seal_encryptor = nullptr;
        seal::Decryptor *seal_decryptor = nullptr;
        // CKKSEncryptor *encryptor = nullptr;
        // CKKSDecryptor *decryptor = nullptr;
        seal::PublicKey pk;
        seal::SecretKey sk;
        seal::GaloisKeys galois_keys;
        seal::RelinKeys relin_keys;
        int encryption_count_ = 0;
        bool standard_params_;
        Mode mode_;
    };

    uint64_t estimate_key_size(int num_galois_shift, int plaintext_slots, int depth);

    // This function tries to load a prevously-generated instance from disk. Instances are parameterized by
    // the number of plaintext slots (num_slots), the multiplicative depth (multiplicative_depth), and the CKKS scale parameter
    // (log_scale). `mode` can be `NORMAL`, `DEBUG`, or `NONEVALUATION`. `NORMAL` results in a standard homomorphic
    // evaluator, while `DEBUG` loads a debug evaluator. `NONEVALUATION` is useful for cliend-side computation which
    // don't need to perform any evaluation. A `NONEVALUATION` instance can *ONLY* be used for encryption and
    // decryption.
    CKKSInstance *try_load_instance(int num_slots, int multiplicative_depth, int log_scale, Mode mode,
                                    const std::vector<int> &galois_steps = std::vector<int>());
}  // namespace hit
