// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "api/decryptor.h"
#include "api/encryptor.h"
#include "hit/protobuf/ckksparams.pb.h"  // NOLINT
#include "seal/context.h"
#include "seal/seal.h"

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

        // only for finding the depth of a computation
        // static CKKSInstance *get_new_depthfinder_instance();

        // only for counting the number of operations in the computation
        // static CKKSInstance *get_new_opcount_instance();

        /* only for doing plaintext computation
         * The number of slots is a proxy for the dimension of the underlying cyclotomic ring.
         * This limits the maximum size of the plaintext vector to `num_slots`, and also limits
         * the maximum size of the modulus. For a fixed multiplicative depth, this imposes a
         * corresponding limit on the scale, and thus the precision, of the computation.
         * There's no good way to know what value to use here without generating some parameters
         * first. Reasonable values include 4096, 8192, or 16384.
         * The `use_seal_params` flag allows you to restrict to SEAL parameters, or to use larger
         * rings. The SEAL paramters are designed to achieve 128-bits of security, while setting
         * `use_seal_params` to false allows you to set parameters which may not achieve 128-bits
         * of security.
         */
        // static CKKSInstance *get_new_plaintext_instance(int num_slots, bool use_seal_params = true);

        /* only for scale estimation
         * See the previous constuctor for an explanation of `num_slots`.
         * `multiplicative_depth` should be the output of `getMultiplicativeDepth`
         * using the DepthFinder evaluator.
         * See `get_new_plaintext_instance` for description of `use_seal_params`.
         */
        // static CKKSInstance *get_new_scaleestimator_instance(int num_slots, int multiplicative_depth, bool use_seal_params = true);

        /* Generate a CKKSInstance targeting the desired number of slots, multiplicative
         * depth and log(scale) value.
         * See `get_new_plaintext_instance` for description of `use_seal_params`.
         */
        // static CKKSInstance *get_new_homomorphic_instance(int num_slots, int multiplicative_depth, int log_scale,
        //                                                   bool use_seal_params = true,
        //                                                   const std::vector<int> &galois_steps = std::vector<int>());

        // static CKKSInstance *load_homomorphic_instance(std::istream &params_stream, std::istream &galois_key_stream,
        //                                                std::istream &relin_key_stream, std::istream &secret_key_stream);

        // void save(std::ostream *params_stream, std::ostream *galois_key_stream, std::ostream *relin_key_stream,
        //           std::ostream *secret_key_stream);

        /* Same as `get_new_homomorphic_instance`, except with verbose meta-data output and internal
         * tracking of relevant values to the computation
         * See `get_new_plaintext_instance` for description of `use_seal_params`.
         */
        // static CKKSInstance *get_new_debug_instance(int num_slots, int multiplicative_depth, int log_scale,
        //                                             bool use_seal_params = true,
        //                                             const std::vector<int> &galois_steps = std::vector<int>());

        /* Create a new debug instance from the provided parameters and keys */
        // static CKKSInstance *load_debug_instance(std::istream &params_stream, std::istream &galois_key_stream,
        //                                          std::istream &relin_key_stream, std::istream &secret_key_stream);

        /* For evaluation only. Decryption is not available. */
        // static CKKSInstance *load_eval_instance(std::istream &params_stream, std::istream &galois_key_stream,
        //                                         std::istream &relin_key_stream);

        /* For encryption and decryption only. Evaluation is not available. */
        // static CKKSInstance *load_noneval_instance(std::istream &params_stream, std::istream &secret_key_stream);

        ~CKKSInstance();

        // Encrypt a (full-dimensional) vector of coefficients. If an encryption level (integer >= 0) is not specified,
        // the ciphertext will be encrypted at the highest level allowed by the parameters.
        virtual CKKSCiphertext encrypt(const std::vector<double> &coeffs, int level) = 0;

        // A warning will show in log if you decrypt when the ciphertext is not at level 0
        // Usually, decrypting a ciphertext not at level 0 indicates you are doing something
        // inefficient. However for testing purposes, it may be useful, so you will want to
        // suppress the warning.
        virtual std::vector<double> decrypt(const CKKSCiphertext &encrypted) const = 0;

        int plaintext_dim() const;

        // CKKSEvaluator *evaluator;
        std::shared_ptr<seal::SEALContext> context;
        seal::EncryptionParameters *params = nullptr;
        seal::CKKSEncoder *encoder = nullptr;
        int log_scale_;

        // double get_estimated_max_log_scale() const;

        // int get_multiplicative_depth() const;

        // double get_exact_max_log_plain_val() const;

        // void print_op_count() const;

        // reuse this instance for another computation
        // void reset();

        CKKSInstance(const CKKSInstance &) = delete;
        CKKSInstance &operator=(const CKKSInstance &) = delete;
        CKKSInstance(CKKSInstance &&) = delete;
        CKKSInstance &operator=(CKKSInstance &&) = delete;

       protected:
        // instances without keys
        CKKSInstance(Mode mode, int num_slots, int multiplicative_depth, int log_scale, bool use_seal_params);

        // generate all keys
        CKKSInstance(int num_slots, int multiplicative_depth, int log_scale, bool use_seal_params, bool debug,
                     const std::vector<int> &galois_steps);

        // loading an instance from streams
        CKKSInstance(std::istream &params_stream, std::istream *galois_key_stream, std::istream *relin_key_stream,
                     std::istream *secret_key_stream, Mode mode);

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
