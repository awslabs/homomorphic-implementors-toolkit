// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "api/decryptor.h"
#include "api/encryptor.h"
#include "api/evaluator.h"
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
        // only for finding the depth of a computation
        static CKKSInstance *get_new_depthfinder_instance(bool verbose = false);

        // only for counting the number of operations in the computation
        static CKKSInstance *get_new_opcount_instance(bool verbose = false);

        /* only for doing plaintext computation
         * The number of slots is a proxy for the dimension of the underlying cyclotomic ring.
         * This limits the maximum size of the plaintext vector to `numSlots`, and also limits
         * the maximum size of the modulus. For a fixed multiplicative depth, this imposes a
         * corresponding limit on the scale, and thus the precision, of the computation.
         * There's no good way to know what value to use here without generating some parameters
         * first. Reasonable values include 4096, 8192, or 16384.
         * The `useSEALParams` flag allows you to restrict to SEAL parameters, or to use larger
         * rings. The SEAL paramters are designed to achieve 128-bits of security, while setting
         * `useSEALParams` to false allows you to set parameters which may not achieve 128-bits
         * of security.
         */
        static CKKSInstance *get_new_plaintext_instance(int numSlots, bool verbose = false, bool useSEALParams = true);

        /* only for scale estimation
         * See the previous constuctor for an explanation of `numSlots`.
         * `multDepth` should be the output of `getMultiplicativeDepth`
         * using the DepthFinder evaluator.
         * See `get_new_plaintext_instance` for description of `useSEALParams`.
         */
        static CKKSInstance *get_new_scaleestimator_instance(int numSlots, int multDepth, bool verbose = false,
                                                          bool useSEALParams = true);

        /* Generate a CKKSInstance targeting the desired number of slots, multiplicative
         * depth and log(scale) value.
         * See `get_new_plaintext_instance` for description of `useSEALParams`.
         */
        static CKKSInstance *get_new_homomorphic_instance(int numSlots, int multDepth, int logScale, bool verbose = false,
                                                       bool useSEALParams = true,
                                                       const std::vector<int> &galois_steps = std::vector<int>());

        static CKKSInstance *load_homomorphic_instance(std::istream &paramsStream, std::istream &galoisKeyStream,
                                                     std::istream &relinKeyStream, std::istream &secretKeyStream,
                                                     bool verbose = false);

        void save(std::ostream *paramsStream, std::ostream *galoisKeyStream, std::ostream *relinKeyStream,
                  std::ostream *secretKeyStream);

        /* Same as `get_new_homomorphic_instance`, except with verbose meta-data output and internal
         * tracking of relevant values to the computation
         * See `get_new_plaintext_instance` for description of `useSEALParams`.
         */
        static CKKSInstance *get_new_debug_instance(int numSlots, int multDepth, int logScale, bool verbose = false,
                                                 bool useSEALParams = true,
                                                 const std::vector<int> &galois_steps = std::vector<int>());

        /* Create a new debug instance from the provided parameters and keys */
        static CKKSInstance *load_debug_instance(std::istream &paramsStream, std::istream &galoisKeyStream,
                                               std::istream &relinKeyStream, std::istream &secretKeyStream,
                                               bool verbose = false);

        /* For evaluation only. Decryption is not available. */
        static CKKSInstance *load_eval_instance(std::istream &paramsStream, std::istream &galoisKeyStream,
                                              std::istream &relinKeyStream, bool verbose = false);

        /* For encryption and decryption only. Evaluation is not available. */
        static CKKSInstance *load_noneval_instance(std::istream &paramsStream, std::istream &secretKeyStream,
                                                 bool verbose = false);

        ~CKKSInstance();

        void encrypt_matrix(const Matrix &mat, CKKSCiphertext &destination, int level = -1);

        /* Encrypt a C++ vector representing a linear algebra column vector.
         * We first encode the vector as a matrix
         * where each row is `plain`; see pplr.cpp for details.
         * This requires the target matrix height as a parameter.
         */
        void encrypt_col_vec(const std::vector<double> &plain, int matHeight, CKKSCiphertext &destination,
                           int level = -1);

        /* Encrypt a C++ vector representing a linear algebra row vector.
         * We first encode the vector as a matrix
         * where each column is `plain`; see pplr.cpp for details.
         * This requires the target matrix width as a parameter.
         */
        void encrypt_row_vec(const std::vector<double> &plain, int matWidth, CKKSCiphertext &destination, int level = -1);

        // verbose flag enables a warning if you decrypt when the ciphertext is not at level 0
        // Usually, decrypting a ciphertext not at level 0 indicates you are doing something
        // inefficient. However for testing purposes, it may be useful, so you will want to
        // suppress the warning.
        std::vector<double> decrypt(const CKKSCiphertext &encrypted, bool verbose = true);

        int plaintext_dim() const;

        CKKSEvaluator *evaluator;
        std::shared_ptr<seal::SEALContext> context;

        double get_estimated_max_log_scale() const;

        int get_multiplicative_depth() const;

        double get_exact_max_log_plain_val() const;

        void print_op_count() const;

        // reuse this instance for another computation
        void reset();

        CKKSInstance(const CKKSInstance &) = delete;
        CKKSInstance &operator=(const CKKSInstance &) = delete;
        CKKSInstance(CKKSInstance &&) = delete;
        CKKSInstance &operator=(CKKSInstance &&) = delete;

       private:
        // instances without keys
        CKKSInstance(Mode m, int numSlots, int multDepth, int logScale, bool verbose, bool useSEALParams);

        // generate all keys
        CKKSInstance(int numSlots, int multDepth, int logScale, bool verbose, bool useSEALParams, bool debug,
                     const std::vector<int> &galois_steps);

        // loading an instance from streams
        CKKSInstance(std::istream &paramsStream, std::istream *galoisKeyStream, std::istream *relinKeyStream,
                     std::istream *secretKeyStream, bool verbose, Mode m);

        int gen_modulus_vec(int numPrimes, std::vector<int> &modulusVector) const;
        void set_max_val(const std::vector<double> &plain);
        void shared_param_init(int numSlots, int multDepth, int logScaleIn, bool useSEALParams, bool verbose);
        protobuf::hit::CKKSParams save_ckks_params();

        seal::Encryptor *sealEncryptor;
        seal::CKKSEncoder *encoder;
        CKKSEncryptor *encryptor;
        CKKSDecryptor *decryptor;
        seal::PublicKey pk;
        seal::SecretKey sk;
        seal::GaloisKeys gk;
        seal::RelinKeys rk;
        seal::EncryptionParameters *params;
        int logScale;
        int encryptionCount = 0;
        bool standardParams;
        Mode mode;
    };

    uint64_t estimate_key_size(int numGaloisShift, int ptslots, int depth);

    // This function tries to load a prevously-generated instance from disk. Instances are parameterized by
    // the number of plaintext slots (numSlots), the multiplicative depth (multDepth), and the CKKS scale parameter
    // (logScale). `mode` can be `NORMAL`, `DEBUG`, or `NONEVALUATION`. `NORMAL` results in a standard homomorphic
    // evaluator, while `DEBUG` loads a debug evaluator. `NONEVALUATION` is useful for cliend-side computation which
    // don't need to perform any evaluation. A `NONEVALUATION` instance can *ONLY* be used for encryption and
    // decryption.
    CKKSInstance *try_load_instance(int numSlots, int multDepth, int logScale, Mode mode,
                                  const std::vector<int> &galois_steps = std::vector<int>());
}  // namespace hit