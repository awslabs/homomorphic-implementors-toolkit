// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <deque>
#include <optional>

#include "../../common.h"
#include "../ciphertext.h"
#include "../evaluator.h"
#include "../params.h"

namespace hit {

    /* This evaluator is a thin wrapper around
     * Lattigo's evaluator API. It actually does
     * computation on Lattigo ciphertexts.
     */
    class HomomorphicEval : public CKKSEvaluator {
       public:
        /* Construct a homomorphic evaluator instance for the provided scheme parameters.
         * This will generate keys for encryption, decryption, and relinearization in all cases. If the provided
         * params include bootstrapping parameters, keys required for bootstrapping are also generated.
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
                        const std::vector<int> &galois_steps = std::vector<int>());

        /* An evaluation-only instance (decryption not available). */
        HomomorphicEval(std::istream &params_stream, std::istream &galois_key_stream, std::istream &relin_key_stream);

        /* A full instance capable of encryption, decryption, and evaluation. */
        HomomorphicEval(std::istream &params_stream, std::istream &galois_key_stream, std::istream &relin_key_stream,
                        std::istream &secret_key_stream);

        /* For documentation on the API, see ../evaluator.h */
        ~HomomorphicEval() override = default;

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

        void bootstrap_inplace_internal(CKKSCiphertext &ct, bool rescale_for_bootstrapping) override;

       private:
        template <typename T>
        class ObjectPool {
           public:
            std::optional<T> poll() {
                std::lock_guard<std::mutex> lock(pool_mutex);
                if (list.empty()) {
                    return {};
                }
                T result = list.back();
                list.pop_back();
                return result;
            }

            void offer(T &&object) {
                std::lock_guard<std::mutex> lock(pool_mutex);
                list.push_back(object);
            }

           private:
            std::mutex pool_mutex;
            std::deque<T> list;
        };

        template <typename T>
        class PoolObject {
           public:
            PoolObject(T &&object, ObjectPool<T> &pool) : pool(pool), object(object) {
            }
            ~PoolObject() {
                pool.offer(std::move(object));
            }

            T *get() {
                return &object;
            }

            T *operator->() {
                return get();
            }

            T &ref() {
                return object;
            }

            explicit operator T &() {
                return ref();
            }

           private:
            ObjectPool<T> &pool;
            T object;
        };

        ObjectPool<latticpp::Encoder> backend_encoder;
        ObjectPool<latticpp::Evaluator> backend_evaluator;
        ObjectPool<latticpp::Encryptor> backend_encryptor;
        ObjectPool<latticpp::Bootstrapper> backend_bootstrapper;
        latticpp::Decryptor backend_decryptor;
        latticpp::PublicKey pk;
        latticpp::SecretKey sk;
        latticpp::RotationKeys galois_keys;
        latticpp::RelinearizationKey relin_keys;
        latticpp::BootstrappingKey btp_keys;

        PoolObject<latticpp::Evaluator> get_evaluator();
        PoolObject<latticpp::Encoder> get_encoder();
        PoolObject<latticpp::Encryptor> get_encryptor();
        PoolObject<latticpp::Bootstrapper> get_bootstrapper();

        uint64_t get_last_prime_internal(const CKKSCiphertext &ct) const override;
        void deserializeEvalKeys(const timepoint &start, std::istream &galois_key_stream,
                                 std::istream &relin_key_stream);

        void deserialize_common(std::istream &params_stream);

        friend class DebugEval;
        friend class ScaleEstimator;
    };
}  // namespace hit
