// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../ciphertext.h"
#include "../evaluator.h"
#include "homomorphic.h"
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
         */
        HomomorphicEval(const std::shared_ptr<seal::SEALContext> &context, seal::CKKSEncoder &encoder,
                        seal::Encryptor &encryptor, const seal::GaloisKeys &galois_keys,
                        const seal::RelinKeys &relin_keys, bool update_metadata);

        /* For documentation on the API, see ../evaluator.h */
        ~HomomorphicEval() override;

        HomomorphicEval(const HomomorphicEval &) = delete;
        HomomorphicEval &operator=(const HomomorphicEval &) = delete;
        HomomorphicEval(HomomorphicEval &&) = delete;
        HomomorphicEval &operator=(HomomorphicEval &&) = delete;

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

        void mod_down_to_inplace_internal(CKKSCiphertext &ct, const CKKSCiphertext &target) override;

        void mod_down_to_min_inplace_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) override;

        void mod_down_to_level_inplace_internal(CKKSCiphertext &ct, int level) override;

        void rescale_to_next_inplace_internal(CKKSCiphertext &ct) override;

        void relinearize_inplace_internal(CKKSCiphertext &ct) override;

        // reuse this evaluator for another computation
        void reset_internal() override;

       private:
        /* Helper function: Return the HE level of the SEAL ciphertext.
         */
        int get_SEAL_level(const CKKSCiphertext &ct) const;

        seal::Evaluator evaluator;
        seal::CKKSEncoder &encoder;
        seal::Encryptor &encryptor;
        // It would be nice to mark these `const`. However, I'm using
        // "move" semantics in CKKSInstance.cpp where they are generated to avoid
        // having two copies of the keys. This doesn't work if I have `const` types
        // involved because the copy constructor is invoked rather than the `move`
        // constructor. Someone with more C++ knowledge may be able to improve
        // the situation.
        const seal::GaloisKeys &galois_keys;
        const seal::RelinKeys &relin_keys;

        bool update_metadata;

        friend class DebugEval;
    };
}  // namespace hit
