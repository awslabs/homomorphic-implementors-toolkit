// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "ciphertext.h"
#include "seal/context.h"
#include "seal/seal.h"

namespace hit {

    /* A thin wrapper around the SEAL `Decryptor` class.
     * The API takes a CKKSCiphertext instead of a Ciphertext.
     * Decryption also implicitly manages decoding. However,
     * just doing decoding results in a C++ vector of size
     * poly_modulus_degree/2. Fortunately, our CKKSCiphertexts
     * hold the plaintext size, so the decryption function also
     * truncates the decoded plaintext to the appropriate length.
     */

    class CKKSDecryptor {
       public:
        CKKSDecryptor(const std::shared_ptr<seal::SEALContext> &context, seal::CKKSEncoder *encoder,
                      const seal::SecretKey &secret_key);

        ~CKKSDecryptor();

        CKKSDecryptor(const CKKSDecryptor &) = delete;
        CKKSDecryptor &operator=(const CKKSDecryptor &) = delete;
        CKKSDecryptor(CKKSDecryptor &&) = delete;
        CKKSDecryptor &operator=(CKKSDecryptor &&) = delete;

        std::vector<double> decrypt(const CKKSCiphertext &encrypted);

       private:
        seal::CKKSEncoder *encoder;
        seal::Decryptor *decryptor;
        const std::shared_ptr<seal::SEALContext> context;
    };
}  // namespace hit
