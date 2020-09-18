// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "decryptor.h"

#include <glog/logging.h>

#include "../common.h"

using namespace std;
using namespace seal;

namespace hit {

    CKKSDecryptor::CKKSDecryptor(const shared_ptr<SEALContext> &context, CKKSEncoder *encoder,
                                 const SecretKey &secret_key)
        : encoder(encoder), context(context) {
        decryptor = new Decryptor(context, secret_key);
    }

    CKKSDecryptor::~CKKSDecryptor() {
        delete (decryptor);
    }

    vector<double> CKKSDecryptor::decrypt(const CKKSCiphertext &encrypted) {
        Plaintext temp;

        int lvl = encrypted.he_level();
        if (lvl != 0) {
            LOG(WARNING) << "Decrypting a ciphertext that is not at level 0! Consider starting with a smaller modulus"
                         << " to improve performance!";
        }

        decryptor->decrypt(encrypted.seal_ct, temp);

        vector<double> decoded_output;
        encoder->decode(temp, decoded_output);

        return decoded_output;
    }
}  // namespace hit
