// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "encryptor.h"

#include <utility>

#include "../common.h"

using namespace std;
using namespace seal;

namespace hit {

    CKKSEncryptor::CKKSEncryptor(const shared_ptr<SEALContext> &context, int numSlots, bool includePlaintext)
        : encoder(nullptr), encryptor(nullptr), context(move(context)), numSlots(numSlots) {
        mode = includePlaintext ? ENC_PLAIN : ENC_META;
    }

    CKKSEncryptor::CKKSEncryptor(const shared_ptr<SEALContext> &context, CKKSEncoder *encoder, Encryptor *encryptor,
                                 bool debug)
        : encoder(encoder), encryptor(encryptor), context(move(context)), numSlots(encoder->slot_count()) {
        mode = debug ? ENC_DEBUG : ENC_NORMAL;
    }

    CKKSCiphertext CKKSEncryptor::encrypt(const vector<double> &coeffs, double scale, int lvl) {
        // in ENC_META, CKKSInstance sets numSlots to 4096 and doesn't actually attempt to calcuate the correct value.
        // We have to ignore that case here. Otherwise, input size should exactly equal the number of slots.
        if (mode != ENC_META && coeffs.size() != numSlots) {
            // bad things can happen if you don't plan for your input to be smaller than the ciphertext
            // This forces the caller to ensure that the input has the correct size or is at least appropriately padded
            throw invalid_argument("You can only encrypt vectors which have exactly as many coefficients as the number of plaintext slots: Expected " +
                                   to_string(numSlots) + ", got " + to_string(coeffs.size()));
        }

        if (lvl == -1) {
            lvl = context->first_context_data()->chain_index();
        }

        auto context_data = context->first_context_data();
        while (context_data->chain_index() > lvl) {
            // order of operations is very important: floating point arithmetic is not associative
            scale = (scale * scale) / static_cast<double>(context_data->parms().coeff_modulus().back().value());
            context_data = context_data->next_context_data();
        }

        CKKSCiphertext destination;
        destination.he_level() = lvl;
        destination.scale = scale;

        // Only set the plaintext in Plaintext or Debug modes
        if (mode == ENC_PLAIN || mode == ENC_DEBUG) {
            destination.raw_pt = coeffs;
        }
        // Only set the ciphertext in Normal or Debug modes
        if (mode == ENC_NORMAL || mode == ENC_DEBUG) {
            Plaintext temp;
            encoder->encode(coeffs, context_data->parms_id(), scale, temp);
            encryptor->encrypt(temp, destination.seal_ct);
        }

        destination.num_slots_ = numSlots;

        return destination;
    }
}  // namespace hit
