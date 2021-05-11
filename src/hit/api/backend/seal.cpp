// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "seal.h"

using namespace std;

namespace hit {

    /*
    Helper function: Generate a list of bit-lengths for the modulus primes.
    */
    vector<int> gen_modulus_vec(int num_primes, int log_scale) {
        vector<int> modulusVector(num_primes);
        // the SEAL examples recommend the last modulus be 60 bits; it's unclear why,
        // and also unclear how closely that choice is related to log_scale (they use 40 in their examples)
        modulusVector[0] = 60;
        for (int i = 1; i < num_primes - 1; i++) {
            modulusVector[i] = log_scale;
        }
        // The special modulus has to be as large as the largest prime in the chain.
        modulusVector[num_primes - 1] = 60;

        return modulusVector;
    }

    SealCtx::SealCtx(int logSlots, int mult_depth, int precisionBits) {
        vector<int> modulusVector = gen_modulus_vec(mult_depth + 2, log_scale_);

        EncryptionParameters params = EncryptionParameters(scheme_type::ckks);
        params.set_poly_modulus_degree(2 * logSlots);
        params.set_coeff_modulus(CoeffModulus::Create(2 * logSlots, modulusVector));

        // for large parameter sets, see https://github.com/microsoft/SEAL/issues/84
        context = make_unique<SEALContext>(params, true, sec_level_type::none);
    }

    shared_ptr<const SEALContext::ContextData> SealCtx::get_context_data(int level) {
        // get the context_data for this ciphertext level
        // but do not use the ciphertext itself! Use the he_level,
        // in case we are not doing ciphertext computations
        auto context_data = context->first_context_data();
        while (context_data->chain_index() > level) {
            // Step forward in the chain.
            context_data = context_data->next_context_data();
        }
        return context_data;
    }

    int SealCtx::max_ciphertext_level() {
        return context->first_context_data()->chain_index();
    }

    int SealCtx::num_slots() {
        return context->first_context_data()->parms().poly_modulus_degree() / 2;
    }

    uint64_t SealCtx::last_prime(int he_level) {
        auto context_data = get_context_data(he_level);
        return context_data->parms().coeff_modulus().back().value();
    }

    int SealCtx::min_log_scale() {
        // SEAL throws an error for 21, but allows 22
        return 22;
    }
}  // namespace hit
