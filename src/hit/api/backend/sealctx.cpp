// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "sealctx.h"

using namespace std;

namespace hit {

    int SealCtx::max_ciphertext_level() {
        return context->first_context_data()->chain_index();
    }

    int SealCtx::num_slots() {
        return context->first_context_data()->parms().poly_modulus_degree() / 2;
    }

    int SealCtx::last_prime(int he_level) {
        // get the context_data for this ciphertext level without
        // using an actual ciphertext.
        auto context_data = context->first_context_data();
        while (context_data->chain_index() > level) {
            // Step forward in the chain.
            context_data = context_data->next_context_data();
        }
        return context_data->parms().coeff_modulus().back().value();
    }

    int SealCtx::min_log_scale() {
        // SEAL throws an error for 21, but allows 22
        return 22;
    }
}  // namespace hit
