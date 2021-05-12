// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <vector>

namespace hit {
    std::vector<int> gen_modulus_vec(int num_primes, int mult_depth, int log_scale);

    class SealCtx : public HEContext {
    public:
        SealCtx(int logSlots, int precisionBits);
        int max_ciphertext_level();
        int num_slots();
        int getQi(int he_level);
        int getPi(int i);
        int numQi();
        int numPi();
        int min_log_scale();
    private:
        shared_ptr<const SEALContext::ContextData> get_context_data(int level);

        const std::shared_ptr<seal::SEALContext> &context;
    };
}  // namespace hit
