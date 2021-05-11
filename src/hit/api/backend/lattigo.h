// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <vector>

namespace hit {
    std::vector<int> gen_modulus_vec(int num_primes, int mult_depth, int log_scale);

    class LattigoCtx : public HEContext {
    public:
        LattigoCtx(int logSlots, int precisionBits);
        int max_ciphertext_level();
        int num_slots();
        int last_prime(int he_level);
        int min_log_scale();
    private:
        Parameters &context;
    };
}  // namespace hit
