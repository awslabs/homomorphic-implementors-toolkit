// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <vector>
#include "hit/api/backend.h"

namespace hit {
    std::vector<int> gen_modulus_vec(int num_primes, int mult_depth, int log_scale);
    uint64_t estimate_key_size(int num_galois_shift, int plaintext_slots, int depth);

    class HEContext {
    public:
        HEContext(int num_slots, int mult_depth, int precisionBits);
        HEContext(const latticpp::Parameters &params);

        int max_ciphertext_level();
        int num_slots();
        uint64_t getQi(int he_level);
        uint64_t getPi(int i);
        int numQi();
        int numPi();
        int min_log_scale();

        latticpp::Parameters params;
    };
}  // namespace hit
