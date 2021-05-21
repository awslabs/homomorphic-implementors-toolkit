// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <vector>

#include "latticpp/latticpp.h"

namespace hit {

    std::vector<int> gen_modulus_vec(int num_primes, int mult_depth, int log_scale);
    uint64_t estimate_key_size(int num_galois_shift, int plaintext_slots, int depth);

    class HEContext {
       public:
        HEContext(int num_slots, int mult_depth, int precisionBits);
        explicit HEContext(latticpp::Parameters &params);

        int max_ciphertext_level() const;
        int num_slots() const;

        // The ciphertext modulus is a product \prod_{i=0}^he_level(Q_i)
        // where each Q_i is a prime.
        // This function can be used to get the "last prime" (Q_{he_level}) in the current ciphertext modulus.
        uint64_t get_qi(int he_level) const;

        // For key switching, CKKS uses an additional modulus \prod_{i=0}^\alpha(P_i)
        // where each P_i is a prime.
        // In SEAL, alpha=0, so there is a single P_i. In general (for other backends)
        // multiple P_i may be supported for improved efficiency.
        uint64_t get_pi(int i) const;

        int num_qi() const;

        int num_pi() const;

        uint64_t total_modulus_bits() const;
        int min_log_scale() const;
        int log_scale() const;

        latticpp::Parameters params;

       private:
        void validateContext() const;
    };
}  // namespace hit
