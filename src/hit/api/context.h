// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "latticpp/latticpp.h"
#include "params.h"

namespace hit {

    std::vector<int> gen_modulus_vec(int num_primes, int mult_depth, int log_scale);
    uint64_t estimate_key_size(int num_galois_shift, int plaintext_slots, int depth);

    /* An internal API for the HE backend. */
    class HEContext {
       public:
        explicit HEContext(const CKKSParams &params);

        // Maximum level of a ciphertext for these parameters. For a leveled-HE scheme,
        // this is one more than the multiplicative depth of the circuit you want to evaluate.
        int max_ciphertext_level() const;

        // Number of plaintext slots support by the current parameters.
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

        // Number of primes in the (maximum) ciphertext modulus
        int num_qi() const;

        // Number of special primes for the key-switch modulus
        int num_pi() const;

        // Total size of the modulus (Q_i + P_i) in bits
        // This determines the ring dimension requried for security.
        uint64_t total_modulus_bits() const;

        // A constant determined by the backend; independent of parameters.
        int min_log_scale() const;

        // Log(scale) for these parameters
        int log_scale() const;

        latticpp::Parameters params;
        std::optional<latticpp::BootstrappingParameters> btp_params = std::optional<latticpp::BootstrappingParameters>();

       private:
        void validateContext() const;
    };
}  // namespace hit
