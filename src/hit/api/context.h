// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <vector>

#include "seal/context.h"
#include "seal/seal.h"

namespace hit {

    std::vector<int> gen_modulus_vec(int num_primes, int mult_depth, int log_scale);
    uint64_t estimate_key_size(int num_galois_shift, int plaintext_slots, int depth);

    class HEContext {
       public:
        HEContext(int num_slots, int mult_depth, int precision_bits, bool use_standard_params);
        explicit HEContext(const seal::EncryptionParameters &params, int precision_bits, bool use_standard_params);

        int max_ciphertext_level() const;
        int num_slots() const;
        uint64_t get_qi(int he_level) const;
        uint64_t get_pi(int i) const;
        int num_qi() const;
        int num_pi() const;
        uint64_t total_modulus_bits() const;
        int min_log_scale() const;
        int log_scale() const;

        std::shared_ptr<seal::SEALContext> params;

        /*
        Helper function: Get the context data for a specific ciphertext level
        */
        std::shared_ptr<const seal::SEALContext::ContextData> get_context_data(int level) const;

       private:
        void validateContext() const;
        void params_to_context(const seal::EncryptionParameters &enc_params, bool use_standard_params);
        int log_scale_;
    };
}  // namespace hit
