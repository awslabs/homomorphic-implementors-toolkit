// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <vector>
#include "hit/api/backend.h"

namespace hit {
    using BackendPlaintext = latticpp::Plaintext;
    using BackendEncoder = latticpp::Encoder;

    std::vector<int> gen_modulus_vec(int num_primes, int mult_depth, int log_scale);
    uint64_t estimate_key_size(int num_galois_shift, int plaintext_slots, int depth);

    class HEContext {
    public:
        HEContext(int num_slots, int mult_depth, int precisionBits);
        explicit HEContext(latticpp::Parameters &params);

        int max_ciphertext_level() const;
        int num_slots() const;
        uint64_t getQi(int he_level) const;
        uint64_t getPi(int i) const;
        int numQi() const;
        int numPi() const;
        int min_log_scale() const;
        int log_scale() const;

        BackendPlaintext encode(const BackendEncoder &e, const std::vector<double> &raw_pt, int level, double scale) const;
        std::vector<double> decode(const BackendEncoder &e, const BackendPlaintext &p) const;

        latticpp::Parameters params;
    private:
        void validateParams(int num_slots, int mult_depth, int precisionBits) const;
    };
}  // namespace hit
