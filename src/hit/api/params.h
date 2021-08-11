// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <iostream>
#include <vector>

#include "../common.h"
#include "seal/seal.h"

namespace hit {
    class CKKSParams {
       public:
        // Provide CKKS parameters without support for bootstrapping
        CKKSParams(int num_slots, int max_ct_level, int log_scale, bool use_standard_params);
        CKKSParams(seal::EncryptionParameters params, int log_scale, bool use_standard_params);

        int num_slots() const;
        int log_scale() const;
        int max_ct_level() const;
        bool use_std_params() const;

        seal::EncryptionParameters params;

       private:
        int log_scale_;
        bool use_std_params_;
        std::vector<int> gen_modulus_vec(int num_primes, int log_scale);
    };
}  // namespace hit
