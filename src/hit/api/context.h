// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>

namespace hit {
    class HEContext {
    public:
        HEContext(int logSlots, int mult_depth, int precisionBits);

        int max_ciphertext_level();
        int num_slots();
        int last_prime(int he_level);
        int min_log_scale();
    };
}  // namespace hit
