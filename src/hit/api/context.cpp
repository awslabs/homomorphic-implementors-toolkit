// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* This file offers default implementation for most functions in the
 * CKKSEvaluator interface.
 */

#include "context.h"

namespace hit {

    int HEContext::max_ciphertext_level() {
        return 0;
    }

    int HEContext::num_slots() {
        return 0;
    }

    int HEContext::last_prime(int he_level) {
        return 0;
    }

    int HEContext::min_log_scale() {
        return 0;
    }
}  // namespace hit
