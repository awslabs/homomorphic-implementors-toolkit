// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "latticpp/latticpp.h"
#include <memory>

// SEAL throws an error for 21, but allows 22
#define MIN_LOG_SCALE 22

namespace hit {
    struct LattigoCtxt {

    };

    /*
    Helper function: Fetch the last prime given SEALContext and heLevel.
    */
    uint64_t get_last_prime(const std::shared_ptr<LattigoCtxt> &context, int he_level);
} // namespace hit
