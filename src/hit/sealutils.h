// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <iomanip>
#include <iostream>

#include "api/ciphertext.h"
#include "common.h"
#include "seal/seal.h"

// SEAL throws an error for 21, but allows 22
#define MIN_LOG_SCALE 22

namespace hit {
    /*
    Helper function: Prints the parameters in a SEALContext.

    Copied from SEAL ./native/examples/examples.h
    */
    void print_parameters(const std::shared_ptr<seal::SEALContext> &context);

    /*
    Helper function: Prints the `parms_id' to std::ostream.

    Copied from SEAL ./native/examples/examples.h
    */
    std::ostream &operator<<(std::ostream &stream, seal::parms_id_type parms_id);

    /*
    Helper function: Get the context data for the ciphertext's level
    */
    std::shared_ptr<const seal::SEALContext::ContextData> get_context_data(
        const std::shared_ptr<seal::SEALContext> &context, int level);

    /*
    Helper function: Fetch the last prime given SEALContext and heLevel.
    */
    uint64_t get_last_prime(const std::shared_ptr<seal::SEALContext> &context, int he_level);

    std::vector<int> gen_modulus_vec(int num_primes, int log_scale);

    uint64_t estimate_key_size(int num_galois_shift, int plaintext_slots, int depth);
}  // namespace hit
