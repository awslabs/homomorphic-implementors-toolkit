// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <iomanip>
#include <iostream>

#include "api/ciphertext.h"
#include "seal/seal.h"

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
    Helper function: Fetch the last prime given SEALContext and heLevel.
    */
    std::uint64_t getLastPrime(const std::shared_ptr<seal::SEALContext> &context, int heLevel);

    /*
    Helper function: Return the HE level of the SEAL ciphertext.
    */
    int get_SEAL_level(const std::shared_ptr<seal::SEALContext> &context, const CKKSCiphertext &ct);
}  // namespace hit
