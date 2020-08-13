// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <iomanip>
#include <iostream>
#include "seal/seal.h"

namespace hit {
    /*
    Helper function: Prints the parameters in a SEALContext.

    Copied from SEAL ./native/examples/examples.h
    */
    inline void print_parameters(const std::shared_ptr<seal::SEALContext> &context) {
        // Verify parameters
        if (!context) {
            throw std::invalid_argument("context is not set");
        }
        const auto &context_data = *context->key_context_data();

        /*
        Which scheme are we using?
        */
        std::string scheme_name;
        switch (context_data.parms().scheme()) {
            case seal::scheme_type::CKKS:
                scheme_name = "CKKS";
                break;
            default:
                throw std::invalid_argument("unsupported scheme");
        }
        std::cout << "/" << std::endl;
        std::cout << "| Encryption parameters :" << std::endl;
        std::cout << "|   scheme: " << scheme_name << std::endl;
        std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

        /*
        Print the size of the true (product) coefficient modulus.
        */
        std::cout << "|   coeff_modulus size: ";
        std::cout << context_data.total_coeff_modulus_bit_count() << " (";
        auto coeff_modulus = context_data.parms().coeff_modulus();
        std::size_t coeff_modulus_size = coeff_modulus.size();
        for (std::size_t i = 0; i < coeff_modulus_size - 1; i++) {
            std::cout << coeff_modulus[i].bit_count() << " + ";
        }
        std::cout << coeff_modulus.back().bit_count();
        std::cout << ") bits" << std::endl;

        /*
        For the BFV scheme print the plain_modulus parameter.
        */
        if (context_data.parms().scheme() == seal::scheme_type::BFV) {
            std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
        }

        std::cout << "\\" << std::endl;
    }

    /*
    Helper function: Prints the `parms_id' to std::ostream.

    Copied from SEAL ./native/examples/examples.h
    */
    inline std::ostream &operator<<(std::ostream &stream, seal::parms_id_type parms_id) {
        /*
        Save the formatting information for std::cout.
        */
        std::ios old_fmt(nullptr);
        old_fmt.copyfmt(std::cout);

        stream << std::hex << std::setfill('0') << std::setw(16) << parms_id[0] << " " << std::setw(16) << parms_id[1]
               << " " << std::setw(16) << parms_id[2] << " " << std::setw(16) << parms_id[3] << " ";

        /*
        Restore the old std::cout formatting.
        */
        std::cout.copyfmt(old_fmt);

        return stream;
    }

    /*
    Helper function: Fetch the last prime given SEALContext and heLevel.
    */
    inline std::uint64_t getLastPrime(const std::shared_ptr<seal::SEALContext> &context, const int heLevel) {
        auto context_data = context->first_context_data();
        while (context_data->chain_index() >= heLevel) {
            if (context_data->chain_index() == heLevel) {
                return context_data->parms().coeff_modulus().back().value();
            }
            context_data = context_data->next_context_data();
        }
        throw std::invalid_argument("Fail to find target level " + std::to_string(heLevel));
    }
}  // namespace hit
