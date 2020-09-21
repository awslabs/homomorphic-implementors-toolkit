// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "sealutils.h"

#include <glog/logging.h>

#include <iomanip>
#include <iostream>

#include "seal/seal.h"

namespace hit {
    /*
    Helper function: Prints the parameters in a SEALContext.

    Copied from SEAL ./native/examples/examples.h
    */
    void print_parameters(const std::shared_ptr<seal::SEALContext> &context) {
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
        LOG(INFO) << "/";
        LOG(INFO) << "| Encryption parameters :";
        LOG(INFO) << "|   scheme: " << scheme_name;
        LOG(INFO) << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree();

        /*
        Print the size of the true (product) coefficient modulus.
        */
        std::stringstream coeff_modulus_size_info;
        coeff_modulus_size_info << "|   coeff_modulus size: ";
        coeff_modulus_size_info << context_data.total_coeff_modulus_bit_count() << " (";
        auto coeff_modulus = context_data.parms().coeff_modulus();
        std::size_t coeff_modulus_size = coeff_modulus.size();
        for (std::size_t i = 0; i < coeff_modulus_size - 1; i++) {
            coeff_modulus_size_info << coeff_modulus[i].bit_count() << " + ";
        }
        coeff_modulus_size_info << coeff_modulus.back().bit_count();
        coeff_modulus_size_info << ") bits";
        LOG(INFO) << coeff_modulus_size_info.str();

        /*
        For the BFV scheme print the plain_modulus parameter.
        */
        if (context_data.parms().scheme() == seal::scheme_type::BFV) {
            LOG(INFO) << "|   plain_modulus: " << context_data.parms().plain_modulus().value();
        }

        LOG(INFO) << "\\";
    }

    /*
    Helper function: Prints the `parms_id' to std::ostream.

    Copied from SEAL ./native/examples/examples.h
    */
    std::ostream &operator<<(std::ostream &stream, seal::parms_id_type parms_id) {
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
    Helper function: Fetch the last prime given SEALContext and he_level.
    */
    std::uint64_t get_last_prime(const std::shared_ptr<seal::SEALContext> &context, int he_level) {
        auto context_data = context->first_context_data();
        while (context_data->chain_index() >= he_level) {
            if (context_data->chain_index() == he_level) {
                return context_data->parms().coeff_modulus().back().value();
            }
            context_data = context_data->next_context_data();
        }
        throw std::invalid_argument("Fail to find target level " + std::to_string(he_level));
    }
}  // namespace hit
