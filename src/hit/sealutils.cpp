// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "sealutils.h"

#include <glog/logging.h>

#include <iomanip>
#include <iostream>

#include "seal/seal.h"

using namespace std;
using namespace seal;

namespace hit {
    /*
    Helper function: Prints the parameters in a SEALContext.

    Copied from SEAL ./native/examples/examples.h
    */
    void print_parameters(const shared_ptr<SEALContext> &context) {
        // Verify parameters
        if (!context) {
            throw invalid_argument("context is not set");
        }
        const auto &context_data = *context->key_context_data();

        /*
        Which scheme are we using?
        */
        string scheme_name;
        switch (context_data.parms().scheme()) {
            case scheme_type::CKKS:
                scheme_name = "CKKS";
                break;
            default:
                throw invalid_argument("unsupported scheme");
        }
        LOG(INFO) << "/";
        LOG(INFO) << "| Encryption parameters :";
        LOG(INFO) << "|   scheme: " << scheme_name;
        LOG(INFO) << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree();

        /*
        Print the size of the true (product) coefficient modulus.
        */
        stringstream coeff_modulus_size_info;
        coeff_modulus_size_info << "|   coeff_modulus size: ";
        coeff_modulus_size_info << context_data.total_coeff_modulus_bit_count() << " (";
        auto coeff_modulus = context_data.parms().coeff_modulus();
        size_t coeff_modulus_size = coeff_modulus.size();
        for (size_t i = 0; i < coeff_modulus_size - 1; i++) {
            coeff_modulus_size_info << coeff_modulus[i].bit_count() << " + ";
        }
        coeff_modulus_size_info << coeff_modulus.back().bit_count();
        coeff_modulus_size_info << ") bits";
        LOG(INFO) << coeff_modulus_size_info.str();

        /*
        For the BFV scheme print the plain_modulus parameter.
        */
        if (context_data.parms().scheme() == scheme_type::BFV) {
            LOG(INFO) << "|   plain_modulus: " << context_data.parms().plain_modulus().value();
        }

        LOG(INFO) << "\\";
    }

    /*
    Helper function: Prints the `parms_id' to ostream.

    Copied from SEAL ./native/examples/examples.h
    */
    ostream &operator<<(ostream &stream, parms_id_type parms_id) {
        /*
        Save the formatting information for cout.
        */
        ios old_fmt(nullptr);
        old_fmt.copyfmt(cout);

        stream << hex << setfill('0') << setw(16) << parms_id[0] << " " << setw(16) << parms_id[1]
               << " " << setw(16) << parms_id[2] << " " << setw(16) << parms_id[3] << " ";

        /*
        Restore the old cout formatting.
        */
        cout.copyfmt(old_fmt);

        return stream;
    }

    /*
    Helper function: Get the context data for the ciphertext's level
    */
    shared_ptr<const SEALContext::ContextData> get_context_data(const shared_ptr<SEALContext> &context, int level) {
        // get the context_data for this ciphertext level
        // but do not use the ciphertext itself! Use the he_level,
        // in case we are not doing ciphertext computations
        auto context_data = context->first_context_data();
        while (context_data->chain_index() > level) {
            // Step forward in the chain.
            context_data = context_data->next_context_data();
        }
        return context_data;
    }

    /*
    Helper function: Fetch the last prime given SEALContext and he_level.
    */
    uint64_t get_last_prime(const shared_ptr<SEALContext> &context, int he_level) {
        return get_context_data(context, he_level)->parms().coeff_modulus().back().value();
    }
}  // namespace hit
