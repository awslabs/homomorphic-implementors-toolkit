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
    Helper function: Generate a list of bit-lengths for the modulus primes.
    */
    vector<int> gen_modulus_vec(int num_primes, int log_scale) {
        vector<int> modulusVector(num_primes);
        // the SEAL examples recommend the last modulus be 60 bits; it's unclear why,
        // and also unclear how closely that choice is related to log_scale (they use 40 in their examples)
        modulusVector[0] = 60;
        for (int i = 1; i < num_primes - 1; i++) {
            modulusVector[i] = log_scale;
        }
        // The special modulus has to be as large as the largest prime in the chain.
        modulusVector[num_primes - 1] = 60;

        return modulusVector;
    }

    /*
    Helper function: Prints the parameters in a SEALContext.

    Copied from SEAL ./native/examples/examples.h
    */
    void print_parameters(const shared_ptr<SEALContext> &context) {
        const auto &context_data = *context->key_context_data();

        VLOG(VLOG_VERBOSE) << "/";
        VLOG(VLOG_VERBOSE) << "| Encryption parameters :";
        VLOG(VLOG_VERBOSE) << "|   scheme: CKKS";
        VLOG(VLOG_VERBOSE) << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree();

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
        VLOG(VLOG_VERBOSE) << coeff_modulus_size_info.str();

        /*
        For the BFV scheme print the plain_modulus parameter.
        */
        if (context_data.parms().scheme() == scheme_type::bfv) {
            VLOG(VLOG_VERBOSE) << "|   plain_modulus: " << context_data.parms().plain_modulus().value();
        }

        VLOG(VLOG_VERBOSE) << "\\";
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

        stream << hex << setfill('0') << setw(16) << parms_id[0] << " " << setw(16) << parms_id[1] << " " << setw(16)
               << parms_id[2] << " " << setw(16) << parms_id[3] << " ";

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

    uint64_t estimate_key_size(int num_galois_shift, int plaintext_slots, int depth) {
        // number of bytes in each coefficient (a 64-bit value)
        int coefficientSizeBytes = 8;
        // size of a single polynomial with one modulus
        // each coefficient is 64 bits, and there are plaintext_slots*2 coefficients.
        uint64_t poly_size_bytes = 2 * coefficientSizeBytes * plaintext_slots;
        // size of a single ciphertext with one modulus
        // a (fresh) ciphertext is a pair of polynomials
        uint64_t ct_size_bytes = 2 * poly_size_bytes;
        // size of the secret key in bytes
        // a secret key is a single polynomial with (depth+2) moduli
        // The reason is that the biggest ciphertext for a depth d computation
        // has d+1 moduli, and SEAL requires an extra modulus for keys.
        uint64_t sk_bytes = (depth + 2) * poly_size_bytes;
        // size of the public key in bytes
        // a public key is just a ciphertext with the (depth+2) moduli
        uint64_t pk_bytes = (depth + 2) * ct_size_bytes;
        // size of relinearization keys
        // each relinearization key is a vector of (depth+1) ciphertexts where each has (depth+2) moduli
        uint64_t rk_bytes = (depth + 1) * pk_bytes;
        // size of Galois keys
        // Galois keys are a vector of relinearization keys
        // there are at most 2*lg(plaintext_slots)+1 keys, but there may be fewer if you have addional
        // information about what shifts are needed during a computation.
        uint64_t gk_bytes = num_galois_shift * rk_bytes;

        return sk_bytes + pk_bytes + rk_bytes + gk_bytes;
    }
}  // namespace hit
