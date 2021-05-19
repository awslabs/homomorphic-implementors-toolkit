// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* This file offers default implementation for most functions in the
 * CKKSEvaluator interface.
 */

#include "context.h"
#include "hit/common.h"

using namespace std;
using namespace latticpp;

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

    void HEContext::validateParams(int num_slots, int mult_depth, int precisionBits) const {
        if (!is_pow2(num_slots) || num_slots < 4096) {
            LOG_AND_THROW_STREAM("Invalid parameters when creating HIT-SEAL instance: "
                                 << "num_slots must be a power of 2, and at least 4096; got "
                                 << num_slots << ".");
        }

        if (precisionBits < min_log_scale()) {
            LOG_AND_THROW_STREAM("Invalid parameters when creating HIT-SEAL instance: "
                                 << "log_scale is " << precisionBits << ", which is less than the minimum "
                                 << min_log_scale() << ".");
        }

        int poly_modulus_degree = num_slots * 2;
        int max_modulus_bits = poly_degree_to_max_mod_bits(poly_modulus_degree);
        uint64_t modulus_bits = total_modulus_bits();
        if (modulus_bits > max_modulus_bits) {
            LOG_AND_THROW_STREAM("Invalid parameters when creating HIT-SEAL instance: "
                                 << "poly_modulus_degree is " << poly_modulus_degree << ", which limits the modulus to "
                                 << max_modulus_bits << " bits, but a " << modulus_bits << "-bit modulus was requested.");
        }
    }

    HEContext::HEContext(std::shared_ptr<seal::SEALContext> &params, double log_scale) : params(params), log_scale(log_scale) {
        validateParams(num_slots(), max_ciphertext_level() - 1, log_scale);
    }

    HEContext::HEContext(int num_slots, int mult_depth, int precisionBits) {
        validateParams(num_slots, mult_depth, precisionBits);
        vector<uint8_t> logQi = gen_ciphertext_modulus_vec(mult_depth + 1, precisionBits);
        vector<uint8_t> logPi(1);
        logPi[0] = 60; // special modulus. For now, we just use a single modulus like SEAL.
        params = newParametersFromLogModuli(log2(num_slots) + 1, logQi, mult_depth + 1, logPi, 1, precisionBits);
    }

    int HEContext::max_ciphertext_level() const {
        return context->first_context_data()->chain_index();
    }

    int HEContext::num_slots() const {
        return context->first_context_data()->parms().poly_modulus_degree() / 2;
    }

    uint64_t HEContext::get_qi(int he_level) const {
        if (he_level > max_ciphertext_level()) {
            LOG_AND_THROW_STREAM("Q_i index-out-of-bounds exception");
        }
        return get_context_data(he_level)->parms().coeff_modulus().back().value();
    }

    uint64_t HEContext::get_pi(int i) const {
        if (i != 0) {
            LOG_AND_THROW_STREAM("SEAL only supports a single key-switch modulus");
        }
        return context->key_context_data()->parms().coeff_modulus().back().value();
    }

    int HEContext::num_qi() const {
        return max_ciphertext_level() + 1;
    }

    int HEContext::num_pi() const { // NOLINT(readability-convert-member-functions-to-static)
        return 1;
    }

    uint64_t HEContext::total_modulus_bits() const {
        double total = 0;
        for (int i = 0; i < num_qi(); i++) {
            total += log2(get_qi(i));
        }
        for (int i = 0; i < num_pi(); i++) {
            total += log2(get_pi(i));
        }
        return static_cast<uint64_t>(round(total));
    }

    int HEContext::min_log_scale() const { // NOLINT(readability-convert-member-functions-to-static)
        // SEAL throws an error for 21, but allows 22
        return 22;
    }

    int HEContext::log_scale() const {
        return ceil(log2(scale(params)));
    }

    BackendPlaintext HEContext::encode(const BackendEncoder &e, const vector<double> &raw_pt, int level, double scale) const {
        Plaintext encoded_plain;
        shared_ptr<const SEALContext::ContextData> ctx_data = get_context_data(context, level);
        e.encode(raw_pt, ctx_data->parms_id(), scale, encoded_plain);
        return encoded_plain;
    }

    vector<double> HEContext::decode(const BackendEncoder &e, const BackendPlaintext &p) const {
        vector<double> decoded_plain;
        e.decode(p, decoded_plain);
        return decoded_plain;
    }
}  // namespace hit
