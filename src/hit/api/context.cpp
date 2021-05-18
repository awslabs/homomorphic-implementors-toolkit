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
    vector<uint8_t> gen_ciphertext_modulus_vec(int num_primes, uint8_t log_scale) {
        vector<uint8_t> modulusVector(num_primes);
        // the SEAL examples recommend the last modulus be 60 bits; it's unclear why,
        // and also unclear how closely that choice is related to log_scale (they use 40 in their examples)
        modulusVector[0] = 60;
        for (int i = 1; i < num_primes; i++) {
            modulusVector[i] = log_scale;
        }
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
            LOG_AND_THROW_STREAM("Invalid parameters when creating HomomorphicEval instance: "
                                 << "num_slots must be a power of 2, and at least 4096. Got " << num_slots);
        }

        int poly_modulus_degree = num_slots * 2;
        if (precisionBits < min_log_scale()) {
            LOG(ERROR) << "poly_modulus_degree is " << poly_modulus_degree << ", which limits the modulus to "
                       << poly_degree_to_max_mod_bits(poly_modulus_degree) << " bits";
            LOG_AND_THROW_STREAM("Invalid parameters when creating HomomorphicEval instance: "
                                 << "log_scale is " << precisionBits << ", which is less than the minimum "
                                 << min_log_scale()
                                 << ". Either increase the number of slots or decrease the number of primes.");
        }

        int modBits = 120 + mult_depth * precisionBits;
        int min_poly_degree = modulus_to_poly_degree(modBits);
        if (poly_modulus_degree < min_poly_degree) {
            LOG_AND_THROW_STREAM("Invalid parameters when creating ScaleEstimator instance: "
                                 << "Parameters for depth " << mult_depth << " circuits and scale "
                                 << precisionBits << " bits require more than " << num_slots << " plaintext slots.");
        }
    }

    HEContext::HEContext(Parameters &params) : params(move(params)) {
        validateParams(num_slots(), max_ciphertext_level() - 1, ceil(log2(scale(params))));
    }

    HEContext::HEContext(int num_slots, int mult_depth, int precisionBits) {
        validateParams(num_slots, mult_depth, precisionBits);
        vector<uint8_t> logQi = gen_ciphertext_modulus_vec(mult_depth + 1, precisionBits);
        vector<uint8_t> logPi(1);
        logPi[0] = 60; // special modulus. For now, we just use a single modulus like SEAL.
        params = newParametersFromLogModuli(log2(num_slots) + 1, logQi, mult_depth + 1, logPi, 1, precisionBits);
    }

    int HEContext::max_ciphertext_level() const {
        return maxLevel(params);
    }

    int HEContext::num_slots() const {
        return numSlots(params);
    }

    uint64_t HEContext::getQi(int he_level) const {
        return qi(params, he_level);
    }

    uint64_t HEContext::getPi(int i) const {
        return pi(params, i);
    }

    int HEContext::numQi() const {
        return qiCount(params);
    }

    int HEContext::numPi() const {
        return piCount(params);
    }

    int HEContext::min_log_scale() const { // NOLINT(readability-convert-member-functions-to-static)
        // SEAL throws an error for 21, but allows 22
        // I haven't updated this for Lattigo; but this is WAY lower than would work in practice anyway,
        // so I'm not too concerned.
        return 22;
    }

    int HEContext::log_scale() const {
        return ceil(log2(scale(params)));
    }
}  // namespace hit
