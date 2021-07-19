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

    void HEContext::validateContext() const {
        int num_slots_ = num_slots();
        int precision_bits = log_scale();
        if (!is_pow2(num_slots_) || num_slots_ < 4096) {
            LOG_AND_THROW_STREAM("Invalid parameters when creating HIT-Lattigo instance: "
                                 << "num_slots must be a power of 2, and at least 4096; got " << num_slots_ << ".");
        }

        if (precision_bits < min_log_scale()) {
            LOG_AND_THROW_STREAM("Invalid parameters when creating HIT-Lattigo instance: "
                                 << "log_scale is " << precision_bits << ", which is less than the minimum "
                                 << min_log_scale() << ".");
        }

        int poly_modulus_degree = num_slots_ * 2;
        int max_modulus_bits = poly_degree_to_max_mod_bits(poly_modulus_degree);
        uint64_t modulus_bits = total_modulus_bits();
        if (modulus_bits > max_modulus_bits) {
            LOG_AND_THROW_STREAM("Invalid parameters when creating HIT-Lattigo instance: "
                                 << "poly_modulus_degree is " << poly_modulus_degree << ", which limits the modulus to "
                                 << max_modulus_bits << " bits, but a " << modulus_bits
                                 << "-bit modulus was requested.");
        }
    }

    HEContext::HEContext(const CKKSParams &params) : params(params.lattigo_params) {
        if (params.btp_params.has_value()) {
            btp_params = params.btp_params.value().lattigo_btp_params;
        }
        validateContext();
    }

    int HEContext::max_ciphertext_level() const {
        return maxLevel(params);
    }

    int HEContext::num_slots() const {
        return numSlots(params);
    }

    uint64_t HEContext::get_qi(int he_level) const {
        if (he_level >= num_qi()) {
            LOG_AND_THROW_STREAM("Q_i index-out-of-bounds exception");
        }
        return qi(params, he_level);
    }

    uint64_t HEContext::get_pi(int i) const {
        if (i >= num_pi()) {
            LOG_AND_THROW_STREAM("P_i index-out-of-bounds exception");
        }
        return pi(params, i);
    }

    int HEContext::num_qi() const {
        return qiCount(params);
    }

    int HEContext::num_pi() const {
        return piCount(params);
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

    int HEContext::min_log_scale() const {  // NOLINT(readability-convert-member-functions-to-static)
        // SEAL throws an error for 21, but allows 22
        // I haven't updated this for Lattigo; but this is WAY lower than would work in practice anyway,
        // so I'm not too concerned.
        return 22;
    }

    int HEContext::log_scale() const {
        return ceil(log2(scale(params)));
    }
}  // namespace hit
