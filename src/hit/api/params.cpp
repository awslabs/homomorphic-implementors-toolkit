// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "params.h"

using namespace std;
using namespace seal;

namespace hit {
    CKKSParams::CKKSParams(int num_slots, int max_ct_level, int log_scale, bool use_standard_params)
        : log_scale_(log_scale), use_std_params_(use_standard_params) {
        if (max_ct_level < 0) {
            LOG_AND_THROW_STREAM("Invalid parameters when creating HIT-SEAL instance: "
                                 << "there must be at least one ciphertext prime.");
        }
        params = EncryptionParameters(scheme_type::ckks);
        int poly_modulus_degree = num_slots * 2;
        params.set_poly_modulus_degree(poly_modulus_degree);
        vector<int> modulus_vec = gen_modulus_vec(max_ct_level + 2, log_scale);
        params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, modulus_vec));
    }

    CKKSParams::CKKSParams(EncryptionParameters params, int log_scale, bool use_standard_params)
        : params(std::move(params)), log_scale_(log_scale), use_std_params_(use_standard_params) {
    }

    int CKKSParams::num_slots() const {
        return static_cast<int>(params.poly_modulus_degree() / 2);
    }

    int CKKSParams::log_scale() const {
        return log_scale_;
    }

    int CKKSParams::max_ct_level() const {
        return static_cast<int>(params.coeff_modulus().size()) - 2;
    }

    bool CKKSParams::use_std_params() const {
        return use_std_params_;
    }

    /*
    Helper function: Generate a list of bit-lengths for the modulus primes.
    */
    vector<int> CKKSParams::gen_modulus_vec(int num_primes, int log_scale) {  // NOLINT
        if (num_primes < 2) {
            LOG_AND_THROW_STREAM("Invalid parameters when creating HIT-SEAL instance: "
                                 << "there must be at least two primes in the modulus.");
        }

        vector<int> modulusVector(num_primes, log_scale);
        // the SEAL examples recommend the last modulus be 60 bits; it's unclear why,
        // and also unclear how closely that choice is related to log_scale (they use 40 in their examples)
        modulusVector[0] = 60;
        // The special modulus has to be as large as the largest prime in the chain.
        modulusVector[num_primes - 1] = 60;

        return modulusVector;
    }
}  // namespace hit
