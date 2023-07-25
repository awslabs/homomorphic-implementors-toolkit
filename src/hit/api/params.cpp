// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "params.h"

#include <boost/multiprecision/miller_rabin.hpp>

using namespace std;
using namespace seal;
using namespace boost::multiprecision;

namespace hit {

    // This is _not_ adversarial prime generation. The primes will be public, and security is based on
    // the total bit size of the _product_ of each "prime", so there are no security implications if
    // we accidentally generate a composite.
    int miller_rabin_iters = 25;

    // true if x \in mods, false otherwise
    bool contains(uint64_t x, const vector<Modulus> &mods) {
        for (const auto &m : mods) {
            if (x == m.value()) {
                return true;
            }
        }
        return false;
    }

    // return the representative of x mod n in (-n/2, n/2]
    uint64_t repr(uint64_t x, uint64_t n) {
        uint64_t cmod = x % n;
        return (cmod <= (n / 2)) ? cmod : (cmod - n);
    }

    // return the closest integer to x such that x = 1 mod n
    uint64_t to1Coset(uint64_t x, uint64_t n) {
        // note that n is always even in our uses case.
        // if x <= kn+n/2 (for some k), then repr(x,n) > 0,
        //   so we return kn+1, which is closer than (k+1)n+1.
        // if x > kn+n/2 (for some k), then repr(x,n) < 0,
        //   so we return (k+1)n+1, which is at least as close as kn+1.
        return x - repr(x, n) + 1;
    }

    // Find the smallest prime larger than `x` that is not in `mods`.
    uint64_t nextPrime(uint64_t x, uint64_t n, const vector<Modulus> &mods) {
        // find a number near x that is congruent to 1 mod n
        uint64_t next_test_val = to1Coset(x, n);

        // to1Coset can return a value smaller than x
        if (next_test_val < x) {
            next_test_val += n;
        }

        while (!miller_rabin_test(next_test_val, 25) || contains(next_test_val, mods)) {
            next_test_val += n;
        }
        return next_test_val;
    }

    // Find the largest prime smaller than `x` that is not in `mods`.
    uint64_t prevPrime(uint64_t x, uint64_t n, const vector<Modulus> &mods) {
        // find a number near x that is congruent to 1 mod n
        uint64_t next_test_val = to1Coset(x, n);

        // to1Coset can return a value larger than x
        if (next_test_val > x) {
            next_test_val -= n;
        }

        while (!miller_rabin_test(next_test_val, 25) || contains(next_test_val, mods)) {
            next_test_val -= n;
        }
        return next_test_val;
    }

    // implements the prime selection algorithm in https://eprint.iacr.org/2020/1118, Algorithm 3
    vector<Modulus> reducedErrorPrimes(int poly_mod_degree, const vector<int> &modulus_vec) {
        int num_moduli = modulus_vec.size();
        vector<Modulus> primes(num_moduli);
        // m = 2 * poly_mod_degree is the cyclotomic index of the ring
        // all primes should be congruent to 1 mod m so that the cyclotomic polynomial splits completely mod q
        uint64_t m = 2 * poly_mod_degree;

        // generate a prime for keyswitching
        // this is independent of the ciphertext chain
        primes[num_moduli - 1] = prevPrime(to1Coset(pow(2, modulus_vec[num_moduli - 1]), m), m, primes);
        primes[num_moduli - 2] = nextPrime(to1Coset(pow(2, modulus_vec[num_moduli - 2]), m), m, primes);
        double delta = static_cast<double>(primes[num_moduli - 2].value());
        bool flip = false;
        for (int l = num_moduli - 3; l > 0; l--) {
            delta = delta * delta / static_cast<double>(primes[l + 1].value());
            uint64_t round_delta = static_cast<uint64_t>(delta);
            if (flip) {
                primes[l] = prevPrime(to1Coset(round_delta, m), m, primes);
            } else {
                primes[l] = nextPrime(to1Coset(round_delta, m), m, primes);
            }
            flip = !flip;
        }
        primes[0] = prevPrime(to1Coset(pow(2, modulus_vec[0]), m), m, primes);
        return primes;
    }

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
        vector<Modulus> mods = reducedErrorPrimes(poly_modulus_degree, modulus_vec);
        params.set_coeff_modulus(mods);
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
