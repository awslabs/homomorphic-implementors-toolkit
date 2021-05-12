// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* This file offers default implementation for most functions in the
 * CKKSEvaluator interface.
 */

#include "context.h"

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
        for (int i = 1; i < num_primes - 1; i++) {
            modulusVector[i] = log_scale;
        }
        return modulusVector;
    }

    HEContext::HEContext(const Parameters &params) : params(params) { }

    HEContext::HEContext(int logSlots, int mult_depth, int precisionBits) {
        vector<uint8_t> logQi = gen_ciphertext_modulus_vec(mult_depth + 1, precisionBits);
        vector<uint8_t> logPi(1);
        logPi[0] = 60; // special modulus. For now, we just use a single modulus like SEAL.
        params = newParametersFromLogModuli(logSlots + 1, logQi, mult_depth + 1, logPi, 1);
    }

    int HEContext::max_ciphertext_level() {
        return maxLevel(params);
    }

    int HEContext::num_slots() {
        return numSlots(params);
    }

    uint64_t HEContext::getQi(int he_level) {
        return qi(params, he_level);
    }

    uint64_t HEContext::getPi(int i) {
        return pi(params, i);
    }

    int HEContext::numQi() {
        return qiCount(params);
    }

    int HEContext::numPi() {
        return piCount(params);
    }

    int HEContext::min_log_scale() {
        // SEAL throws an error for 21, but allows 22
        // I haven't updated this for Lattigo; but this is WAY lower than would work in practice anyway,
        // so I'm not too concerned.
        return 22;
    }
}  // namespace hit
