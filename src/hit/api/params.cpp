// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "params.h"

using namespace std;

namespace hit {
    BootstrappingParams::BootstrappingParams(latticpp::BootstrappingParameters lattigo_btp_params)
        : lattigo_btp_params(move(lattigo_btp_params)) {
    }

    int BootstrappingParams::bootstrapping_depth() const {
        return bootstrapDepth(lattigo_btp_params);
    }

    CKKSParams::CKKSParams(latticpp::Parameters lattigo_params) : lattigo_params(move(lattigo_params)) {
    }

    CKKSParams::CKKSParams(latticpp::BootstrappingParameters lattigo_btp_params)
        : CKKSParams(genParams(move(lattigo_btp_params)), move(lattigo_btp_params)) {
    }

    CKKSParams::CKKSParams(latticpp::Parameters lattigo_params, latticpp::BootstrappingParameters lattigo_btp_params)
        : lattigo_params(move(lattigo_params)),
          btp_params(optional<BootstrappingParams>(BootstrappingParams(move(lattigo_btp_params)))) {
    }

    CKKSParams::CKKSParams(int num_slots, int max_ct_level, int log_scale, int num_ks_primes,
                           optional<BootstrappingParams> btp_params)
        : btp_params(move(btp_params)) {
        if (max_ct_level < 0 || num_ks_primes < 1) {
            LOG_AND_THROW_STREAM("Invalid parameters when creating HIT-Lattigo instance: "
                                 << "there must be at least one ciphertext prime and one ks prime.");
        }

        vector<uint8_t> log_qi(max_ct_level + 1, log_scale);
        // the SEAL examples recommend the last modulus be 60 bits; it's unclear why,
        // and also unclear how closely that choice is related to log_scale (they use 40 in their examples)
        log_qi[0] = 60;
        vector<uint8_t> log_pi(num_ks_primes, 61);

        lattigo_params = latticpp::newParametersFromLogModuli(log2(num_slots) + 1, log_qi, log_pi, log_scale);
    }

    int CKKSParams::num_slots() const {
        return latticpp::numSlots(lattigo_params);
    }

    int CKKSParams::log_scale() const {
        return static_cast<int>(log2(latticpp::scale(lattigo_params)));
    }

    int CKKSParams::max_ct_level() const {
        int maxLvl = latticpp::maxLevel(lattigo_params);
        if (btp_params.has_value()) {
            maxLvl -= btp_params.value().bootstrapping_depth();
        }
        return maxLvl;
    }

    int CKKSParams::max_param_level() const {
        return latticpp::maxLevel(lattigo_params);
    }

}  // namespace hit
