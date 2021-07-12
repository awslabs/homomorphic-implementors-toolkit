// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "params.h"

using namespace std;

namespace hit {

    // BootstrappingParams::BootstrappingParams(uint64_t secret_hamming_weight, uint64_t approx_range,
    //                                          uint64_t approx_degree, uint64_t double_angle_applications,
    //                                          vector<uint8_t> CtSLevels, vector<uint8_t> StCLevels, double
    //                                          maxN1N2Ratio)
    //     : secret_hamming_weight(secret_hamming_weight),
    //       approx_range(approx_range),
    //       approx_degree(approx_degree),
    //       double_angle_applications(double_angle_applications),
    //       CtSLevels(move(CtSLevels)),
    //       StCLevels(move(StCLevels)),
    //       maxN1N2Ratio(maxN1N2Ratio) {
    //     // From https://eprint.iacr.org/eprint-bin/getfile.pl?entry=2020/1203&version=20201008:204443&file=1203.pdf
    //     // section 5.4 The latest version of the paper https://eprint.iacr.org/2020/1203.pdf doesn't go into as much
    //     // detail and merely says "use Cos2 for non-sparse keys" (section 5.4)
    //     if (approx_degree < 2 * approx_range - 1) {
    //         trig_approx = Cos2;
    //     } else {
    //         trig_approx = Cos1;
    //     }
    // }

    BootstrappingParams::BootstrappingParams(latticpp::BootstrappingParameters btp_params)
        : lattigo_btp_params(move(btp_params)) {
    }

    int BootstrappingParams::bootstrapping_depth() const {
        return bootstrap_depth(lattigo_btp_params);
    }

    CKKSParams::CKKSParams(latticpp::Parameters params) : lattigo_params(move(params)) {
    }

    CKKSParams::CKKSParams(latticpp::Parameters lattigo_params, latticpp::BootstrappingParameters lattigo_btp_params) : 
      lattigo_params(move(lattigo_params)), 
      btp_params(optional<BootstrappingParams>(BootstrappingParams(move(lattigo_btp_params)))) {
    }

    CKKSParams::CKKSParams(int num_slots, int log_scale, int max_ct_level, int num_ks_primes,
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

        lattigo_params = latticpp::newParametersFromLogModuli(log2(num_slots) + 1, log_qi, max_ct_level + 1, log_pi,
                                                              num_ks_primes, log_scale);
    }

    int CKKSParams::num_slots() const {
        return latticpp::numSlots(lattigo_params);
    }

    int CKKSParams::log_scale() const {
        return static_cast<int>(log2(latticpp::scale(lattigo_params)));
    }

    int CKKSParams::max_ct_level() const {
        return latticpp::maxLevel(lattigo_params);
    }

}  // namespace hit
