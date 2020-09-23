// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "CKKSInstance.h"

#include <glog/logging.h>

#include <experimental/filesystem>
#include <fstream>

#include "api/evaluator/debug.h"
#include "api/evaluator/depthfinder.h"
#include "api/evaluator/homomorphic.h"
#include "api/evaluator/opcount.h"
#include "api/evaluator/plaintext.h"
#include "api/evaluator/scaleestimator.h"
#include "common.h"
#include "sealutils.h"

using namespace std;
using namespace seal;
namespace fs = experimental::filesystem;

// SEAL throws an error for 21, but allows 22
#define MIN_LOG_SCALE 22

namespace hit {

    std::vector<double> CKKSInstance::decrypt(const CKKSCiphertext&) const {
        throw invalid_argument("decrypt can only be called with Homomorphic or Debug evaluators");
    }

    int CKKSInstance::gen_modulus_vec(int numPrimes, vector<int> &modulusVector) const {
        // covers the initial and final 60-bit modulus
        int modBits = 120;
        // the SEAL examples recommend the last modulus be 60 bits; it's unclear why,
        // and also unclear how closely that choice is related to log_scale (they use 40 in their examples)
        modulusVector.push_back(60);
        for (int i = 2; i < numPrimes; i++) {
            modBits += log_scale_;
            modulusVector.push_back(log_scale_);
        }
        // The special modulus has to be as large as the largest prime in the chain.
        modulusVector.push_back(max(60, static_cast<int>(log_scale_)));

        return modBits;
    }

    void CKKSInstance::shared_param_init(int num_slots, int multiplicative_depth, int log_scale_in, bool use_seal_params) {
        log_scale_ = log_scale_in;
        if (!is_pow2(num_slots) || num_slots < 4096) {
            throw invalid_argument("Invalid parameters: num_slots must be a power of 2, and at least 4096. Got " + to_string(num_slots));
        }

        int poly_modulus_degree = num_slots * 2;
        if (log_scale_ < MIN_LOG_SCALE) {
            stringstream buffer;
            buffer << "Invalid parameters: Implied log_scale is " << log_scale_ << ", which is less than the minimum, "
                   << MIN_LOG_SCALE << ". Either increase the number of slots or decrease the number of primes."
                   << endl;
            buffer << "poly_modulus_degree is " << poly_modulus_degree << ", which limits the modulus to "
                   << poly_degree_to_max_mod_bits(poly_modulus_degree) << " bits";
            throw invalid_argument(buffer.str());
        }
        vector<int> modulusVector;
        int numPrimes = multiplicative_depth + 2;
        int modBits = gen_modulus_vec(numPrimes, modulusVector);
        int min_poly_degree = modulus_to_poly_degree(modBits);
        if (poly_modulus_degree < min_poly_degree) {
            stringstream buffer;
            buffer << "Invalid parameters: Ciphertexts for this combination of numPrimes and log_scale have more than "
                   << num_slots << " plaintext slots.";
            throw invalid_argument(buffer.str());
        }
        params = new EncryptionParameters(scheme_type::CKKS);
        params->set_poly_modulus_degree(poly_modulus_degree);
        params->set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, modulusVector));
        timepoint start = chrono::steady_clock::now();
        if (use_seal_params) {
            VLOG(LOG_VERBOSE) << "Creating encryption context...";
            context = SEALContext::Create(*params);
            if (VLOG_IS_ON(LOG_VERBOSE)) {
                print_elapsed_time(start);
            }
            standard_params_ = true;
        } else {
            LOG(WARNING) << "YOU ARE NOT USING SEAL PARAMETERS. Encryption parameters may not achieve 128-bit security"
                         << "DO NOT USE IN PRODUCTION";
            // for large parameter sets, see https://github.com/microsoft/SEAL/issues/84
            VLOG(LOG_VERBOSE) << "Creating encryption context...";
            context = SEALContext::Create(*params, true, sec_level_type::none);
            if (VLOG_IS_ON(LOG_VERBOSE)) {
                print_elapsed_time(start);
            }
            standard_params_ = false;
        }
        encoder = new CKKSEncoder(context);
    }

    uint64_t estimate_key_size(int num_galois_shift, int plaintext_slots, int depth) {
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
        // a public key just a ciphertext with the (depth+2) moduli
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




    protobuf::CKKSParams CKKSInstance::save_ckks_params() {
        protobuf::CKKSParams p;

        auto context_data = context->key_context_data();
        p.set_numslots(context_data->parms().poly_modulus_degree() / 2);
        p.set_logscale(log_scale_);
        p.set_standardparams(standard_params_);

        ostringstream sealpkBuf;
        pk.save(sealpkBuf);
        p.set_pubkey(sealpkBuf.str());

        for (const auto &prime : context_data->parms().coeff_modulus()) {
            p.add_modulusvec(prime.value());
        }

        return p;
    }

    CKKSInstance *try_load_instance(int num_slots, int multiplicative_depth, int log_scale, Mode mode,
                                    const vector<int> &) {
        string keydir = "keys";

        string paramID = to_string(2 * num_slots) + "-" + to_string(multiplicative_depth + 2) + "-" + to_string(log_scale);
        string paramsPath = keydir + "/" + paramID;

        if (!fs::exists(paramsPath)) {
            fs::create_directories(paramsPath);
        }

        string paramsFilePath = paramsPath + "/params.bin";
        string galoisFilePath = paramsPath + "/galois.bin";
        string relinFilePath = paramsPath + "/relin.bin";
        string privkeyFilePath = paramsPath + "/privkey.bin";

        CKKSInstance *c = nullptr;

        // We can't create generic fstream here for both cases:
        // if the file doesn't exist, opening an fstream with `ios::in | ios::out`
        // will create an empty file which will cause us to fall into
        // the wrong branch of the `if` statement.
        if (fs::exists(paramsFilePath) && fs::exists(privkeyFilePath)) {
            ifstream paramsFile(paramsFilePath, ios::in | ios::binary);
            ifstream privkeyFile(privkeyFilePath, ios::in | ios::binary);

            if (mode == NONEVALUATION) {
                // c = CKKSInstance::load_noneval_instance(paramsFile, privkeyFile);
            }

            if ((mode == DEBUG || mode == NORMAL) && fs::exists(galoisFilePath) && fs::exists(relinFilePath)) {
                ifstream galoisFile(galoisFilePath, ios::in | ios::binary);
                ifstream relinFile(relinFilePath, ios::in | ios::binary);

                // if (mode == DEBUG) {
                //     c = CKKSInstance::load_debug_instance(paramsFile, galoisFile, relinFile, privkeyFile);
                // } else {
                //     c = CKKSInstance::load_homomorphic_instance(paramsFile, galoisFile, relinFile, privkeyFile);
                // }

                galoisFile.close();
                relinFile.close();
            }

            paramsFile.close();
            privkeyFile.close();
        } else {
            ofstream paramsFile(paramsFilePath, ios::out | ios::binary);
            ofstream galoisFile(galoisFilePath, ios::out | ios::binary);
            ofstream relinFile(relinFilePath, ios::out | ios::binary);
            ofstream privkeyFile(privkeyFilePath, ios::out | ios::binary);
            // if (mode == DEBUG) {
            //     c = CKKSInstance::get_new_debug_instance(num_slots, multiplicative_depth, log_scale, false, galois_steps);
            // } else {  // NORMAL *or* NON-EVALUATION
            //     c = CKKSInstance::get_new_homomorphic_instance(num_slots, multiplicative_depth, log_scale, false, galois_steps);
            // }
            LOG(INFO) << "Saving keys to disk...";
            timepoint start = chrono::steady_clock::now();
            // c->save(&paramsFile, &galoisFile, &relinFile, &privkeyFile);
            print_elapsed_time(start);
            paramsFile.close();
            galoisFile.close();
            relinFile.close();
            privkeyFile.close();
        }

        return c;
    }
}  // namespace hit
