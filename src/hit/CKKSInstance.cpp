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

namespace hit {

// SEAL throws an error for 21, but allows 22
#define MIN_LOG_SCALE 22

    // it turns out that the lossiness of encoding/decoding strongly depends on
    // this value. For evaluators that don't really use SEAL, but do use CKKS
    // encoding/decoding, this should be set to as high as possible.
    int defaultScaleBits = 30;

    CKKSInstance *CKKSInstance::get_new_depthfinder_instance() {
        return new CKKSInstance(DEPTH, 4096, 0, defaultScaleBits, true);
    }
    CKKSInstance *CKKSInstance::get_new_opcount_instance() {
        return new CKKSInstance(OPCOUNT, 4096, 0, defaultScaleBits, true);
    }
    CKKSInstance *CKKSInstance::get_new_plaintext_instance(int num_slots, bool use_seal_params) {
        return new CKKSInstance(PLAINTEXT, num_slots, 0, defaultScaleBits, use_seal_params);
    }
    CKKSInstance *CKKSInstance::get_new_scaleestimator_instance(int num_slots, int multiplicative_depth, bool use_seal_params) {
        return new CKKSInstance(SCALE, num_slots, multiplicative_depth, defaultScaleBits, use_seal_params);
    }
    CKKSInstance *CKKSInstance::get_new_homomorphic_instance(int num_slots, int multiplicative_depth, int log_scale,
                                                             bool use_seal_params, const vector<int> &galois_steps) {
        return new CKKSInstance(num_slots, multiplicative_depth, log_scale, use_seal_params, false, galois_steps);
    }
    CKKSInstance *CKKSInstance::load_homomorphic_instance(istream &params_stream, istream &galois_key_stream,
                                                          istream &relin_key_stream, istream &secret_key_stream) {
        return new CKKSInstance(params_stream, &galois_key_stream, &relin_key_stream, &secret_key_stream, NORMAL);
    }
    CKKSInstance *CKKSInstance::get_new_debug_instance(int num_slots, int multiplicative_depth, int log_scale, bool use_seal_params,
                                                       const vector<int> &galois_steps) {
        LOG(WARNING) << "CREATING AN INSECURE DEBUG EVALUATOR. DO NOT USE IN PRODUCTION.";
        return new CKKSInstance(num_slots, multiplicative_depth, log_scale, use_seal_params, true, galois_steps);
    }
    CKKSInstance *CKKSInstance::load_debug_instance(istream &params_stream, istream &galois_key_stream,
                                                    istream &relin_key_stream, istream &secret_key_stream) {
        return new CKKSInstance(params_stream, &galois_key_stream, &relin_key_stream, &secret_key_stream, DEBUG);
    }
    CKKSInstance *CKKSInstance::load_eval_instance(istream &params_stream, istream &galois_key_stream,
                                                   istream &relin_key_stream) {
        return new CKKSInstance(params_stream, &galois_key_stream, &relin_key_stream, nullptr, EVALUATION);
    }

    CKKSInstance *CKKSInstance::load_noneval_instance(istream &params_stream, istream &secret_key_stream) {
        return new CKKSInstance(params_stream, nullptr, nullptr, &secret_key_stream, NONEVALUATION);
    }

    protobuf::CKKSParams CKKSInstance::save_ckks_params() {
        protobuf::CKKSParams p;

        p.set_version(0);
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

    CKKSInstance::CKKSInstance(Mode mode, int num_slots, int multiplicative_depth, int log_scale, bool use_seal_params)
        : seal_encryptor(nullptr), decryptor(nullptr), mode_(mode) {
        shared_param_init(num_slots, multiplicative_depth, log_scale, use_seal_params);

        switch (mode) {
            case DEPTH:
                encryptor = new CKKSEncryptor(context, num_slots, false);
                evaluator = new DepthFinder(context);
                break;
            case OPCOUNT:
                encryptor = new CKKSEncryptor(context, num_slots, false);
                evaluator = new OpCount(context);
                break;
            case PLAINTEXT:
                encryptor = new CKKSEncryptor(context, num_slots, true);
                evaluator = new PlaintextEval(context);
                break;
            case SCALE:
                encryptor = new CKKSEncryptor(context, num_slots, true);
                evaluator = new ScaleEstimator(context, 2 * num_slots, pow(2.0, log_scale));
                break;
            default:
                throw invalid_argument("CKKSInstance: Unsupported mode");
        }
    }

    void CKKSInstance::shared_param_init(int num_slots, int multiplicative_depth, int log_scale_in, bool use_seal_params) {
        log_scale_ = log_scale_in;
        if (!is_pow2(num_slots) || num_slots < 4096) {
            stringstream buffer;
            buffer << "Invalid parameters: num_slots must be a power of 2, and at least 4096. Got " << num_slots;
            throw invalid_argument(buffer.str());
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

    void CKKSInstance::reset() {
        evaluator->reset();
        encryption_count_ = 0;
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

    CKKSInstance::CKKSInstance(istream &params_stream, istream *galois_key_stream, istream *relin_key_stream,
                               istream *secret_key_stream, Mode mode) {
        mode_ = mode;
        protobuf::CKKSParams ckksParams;
        ckksParams.ParseFromIstream(&params_stream);
        log_scale_ = ckksParams.logscale();
        int num_slots = ckksParams.numslots();
        int poly_modulus_degree = num_slots * 2;
        int numPrimes = ckksParams.modulusvec_size();
        vector<Modulus> modulusVector;
        modulusVector.reserve(numPrimes);
        for (int i = 0; i < numPrimes; i++) {
            auto val = Modulus(ckksParams.modulusvec(i));
            modulusVector.push_back(val);
        }

        params = new EncryptionParameters(scheme_type::CKKS);
        params->set_poly_modulus_degree(poly_modulus_degree);
        params->set_coeff_modulus(modulusVector);

        standard_params_ = ckksParams.standardparams();
        timepoint start = chrono::steady_clock::now();
        if (standard_params_) {
            VLOG(LOG_VERBOSE) << "Creating encryption context...";
            context = SEALContext::Create(*params);
            if (VLOG_IS_ON(LOG_VERBOSE)) {
                print_elapsed_time(start);
            }
        } else {
            LOG(WARNING) << "YOU ARE NOT USING SEAL PARAMETERS. Encryption parameters may not achieve 128-bit security."
                         << " DO NOT USE IN PRODUCTION";
            // for large parameter sets, see https://github.com/microsoft/SEAL/issues/84
            VLOG(LOG_VERBOSE) << "Creating encryption context...";
            context = SEALContext::Create(*params, true, sec_level_type::none);
            if (VLOG_IS_ON(LOG_VERBOSE)) {
                print_elapsed_time(start);
            }
        }
        encoder = new CKKSEncoder(context);

        start = chrono::steady_clock::now();
        VLOG(LOG_VERBOSE) << "Reading keys...";
        istringstream pkstream(ckksParams.pubkey());
        pk.load(context, pkstream);
        seal_encryptor = new Encryptor(context, pk);
        encryptor = new CKKSEncryptor(context, encoder, seal_encryptor, mode == DEBUG);

        if (mode != EVALUATION && secret_key_stream == nullptr) {
            throw invalid_argument("secret_key_stream is required in for non-eval evaluator");
        }

        if (secret_key_stream != nullptr) {
            sk.load(context, *secret_key_stream);
            decryptor = new CKKSDecryptor(context, encoder, sk);
        }
        if (galois_key_stream != nullptr) {
            gk.load(context, *galois_key_stream);
        }
        if (relin_key_stream != nullptr) {
            rk.load(context, *relin_key_stream);
        }
        if (VLOG_IS_ON(LOG_VERBOSE)) {
            print_elapsed_time(start);
        }

        if (mode == DEBUG) {
            evaluator = new DebugEval(context, *encoder, *seal_encryptor, gk, rk, pow(2.0, log_scale_), *decryptor);
        } else if (mode == NONEVALUATION) {
            // don't make an evaluator
            return;
        } else {  // mode == NORMAL or EVALUATION
            evaluator = new HomomorphicEval(context, *encoder, *seal_encryptor, gk, rk, true);
        }
    }

    void CKKSInstance::save(ostream *params_stream, ostream *galois_key_stream, ostream *relin_key_stream,
                            ostream *secret_key_stream) {
        if (mode_ != NORMAL && mode_ != DEBUG) {
            throw invalid_argument("You can only save homomorphic or debug instances.");
        }
        if (secret_key_stream != nullptr) {
            sk.save(*secret_key_stream);
        }
        if (params_stream != nullptr) {
            protobuf::CKKSParams ckksParams = save_ckks_params();
            ckksParams.SerializeToOstream(params_stream);
        }
        if (galois_key_stream != nullptr) {
            // There is a SEAL limitation that prevents saving large files with compression
            // This is reported at https://github.com/microsoft/SEAL/issues/142
            gk.save(*galois_key_stream, compr_mode_type::none);
        }
        if (relin_key_stream != nullptr) {
            rk.save(*relin_key_stream);
        }
    }

    CKKSInstance::CKKSInstance(int num_slots, int multiplicative_depth, int log_scale, bool use_seal_params, bool debug,
                               const vector<int> &galois_steps) {
        shared_param_init(num_slots, multiplicative_depth, log_scale, use_seal_params);

        int numGaloisKeys = galois_steps.size();
        LOG(INFO) << "Generating keys for " << num_slots << " slots and depth " << multiplicative_depth << ", including "
                  << (numGaloisKeys != 0 ? to_string(numGaloisKeys) : "all") << " Galois keys." << endl;

        double keysSizeBytes = estimate_key_size(galois_steps.size(), num_slots, multiplicative_depth);
        LOG(INFO) << "Estimated size is " << setprecision(3);
        // using base-10 (SI) units, rather than base-2 units.
        double unitMultiplier = 1000;
        double bytesPerKB = unitMultiplier;
        double bytesPerMB = bytesPerKB * unitMultiplier;
        double bytesPerGB = bytesPerMB * unitMultiplier;
        if (keysSizeBytes < bytesPerKB) {
            LOG(INFO) << keysSizeBytes << " bytes";
        } else if (keysSizeBytes < bytesPerMB) {
            LOG(INFO) << keysSizeBytes / bytesPerKB << " kilobytes (base 10)";
        } else if (keysSizeBytes < bytesPerGB) {
            LOG(INFO) << keysSizeBytes / bytesPerMB << " megabytes (base 10)";
        } else {
            LOG(INFO) << keysSizeBytes / bytesPerGB << " gigabytes (base 10)";
        }

        LOG(INFO) << "Generating keys...";
        timepoint start = chrono::steady_clock::now();

        // generate keys
        // This call generates a KeyGenerator with fresh randomness
        // The KeyGenerator object contains deterministic keys.
        KeyGenerator keygen(context);
        sk = keygen.secret_key();
        pk = keygen.public_key();
        if (numGaloisKeys > 0) {
            gk = keygen.galois_keys_local(galois_steps);
        } else {
            // generate all galois keys
            gk = keygen.galois_keys_local();
        }
        rk = keygen.relin_keys_local();

        print_elapsed_time(start);

        seal_encryptor = new Encryptor(context, pk);
        encryptor = new CKKSEncryptor(context, encoder, seal_encryptor, debug);
        decryptor = new CKKSDecryptor(context, encoder, sk);

        if (debug) {
            evaluator = new DebugEval(context, *encoder, *seal_encryptor, gk, rk, pow(2.0, log_scale), *decryptor);
            mode_ = DEBUG;
        } else {
            evaluator = new HomomorphicEval(context, *encoder, *seal_encryptor, gk, rk, true);
            mode_ = NORMAL;
        }

        if (debug && VLOG_IS_ON(LOG_VERBOSE)) {
            print_parameters(context);

            // There are convenience method for accessing the SEALContext::ContextData for
            // some of the most important levels:

            //     SEALContext::key_context_data(): access to key level ContextData
            //     SEALContext::first_context_data(): access to highest data level ContextData
            //     SEALContext::last_context_data(): access to lowest level ContextData

            // We iterate over the chain and print the parms_id for each set of parameters.
            LOG(INFO) << "Print the modulus switching chain.";

            // First print the key level parameter information.
            auto context_data = context->key_context_data();
            LOG(INFO) << "----> Level (chain index): " << context_data->chain_index() << " ...... key_context_data()";
            LOG(INFO) << "      parms_id: " << context_data->parms_id();
            stringstream key_level_primes;
            for (const auto &prime : context_data->parms().coeff_modulus()) {
                key_level_primes << prime.value() << " ";
            }
            LOG(INFO) << "      coeff_modulus primes: " << hex << key_level_primes.str() << dec;
            LOG(INFO) << "\\";

            // Next iterate over the remaining (data) levels.
            context_data = context->first_context_data();
            while (context_data) {
                LOG(INFO) << " \\--> Level (chain index): " << context_data->chain_index();
                if (context_data->parms_id() == context->first_parms_id()) {
                    LOG(INFO) << " ...... first_context_data()";
                } else if (context_data->parms_id() == context->last_parms_id()) {
                    LOG(INFO) << " ...... last_context_data()";
                }
                LOG(INFO) << "      parms_id: " << context_data->parms_id() << endl;
                stringstream data_level_primes;
                for (const auto &prime : context_data->parms().coeff_modulus()) {
                    data_level_primes << prime.value() << " ";
                }
                LOG(INFO) << "      coeff_modulus primes: " << hex << data_level_primes.str() << dec;
                LOG(INFO) << "\\";

                // Step forward in the chain.
                context_data = context_data->next_context_data();
            }
            LOG(INFO) << " End of chain reached" << endl;
        }
    }

    CKKSInstance::~CKKSInstance() {
        if (mode_ == NONEVALUATION) {
            delete encryptor;
            delete seal_encryptor;
            delete decryptor;
        } else {
            delete evaluator;
            if (mode_ >= NORMAL) {
                delete encryptor;
                delete seal_encryptor;
                if (mode_ != EVALUATION) {
                    delete decryptor;
                }
            }
        }

        delete encoder;
        delete params;
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

    void CKKSInstance::set_max_val(const vector<double> &plain) {
        double maxVal = l_inf_norm(plain);

        switch (mode_) {
            case SCALE: {
                auto *e = dynamic_cast<ScaleEstimator *>(evaluator);
                e->update_plaintext_max_val(maxVal);
                break;
            }
            case DEBUG: {
                auto *e = dynamic_cast<DebugEval *>(evaluator);
                e->update_plaintext_max_val(maxVal);
                break;
            }
            case PLAINTEXT: {
                auto *e = dynamic_cast<PlaintextEval *>(evaluator);
                e->update_plaintext_max_val(maxVal);
                break;
            }
            default:
                break;
        }
    }

    CKKSCiphertext CKKSInstance::encrypt(const vector<double> &coeffs, int level) {
        CKKSCiphertext ct = encryptor->encrypt(coeffs, pow(2.0, log_scale_), level);
        set_max_val(coeffs);
        encryption_count_++;
        return ct;
    }

    vector<double> CKKSInstance::decrypt(const CKKSCiphertext &encrypted) {
        if (mode_ == NORMAL || mode_ == DEBUG || mode_ == NONEVALUATION) {
            return decryptor->decrypt(encrypted);
        }
        throw invalid_argument(
            "CKKSInstance: You cannot call decrypt unless using the Homomorphic or Debug evaluators!");
    }

    int CKKSInstance::plaintext_dim() const {
        return encoder->slot_count();
    }

    double CKKSInstance::get_estimated_max_log_scale() const {
        if (mode_ == SCALE) {
            auto *e = dynamic_cast<ScaleEstimator *>(evaluator);
            return e->get_estimated_max_log_scale();
        }
        if (mode_ == DEBUG) {
            auto *e = dynamic_cast<DebugEval *>(evaluator);
            return e->get_estimated_max_log_scale();
        }
        throw invalid_argument(
            "CKKSInstance: You cannot call get_estimated_max_log_scale unless using the ScaleEstimator or DebugEval "
            "evaluator!");
    }

    double CKKSInstance::get_exact_max_log_plain_val() const {
        if (mode_ == SCALE) {
            auto *e = dynamic_cast<ScaleEstimator *>(evaluator);
            return e->get_exact_max_log_plain_val();
        }
        if (mode_ == PLAINTEXT) {
            auto *e = dynamic_cast<PlaintextEval *>(evaluator);
            return e->get_exact_max_log_plain_val();
        }
        if (mode_ == DEBUG) {
            auto *e = dynamic_cast<DebugEval *>(evaluator);
            return e->get_exact_max_log_plain_val();
        }
        throw invalid_argument(
            "CKKSInstance: You cannot call get_exact_max_log_plain_val unless using the ScaleEstimator or DebugEval "
            "evaluator!");
    }

    int CKKSInstance::get_multiplicative_depth() const {
        if (mode_ == DEPTH) {
            auto *e = dynamic_cast<DepthFinder *>(evaluator);
            return e->get_multiplicative_depth();
        }
        if (mode_ == OPCOUNT) {
            auto *e = dynamic_cast<OpCount *>(evaluator);
            return e->get_multiplicative_depth();
        }
        throw invalid_argument(
            "CKKSInstance: You cannot call get_multiplicative_depth unless using the DepthFinder evaluator!");
    }

    void CKKSInstance::print_op_count() const {
        if (mode_ == OPCOUNT) {
            auto *e = dynamic_cast<OpCount *>(evaluator);
            LOG(INFO) << endl << "Encryptions: " << encryption_count_;
            e->print_op_count();
            return;
        }
        throw invalid_argument("CKKSInstance: You cannot call print_op_count unless using the OpCount evaluator!");
    }

    CKKSInstance *try_load_instance(int num_slots, int multiplicative_depth, int log_scale, Mode mode,
                                    const vector<int> &galois_steps) {
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
                c = CKKSInstance::load_noneval_instance(paramsFile, privkeyFile);
            }

            if ((mode == DEBUG || mode == NORMAL) && fs::exists(galoisFilePath) && fs::exists(relinFilePath)) {
                ifstream galoisFile(galoisFilePath, ios::in | ios::binary);
                ifstream relinFile(relinFilePath, ios::in | ios::binary);

                if (mode == DEBUG) {
                    c = CKKSInstance::load_debug_instance(paramsFile, galoisFile, relinFile, privkeyFile);
                } else {
                    c = CKKSInstance::load_homomorphic_instance(paramsFile, galoisFile, relinFile, privkeyFile);
                }

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
            if (mode == DEBUG) {
                c = CKKSInstance::get_new_debug_instance(num_slots, multiplicative_depth, log_scale, false, galois_steps);
            } else {  // NORMAL *or* NON-EVALUATION
                c = CKKSInstance::get_new_homomorphic_instance(num_slots, multiplicative_depth, log_scale, false, galois_steps);
            }
            LOG(INFO) << "Saving keys to disk...";
            timepoint start = chrono::steady_clock::now();
            c->save(&paramsFile, &galoisFile, &relinFile, &privkeyFile);
            print_elapsed_time(start);
            paramsFile.close();
            galoisFile.close();
            relinFile.close();
            privkeyFile.close();
        }

        return c;
    }
}  // namespace hit
