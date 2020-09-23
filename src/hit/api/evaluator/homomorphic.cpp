// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* This is an alternate interface for SEAL's Evaluator interface. It only includes a subset of
 * SEAL's Evaluator API, and those functions now have a simpler interface.
 */

#include "homomorphic.h"
#include "../../common.h"

#include <future>

#include "../../sealutils.h"
#include <glog/logging.h>

using namespace std;
using namespace seal;

namespace hit {

    /* Note: there is a flag to update_metadata of ciphertexts
     * however, *this evaluator must not depend on those values* (specifically: he_level() and scale()).
     * Instead, it must depend on SEAL's metadata for ciphertext level and scale.
     * This is a result of the current architecture of the evaluators:
     * In the Debug evaluator, we turn off update_metadata and let the DepthFinder/ScaleEstimator
     * evaluators take compute HE level and scale. That means if this evaluator tries to use those
     * metadata values, it will always be incorrect (no matter which order Debug calls its sub-evaluators).
     */

    HomomorphicEval::HomomorphicEval(int num_slots, int multiplicative_depth, int log_scale, bool use_seal_params,
                                     const vector<int> &galois_steps) {
        shared_param_init(num_slots, multiplicative_depth, log_scale, use_seal_params);
        seal_evaluator = new seal::Evaluator(context);

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
            galois_keys = keygen.galois_keys_local(galois_steps);
        } else {
            // generate all galois keys
            galois_keys = keygen.galois_keys_local();
        }
        relin_keys = keygen.relin_keys_local();

        print_elapsed_time(start);

        seal_encryptor = new Encryptor(context, pk);
        seal_decryptor = new Decryptor(context, sk);
    }

    void HomomorphicEval::deserialize_common(istream &params_stream) {
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


        istringstream pkstream(ckksParams.pubkey());
        pk.load(context, pkstream);
        seal_encryptor = new Encryptor(context, pk);
    }

    /* An evaluation instance */
    HomomorphicEval::HomomorphicEval(istream &params_stream, istream &galois_key_stream,
                                     istream &relin_key_stream) {
        deserialize_common(params_stream);

        timepoint start = chrono::steady_clock::now();
        VLOG(LOG_VERBOSE) << "Reading keys...";
        galois_keys.load(context, galois_key_stream);
        relin_keys.load(context, relin_key_stream);
        if (VLOG_IS_ON(LOG_VERBOSE)) {
            print_elapsed_time(start);
        }
    }

    /* A full instance */
    HomomorphicEval::HomomorphicEval(istream &params_stream, istream &galois_key_stream,
                                     istream &relin_key_stream, istream &secret_key_stream) {
        deserialize_common(params_stream);

        timepoint start = chrono::steady_clock::now();
        VLOG(LOG_VERBOSE) << "Reading keys...";
        sk.load(context, secret_key_stream);
        galois_keys.load(context, galois_key_stream);
        relin_keys.load(context, relin_key_stream);
        if (VLOG_IS_ON(LOG_VERBOSE)) {
            print_elapsed_time(start);
        }
    }

    HomomorphicEval::~HomomorphicEval() {
        delete seal_encryptor;
        delete seal_decryptor;
        delete seal_evaluator;
        delete encoder;
        delete params;
    }

    void HomomorphicEval::save(ostream &params_stream, ostream &galois_key_stream, ostream &relin_key_stream,
                               ostream *secret_key_stream) {
        if (secret_key_stream != nullptr) {
            sk.save(*secret_key_stream);
        }

        protobuf::CKKSParams ckksParams = save_ckks_params();
        ckksParams.SerializeToOstream(&params_stream);

        // There is a SEAL limitation that prevents saving large files with compression
        // This is reported at https://github.com/microsoft/SEAL/issues/142
        galois_keys.save(galois_key_stream, compr_mode_type::none);
        relin_keys.save(relin_key_stream);
    }

    CKKSCiphertext HomomorphicEval::encrypt(const vector<double> &coeffs, int level) {
        int num_slots_ = encoder->slot_count();
        if (coeffs.size() != num_slots_) {
            // bad things can happen if you don't plan for your input to be smaller than the ciphertext
            // This forces the caller to ensure that the input has the correct size or is at least appropriately padded
            throw invalid_argument(
                "You can only encrypt vectors which have exactly as many coefficients as the number of plaintext "
                "slots: Expected " +
                to_string(num_slots_) + ", got " + to_string(coeffs.size()));
        }

        if (level == -1) {
            level = context->first_context_data()->chain_index();
        }

        auto context_data = context->first_context_data();
        double scale = (double)pow(2, log_scale_);
        while (context_data->chain_index() > level) {
            // order of operations is very important: floating point arithmetic is not associative
            scale = (scale * scale) / static_cast<double>(context_data->parms().coeff_modulus().back().value());
            context_data = context_data->next_context_data();
        }

        CKKSCiphertext destination;
        destination.he_level_ = level;
        destination.scale_ = scale;

        Plaintext temp;
        encoder->encode(coeffs, context_data->parms_id(), scale, temp);
        seal_encryptor->encrypt(temp, destination.seal_ct);

        destination.num_slots_ = num_slots_;
        destination.initialized = true;

        return destination;
    }

    vector<double> HomomorphicEval::decrypt(const CKKSCiphertext &encrypted) const {
        if (seal_decryptor == nullptr) {
            throw invalid_argument("Decryption is only possible from a deserialized instance when the secret key is provided.");
        }

        Plaintext temp;

        int lvl = encrypted.he_level();
        if (lvl != 0) {
            LOG(WARNING) << "Decrypting a ciphertext at level " << lvl << "; consider starting with a smaller modulus"
                         << " to improve performance.";
        }

        seal_decryptor->decrypt(encrypted.seal_ct, temp);

        vector<double> decoded_output;
        encoder->decode(temp, decoded_output);

        return decoded_output;
    }

    void HomomorphicEval::reset_internal() {
    }

    int HomomorphicEval::get_SEAL_level(const CKKSCiphertext &ct) const {
        return context->get_context_data(ct.seal_ct.parms_id())->chain_index();
    }

    void HomomorphicEval::rotate_right_inplace_internal(CKKSCiphertext &ct, int steps) {
        CKKSCiphertext dest = ct;
        seal_evaluator->rotate_vector_inplace(ct.seal_ct, -steps, galois_keys);
    }

    void HomomorphicEval::rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) {
        seal_evaluator->rotate_vector_inplace(ct.seal_ct, steps, galois_keys);
    }

    void HomomorphicEval::negate_inplace_internal(CKKSCiphertext &ct) {
        seal_evaluator->negate_inplace(ct.seal_ct);
    }

    void HomomorphicEval::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // check that ciphertexts are at the same level to avoid an obscure SEAL error
        if (get_SEAL_level(ct1) != get_SEAL_level(ct2)) {
            stringstream buffer;
            buffer << "Error in HomomorphicEval::add: input levels do not match: " << get_SEAL_level(ct1)
                   << " != " << get_SEAL_level(ct2);
            throw invalid_argument(buffer.str());
        }
        seal_evaluator->add_inplace(ct1.seal_ct, ct2.seal_ct);
    }

    void HomomorphicEval::add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        Plaintext encoded_plain;
        encoder->encode(scalar, ct.seal_ct.parms_id(), ct.seal_ct.scale(), encoded_plain);
        seal_evaluator->add_plain_inplace(ct.seal_ct, encoded_plain);
    }

    void HomomorphicEval::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        if (plain.size() != ct.num_slots()) {
            throw invalid_argument(
                "Error in HomomorphicEval::add_plain_internal: plaintext size does not match ciphertext size");
        }
        Plaintext temp;
        encoder->encode(plain, ct.seal_ct.parms_id(), ct.seal_ct.scale(), temp);
        seal_evaluator->add_plain_inplace(ct.seal_ct, temp);
    }

    void HomomorphicEval::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // check that ciphertexts are at the same level to avoid an obscure SEAL error
        if (get_SEAL_level(ct1) != get_SEAL_level(ct2)) {
            stringstream buffer;
            buffer << "Error in HomomorphicEval::sub: input levels do not match: " << get_SEAL_level(ct1)
                   << " != " << get_SEAL_level(ct2);
            throw invalid_argument(buffer.str());
        }
        seal_evaluator->sub_inplace(ct1.seal_ct, ct2.seal_ct);
    }

    void HomomorphicEval::sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        Plaintext encoded_plain;
        encoder->encode(scalar, ct.seal_ct.parms_id(), ct.seal_ct.scale(), encoded_plain);
        seal_evaluator->sub_plain_inplace(ct.seal_ct, encoded_plain);
    }

    void HomomorphicEval::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        if (plain.size() != ct.num_slots()) {
            throw invalid_argument(
                "Error in HomomorphicEval::sub_plain_internal: plaintext size does not match ciphertext size");
        }
        Plaintext temp;
        encoder->encode(plain, ct.seal_ct.parms_id(), ct.seal_ct.scale(), temp);
        seal_evaluator->sub_plain_inplace(ct.seal_ct, temp);
    }

    void HomomorphicEval::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // check that ciphertexts are at the same level to avoid an obscure SEAL error
        if (get_SEAL_level(ct1) != get_SEAL_level(ct2)) {
            stringstream buffer;
            buffer << "Error in HomomorphicEval::multiply: input levels do not match: " << get_SEAL_level(ct1)
                   << " != " << get_SEAL_level(ct2);
            throw invalid_argument(buffer.str());
        }
        seal_evaluator->multiply_inplace(ct1.seal_ct, ct2.seal_ct);
        if (update_metadata_) {
            ct1.scale_ *= ct2.scale();
        }
    }

    /* WARNING: Multiplying by 0 results in non-constant time behavior! Only multiply by 0 if the scalar is truly
     * public. */
    void HomomorphicEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        if (scalar != double{0}) {
            Plaintext encoded_plain;
            encoder->encode(scalar, ct.seal_ct.parms_id(), ct.seal_ct.scale(), encoded_plain);
            seal_evaluator->multiply_plain_inplace(ct.seal_ct, encoded_plain);
        } else {
            double previous_scale = ct.seal_ct.scale();
            seal_encryptor->encrypt_zero(ct.seal_ct.parms_id(), ct.seal_ct);
            // seal sets the scale to be 1, but our the debug evaluator always ensures that the SEAL scale is consistent
            // with our mirror calculation
            ct.seal_ct.scale() = previous_scale * previous_scale;
        }
        if (update_metadata_) {
            ct.scale_ *= ct.scale();
        }
    }

    void HomomorphicEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        if (plain.size() != ct.num_slots()) {
            throw invalid_argument(
                "Error in HomomorphicEval::multiply_plain_internal: plaintext size does not match ciphertext "
                "size");
        }
        Plaintext temp;
        encoder->encode(plain, ct.seal_ct.parms_id(), ct.seal_ct.scale(), temp);
        seal_evaluator->multiply_plain_inplace(ct.seal_ct, temp);
        if (update_metadata_) {
            ct.scale_ *= ct.scale();
        }
    }

    void HomomorphicEval::square_inplace_internal(CKKSCiphertext &ct) {
        seal_evaluator->square_inplace(ct.seal_ct);
        if (update_metadata_) {
            ct.scale_ *= ct.scale();
        }
    }

    void HomomorphicEval::mod_down_to_level_inplace_internal(CKKSCiphertext &ct, int level) {
        if (get_SEAL_level(ct) < level) {
            stringstream buffer;
            buffer << "Error in mod_down_to_level: input is at a lower level than target. Input level: "
                   << get_SEAL_level(ct) << ", target level: " << level;
            throw invalid_argument(buffer.str());
        }
        while (get_SEAL_level(ct) > level) {
            multiply_plain_inplace(ct, 1);
            rescale_to_next_inplace(ct);
        }
    }

    void HomomorphicEval::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        seal_evaluator->rescale_to_next_inplace(ct.seal_ct);

        if (update_metadata_) {
            // we have to get the last prime *before* reducing the HE level,
            // since the "last prime" is level-dependent
            auto context_data = getContextData(ct);
            uint64_t prime = context_data->parms().coeff_modulus().back().value();
            ct.scale_ /= prime;
            ct.he_level_--;
        }
    }

    void HomomorphicEval::relinearize_inplace_internal(CKKSCiphertext &ct) {
        seal_evaluator->relinearize_inplace(ct.seal_ct, relin_keys);
    }
}  // namespace hit
