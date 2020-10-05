// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* This is an alternate interface for SEAL's Evaluator interface. It only includes a subset of
 * SEAL's Evaluator API, and those functions now have a simpler interface.
 */

#include "homomorphic.h"
#include "../../common.h"
#include "hit/protobuf/ckksparams.pb.h"

#include <future>

#include "../../sealutils.h"
#include <glog/logging.h>

using namespace std;
using namespace seal;

// SEAL throws an error for 21, but allows 22
#define MIN_LOG_SCALE 22

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
                                     const vector<int> &galois_steps): log_scale_(log_scale) {

        if (!is_pow2(num_slots) || num_slots < 4096) {
            LOG_AND_THROW_STREAM("Invalid parameters when creating HomomorphicEval instance: "
                       << "num_slots must be a power of 2, and at least 4096. Got " << num_slots);
        }

        int poly_modulus_degree = num_slots * 2;
        if (log_scale_ < MIN_LOG_SCALE) {
            LOG_AND_THROW_STREAM("Invalid parameters when creating HomomorphicEval instance: "
                       << "log_scale is " << log_scale_ << ", which is less than the minimum "
                       << MIN_LOG_SCALE << ". Either increase the number of slots or decrease the number of primes."
                       << endl
                       << "poly_modulus_degree is " << poly_modulus_degree << ", which limits the modulus to "
                       << poly_degree_to_max_mod_bits(poly_modulus_degree) << " bits");
        }

        int num_primes = multiplicative_depth + 2;
        vector<int> modulusVector = gen_modulus_vec(num_primes, log_scale_);
        int mod_bits = 0;
        for(const auto &bits : modulusVector) {
            mod_bits += bits;
        }
        int min_poly_degree = modulus_to_poly_degree(mod_bits);
        if (poly_modulus_degree < min_poly_degree) {
            LOG_AND_THROW_STREAM("Invalid parameters when creating HomomorphicEval instance: "
                       << "Parameters for depth " << multiplicative_depth << " circuits and scale "
                       << log_scale << " bits require more than " << num_slots << " plaintext slots.");
        }
        EncryptionParameters params = EncryptionParameters(scheme_type::CKKS);
        params.set_poly_modulus_degree(poly_modulus_degree);
        params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, modulusVector));
        timepoint start = chrono::steady_clock::now();
        if (use_seal_params) {
            context = SEALContext::Create(params);
            print_elapsed_time(start, "Creating encryption context...");
            standard_params_ = true;
        } else {
            LOG(WARNING) << "YOU ARE NOT USING SEAL PARAMETERS. Encryption parameters may not achieve 128-bit security"
                         << "DO NOT USE IN PRODUCTION";
            // for large parameter sets, see https://github.com/microsoft/SEAL/issues/84
            context = SEALContext::Create(params, true, sec_level_type::none);
            print_elapsed_time(start, "Creating encryption context...");
            standard_params_ = false;
        }
        encoder = new CKKSEncoder(context);
        seal_evaluator = new Evaluator(context);

        int num_galois_keys = galois_steps.size();
        VLOG(VLOG_VERBOSE) << "Generating keys for " << num_slots << " slots and depth " << multiplicative_depth << ", including "
                  << (num_galois_keys != 0 ? to_string(num_galois_keys) : "all") << " Galois keys." << endl;

        double keys_size_bytes = estimate_key_size(galois_steps.size(), num_slots, multiplicative_depth);
        VLOG(VLOG_VERBOSE) << "Estimated size is " << setprecision(3);
        // using base-10 (SI) units, rather than base-2 units.
        double unit_multiplier = 1000;
        double bytes_per_kb = unit_multiplier;
        double bytes_per_mb = bytes_per_kb * unit_multiplier;
        double bytes_per_gb = bytes_per_mb * unit_multiplier;
        if (keys_size_bytes < bytes_per_kb) {
            VLOG(VLOG_VERBOSE) << keys_size_bytes << " bytes";
        } else if (keys_size_bytes < bytes_per_mb) {
            VLOG(VLOG_VERBOSE) << keys_size_bytes / bytes_per_kb << " kilobytes (base 10)";
        } else if (keys_size_bytes < bytes_per_gb) {
            VLOG(VLOG_VERBOSE) << keys_size_bytes / bytes_per_mb << " megabytes (base 10)";
        } else {
            VLOG(VLOG_VERBOSE) << keys_size_bytes / bytes_per_gb << " gigabytes (base 10)";
        }

        start = chrono::steady_clock::now();
        // generate keys
        // This call generates a KeyGenerator with fresh randomness
        // The KeyGenerator object contains deterministic keys.
        KeyGenerator keygen(context);
        sk = keygen.secret_key();
        pk = keygen.public_key();
        if (num_galois_keys > 0) {
            galois_keys = keygen.galois_keys_local(galois_steps);
        } else {
            // generate all galois keys
            galois_keys = keygen.galois_keys_local();
        }
        relin_keys = keygen.relin_keys_local();

        print_elapsed_time(start, "Generating keys...");

        seal_encryptor = new Encryptor(context, pk);
        seal_decryptor = new Decryptor(context, sk);
    }

    HomomorphicEval::~HomomorphicEval() {
        delete encoder;
        delete seal_evaluator;
        delete seal_encryptor;
        delete seal_decryptor;
    }

    void HomomorphicEval::deserialize_common(istream &params_stream) {
        protobuf::CKKSParams ckks_params;
        ckks_params.ParseFromIstream(&params_stream);
        log_scale_ = ckks_params.logscale();
        int num_slots = ckks_params.numslots();
        int poly_modulus_degree = num_slots * 2;
        int numPrimes = ckks_params.modulusvec_size();
        vector<Modulus> modulus_vector;
        modulus_vector.reserve(numPrimes);
        for (int i = 0; i < numPrimes; i++) {
            auto val = Modulus(ckks_params.modulusvec(i));
            modulus_vector.push_back(val);
        }

        EncryptionParameters params = EncryptionParameters(scheme_type::CKKS);
        params.set_poly_modulus_degree(poly_modulus_degree);
        params.set_coeff_modulus(modulus_vector);

        standard_params_ = ckks_params.standardparams();
        timepoint start = chrono::steady_clock::now();
        if (standard_params_) {
            context = SEALContext::Create(params);
            print_elapsed_time(start, "Creating encryption context...");
        } else {
            LOG(WARNING) << "YOU ARE NOT USING SEAL PARAMETERS. Encryption parameters may not achieve 128-bit security."
                         << " DO NOT USE IN PRODUCTION";
            // for large parameter sets, see https://github.com/microsoft/SEAL/issues/84
            context = SEALContext::Create(params, true, sec_level_type::none);
            print_elapsed_time(start, "Creating encryption context...");
        }
        seal_evaluator = new Evaluator(context);
        encoder = new CKKSEncoder(context);


        istringstream pkstream(ckks_params.pubkey());
        pk.load(context, pkstream);
        seal_encryptor = new Encryptor(context, pk);
    }

    /* An evaluation instance */
    HomomorphicEval::HomomorphicEval(istream &params_stream, istream &galois_key_stream,
                                     istream &relin_key_stream) {
        deserialize_common(params_stream);

        timepoint start = chrono::steady_clock::now();
        galois_keys.load(context, galois_key_stream);
        relin_keys.load(context, relin_key_stream);
        print_elapsed_time(start, "Reading keys...");
    }

    /* A full instance */
    HomomorphicEval::HomomorphicEval(istream &params_stream, istream &galois_key_stream,
                                     istream &relin_key_stream, istream &secret_key_stream) {
        deserialize_common(params_stream);

        timepoint start = chrono::steady_clock::now();
        sk.load(context, secret_key_stream);
        galois_keys.load(context, galois_key_stream);
        relin_keys.load(context, relin_key_stream);
        print_elapsed_time(start, "Reading keys...");
        seal_decryptor = new Decryptor(context, sk);
    }

    void HomomorphicEval::save(ostream &params_stream, ostream &galois_key_stream, ostream &relin_key_stream,
                               ostream *secret_key_stream) {
        if (secret_key_stream != nullptr) {
            sk.save(*secret_key_stream);
        }

        protobuf::CKKSParams ckks_params;
        auto context_data = context->key_context_data();
        ckks_params.set_numslots(context_data->parms().poly_modulus_degree() / 2);
        ckks_params.set_logscale(log_scale_);
        ckks_params.set_standardparams(standard_params_);

        ostringstream sealpkBuf;
        pk.save(sealpkBuf);
        ckks_params.set_pubkey(sealpkBuf.str());

        for (const auto &prime : context_data->parms().coeff_modulus()) {
            ckks_params.add_modulusvec(prime.value());
        }
        ckks_params.SerializeToOstream(&params_stream);

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
            LOG_AND_THROW_STREAM("You can only encrypt vectors which have exactly as many "
                       << " coefficients as the number of plaintext slots: Expected "
                       << num_slots_ << " coefficients, but " << coeffs.size()
                       << " were provided");
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

    vector<double> HomomorphicEval::decrypt(const CKKSCiphertext &encrypted, bool suppress_warnings) const {
        if (seal_decryptor == nullptr) {
            LOG_AND_THROW_STREAM("Decryption is only possible from a deserialized instance when the secret key is provided.");
        }

        Plaintext temp;

        if (!suppress_warnings) {
            decryption_warning(encrypted.he_level());
        }

        seal_decryptor->decrypt(encrypted.seal_ct, temp);

        vector<double> decoded_output;
        encoder->decode(temp, decoded_output);

        return decoded_output;
    }

    int HomomorphicEval::num_slots() const {
        return encoder->slot_count();
    }

    uint64_t HomomorphicEval::get_last_prime_internal(const CKKSCiphertext &ct) const {
        return get_last_prime(context, ct.he_level());
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
        seal_evaluator->add_inplace(ct1.seal_ct, ct2.seal_ct);
    }

    void HomomorphicEval::add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        Plaintext encoded_plain;
        encoder->encode(scalar, ct.seal_ct.parms_id(), ct.seal_ct.scale(), encoded_plain);
        seal_evaluator->add_plain_inplace(ct.seal_ct, encoded_plain);
    }

    void HomomorphicEval::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        Plaintext temp;
        encoder->encode(plain, ct.seal_ct.parms_id(), ct.seal_ct.scale(), temp);
        seal_evaluator->add_plain_inplace(ct.seal_ct, temp);
    }

    void HomomorphicEval::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        seal_evaluator->sub_inplace(ct1.seal_ct, ct2.seal_ct);
    }

    void HomomorphicEval::sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        Plaintext encoded_plain;
        encoder->encode(scalar, ct.seal_ct.parms_id(), ct.seal_ct.scale(), encoded_plain);
        seal_evaluator->sub_plain_inplace(ct.seal_ct, encoded_plain);
    }

    void HomomorphicEval::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        Plaintext temp;
        encoder->encode(plain, ct.seal_ct.parms_id(), ct.seal_ct.scale(), temp);
        seal_evaluator->sub_plain_inplace(ct.seal_ct, temp);
    }

    void HomomorphicEval::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        seal_evaluator->multiply_inplace(ct1.seal_ct, ct2.seal_ct);
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
    }

    void HomomorphicEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        Plaintext temp;
        encoder->encode(plain, ct.seal_ct.parms_id(), ct.seal_ct.scale(), temp);
        seal_evaluator->multiply_plain_inplace(ct.seal_ct, temp);
    }

    void HomomorphicEval::square_inplace_internal(CKKSCiphertext &ct) {
        seal_evaluator->square_inplace(ct.seal_ct);
    }

    void HomomorphicEval::reduce_level_to_inplace_internal(CKKSCiphertext &ct, int level) {
        while (ct.he_level() > level) {
            multiply_plain_inplace(ct, 1);
            rescale_to_next_inplace(ct);
        }
    }

    void HomomorphicEval::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        seal_evaluator->rescale_to_next_inplace(ct.seal_ct);
    }

    void HomomorphicEval::relinearize_inplace_internal(CKKSCiphertext &ct) {
        seal_evaluator->relinearize_inplace(ct.seal_ct, relin_keys);
    }
}  // namespace hit
