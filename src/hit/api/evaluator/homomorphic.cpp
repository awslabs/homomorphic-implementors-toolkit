// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* This is an alternate interface for SEAL's Evaluator interface. It only includes a subset of
 * SEAL's Evaluator API, and those functions now have a simpler interface.
 */

#include "homomorphic.h"

#include <glog/logging.h>

#include <future>

#include "../../sealutils.h"
#include "hit/protobuf/ckksparams.pb.h"

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

    HomomorphicEval::HomomorphicEval(int num_slots, int multiplicative_depth, int log_scale, bool use_standard_params,
                                     const vector<int> &galois_steps) {
        timepoint start = chrono::steady_clock::now();
        standard_params_ = use_standard_params;
        context = make_shared<HEContext>(num_slots, multiplicative_depth, log_scale, use_standard_params);
        log_elapsed_time(start, "Creating encryption context...");
        backend_evaluator = new Evaluator(*(context->params));
        backend_encoder = new CKKSEncoder(*(context->params));

        int num_galois_keys = galois_steps.size();
        VLOG(VLOG_VERBOSE) << "Generating keys for " << num_slots << " slots and depth " << multiplicative_depth
                           << ", including " << (num_galois_keys != 0 ? to_string(num_galois_keys) : "all")
                           << " Galois keys.";

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
        KeyGenerator keygen(*(context->params));
        sk = keygen.secret_key();
        keygen.create_public_key(pk);
        if (num_galois_keys > 0) {
            keygen.create_galois_keys(galois_steps, galois_keys);
        } else {
            // generate all galois keys
            keygen.create_galois_keys(galois_keys);
        }
        keygen.create_relin_keys(relin_keys);

        log_elapsed_time(start, "Generating keys...");

        backend_encryptor = new Encryptor(*(context->params), pk);
        backend_decryptor = new Decryptor(*(context->params), sk);
    }

    HomomorphicEval::~HomomorphicEval() {
        delete backend_encoder;
        delete backend_evaluator;
        delete backend_encryptor;
        delete backend_decryptor;
    }

    void HomomorphicEval::deserialize_common(istream &params_stream) {
        protobuf::CKKSParams ckks_params;
        ckks_params.ParseFromIstream(&params_stream);

        EncryptionParameters params = EncryptionParameters(scheme_type::none);
        istringstream ctxstream(ckks_params.ctx());
        params.load(ctxstream);

        int log_scale = ckks_params.logscale();

        standard_params_ = ckks_params.standardparams();
        timepoint start = chrono::steady_clock::now();
        context = make_shared<HEContext>(params, log_scale, standard_params_);
        log_elapsed_time(start, "Creating encryption context...");
        backend_evaluator = new Evaluator(*(context->params));
        backend_encoder = new CKKSEncoder(*(context->params));

        istringstream pkstream(ckks_params.pubkey());
        pk.load(*(context->params), pkstream);
        backend_encryptor = new Encryptor(*(context->params), pk);
    }

    /* An evaluation instance */
    HomomorphicEval::HomomorphicEval(istream &params_stream, istream &galois_key_stream, istream &relin_key_stream) {
        deserialize_common(params_stream);

        timepoint start = chrono::steady_clock::now();
        galois_keys.load(*(context->params), galois_key_stream);
        relin_keys.load(*(context->params), relin_key_stream);
        log_elapsed_time(start, "Reading keys...");
    }

    /* A full instance */
    HomomorphicEval::HomomorphicEval(istream &params_stream, istream &galois_key_stream, istream &relin_key_stream,
                                     istream &secret_key_stream) {
        deserialize_common(params_stream);

        timepoint start = chrono::steady_clock::now();
        sk.load(*(context->params), secret_key_stream);
        galois_keys.load(*(context->params), galois_key_stream);
        relin_keys.load(*(context->params), relin_key_stream);
        log_elapsed_time(start, "Reading keys...");
        backend_decryptor = new Decryptor(*(context->params), sk);
    }

    void HomomorphicEval::save(ostream &params_stream, ostream &galois_key_stream, ostream &relin_key_stream,
                               ostream *secret_key_stream) {
        if (secret_key_stream != nullptr) {
            sk.save(*secret_key_stream);
        }

        protobuf::CKKSParams ckks_params;
        ostringstream sealctxBuf;
        context->params->key_context_data()->parms().save(sealctxBuf);
        ckks_params.set_ctx(sealctxBuf.str());
        ckks_params.set_logscale(context->log_scale());

        ostringstream sealpkBuf;
        pk.save(sealpkBuf);
        ckks_params.set_pubkey(sealpkBuf.str());

        ckks_params.set_standardparams(standard_params_);
        ckks_params.SerializeToOstream(&params_stream);

        // There is a SEAL limitation that prevents saving large files with compression
        // This is reported at https://github.com/microsoft/SEAL/issues/142
        galois_keys.save(galois_key_stream, compr_mode_type::none);
        relin_keys.save(relin_key_stream);
    }

    CKKSCiphertext HomomorphicEval::encrypt(const vector<double> &coeffs) {
        return encrypt(coeffs, -1);
    }

    CKKSCiphertext HomomorphicEval::encrypt(const vector<double> &coeffs, int level) {
        int num_slots_ = backend_encoder->slot_count();
        if (coeffs.size() != num_slots_) {
            // bad things can happen if you don't plan for your input to be smaller than the ciphertext
            // This forces the caller to ensure that the input has the correct size or is at least appropriately padded
            LOG_AND_THROW_STREAM("You can only encrypt vectors which have exactly as many "
                                 << " coefficients as the number of plaintext slots: Expected " << num_slots_
                                 << " coefficients, but " << coeffs.size() << " were provided");
        }

        if (level == -1) {
            level = context->max_ciphertext_level();
        }

        auto context_data = context->first_context_data();
        double scale = pow(2, log_scale_);
        while (context_data->chain_index() > level) {
            // order of operations is very important: floating point arithmetic is not associative
            scale = (scale * scale) / static_cast<double>(context_data->parms().coeff_modulus().back().value());
            context_data = context_data->next_context_data();
        }

        CKKSCiphertext destination;
        destination.he_level_ = level;
        destination.scale_ = scale;

        Plaintext temp;
        backend_encoder->encode(coeffs, context_data->parms_id(), scale, temp);
        backend_encryptor->encrypt(temp, destination.backend_ct);

        destination.num_slots_ = num_slots_;
        destination.initialized = true;

        return destination;
    }

    vector<double> HomomorphicEval::decrypt(const CKKSCiphertext &encrypted) {
        return decrypt(encrypted, false);
    }

    vector<double> HomomorphicEval::decrypt(const CKKSCiphertext &encrypted, bool suppress_warnings) {
        if (backend_decryptor == nullptr) {
            LOG_AND_THROW_STREAM(
                "Decryption is only possible from a deserialized instance when the secret key is provided.");
        }

        Plaintext temp;

        if (!suppress_warnings) {
            decryption_warning(encrypted.he_level());
        }

        backend_decryptor->decrypt(encrypted.backend_ct, temp);

        vector<double> decoded_output;
        backend_encoder->decode(temp, decoded_output);

        return decoded_output;
    }

    int HomomorphicEval::num_slots() const {
        return context->num_slots();
    }

    uint64_t HomomorphicEval::get_last_prime_internal(const CKKSCiphertext &ct) const {
        return context->getQi(ct.he_level());
    }

    void HomomorphicEval::rotate_right_inplace_internal(CKKSCiphertext &ct, int steps) {
        backend_evaluator->rotate_vector_inplace(ct.backend_ct, -steps, galois_keys);
    }

    void HomomorphicEval::rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) {
        backend_evaluator->rotate_vector_inplace(ct.backend_ct, steps, galois_keys);
    }

    void HomomorphicEval::negate_inplace_internal(CKKSCiphertext &ct) {
        backend_evaluator->negate_inplace(ct.backend_ct);
    }

    void HomomorphicEval::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        backend_evaluator->add_inplace(ct1.backend_ct, ct2.backend_ct);
    }

    void HomomorphicEval::add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        Plaintext encoded_plain;
        backend_encoder->encode(scalar, ct.backend_ct.parms_id(), ct.backend_ct.scale(), encoded_plain);
        backend_evaluator->add_plain_inplace(ct.backend_ct, encoded_plain);
    }

    void HomomorphicEval::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        Plaintext temp;
        backend_encoder->encode(plain, ct.backend_ct.parms_id(), ct.backend_ct.scale(), temp);
        backend_evaluator->add_plain_inplace(ct.backend_ct, temp);
    }

    void HomomorphicEval::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        backend_evaluator->sub_inplace(ct1.backend_ct, ct2.backend_ct);
    }

    void HomomorphicEval::sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        Plaintext encoded_plain;
        backend_encoder->encode(scalar, ct.backend_ct.parms_id(), ct.backend_ct.scale(), encoded_plain);
        backend_evaluator->sub_plain_inplace(ct.backend_ct, encoded_plain);
    }

    void HomomorphicEval::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        Plaintext temp;
        backend_encoder->encode(plain, ct.backend_ct.parms_id(), ct.backend_ct.scale(), temp);
        backend_evaluator->sub_plain_inplace(ct.backend_ct, temp);
    }

    void HomomorphicEval::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        backend_evaluator->multiply_inplace(ct1.backend_ct, ct2.backend_ct);
    }

    /* WARNING: This function is not constant time in the scalar argument. */
    void HomomorphicEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        if (scalar != double{0}) {
            Plaintext encoded_plain;
            backend_encoder->encode(scalar, ct.backend_ct.parms_id(), ct.backend_ct.scale(), encoded_plain);
            backend_evaluator->multiply_plain_inplace(ct.backend_ct, encoded_plain);
        } else {
            double previous_scale = ct.backend_ct.scale();
            backend_encryptor->encrypt_zero(ct.backend_ct.parms_id(), ct.backend_ct);
            // seal sets the scale to be 1, but our the debug evaluator always ensures that the SEAL scale is consistent
            // with our mirror calculation
            ct.backend_ct.scale() = previous_scale * previous_scale;
        }
    }

    void HomomorphicEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        BackendPlaintext temp = context->encode(backend_encoder, plain, , ct.backend_ct.scale())
        backend_encoder->encode(plain, ct.backend_ct.parms_id(), ct.backend_ct.scale(), temp);
        backend_evaluator->multiply_plain_inplace(ct.backend_ct, temp);
    }

    void HomomorphicEval::square_inplace_internal(CKKSCiphertext &ct) {
        backend_evaluator->square_inplace(ct.backend_ct);
    }

    void HomomorphicEval::reduce_level_to_inplace_internal(CKKSCiphertext &ct, int level) {
        while (ct.he_level() > level) {
            multiply_plain_inplace(ct, 1);
            rescale_to_next_inplace(ct);
        }
    }

    void HomomorphicEval::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        backend_evaluator->rescale_to_next_inplace(ct.backend_ct);
    }

    void HomomorphicEval::relinearize_inplace_internal(CKKSCiphertext &ct) {
        backend_evaluator->relinearize_inplace(ct.backend_ct, relin_keys);
    }
}  // namespace hit
