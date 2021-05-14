// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* This is an alternate interface for SEAL's Evaluator interface. It only includes a subset of
 * SEAL's Evaluator API, and those functions now have a simpler interface.
 */

#include "homomorphic.h"

#include <glog/logging.h>
#include <iomanip>

#include "hit/protobuf/ckksparams.pb.h"

using namespace std;
using namespace latticpp;

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
        context = make_shared<HEContext>(HEContext(num_slots, multiplicative_depth, log_scale));
        standard_params_ = use_seal_params;
        seal_evaluator = newEvaluator(context->params);
        seal_encoder = newEncoder(context->params);

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

        timepoint start = chrono::steady_clock::now();
        // generate keys
        // This call generates a KeyGenerator with fresh randomness
        // The KeyGenerator object contains deterministic keys.
        KeyGenerator keyGenerator = newKeyGenerator(context->params);
        KeyPairHandle kp = genKeyPair(keyGenerator);
        sk = kp.sk;
        pk = kp.pk;
        // if (num_galois_keys > 0) {
        //     keygen.create_galois_keys(galois_steps, galois_keys);
        // } else {
        //     // generate all galois keys
        //     keygen.create_galois_keys(galois_keys);
        // }
        galois_keys = genRotationKeysPow2(keyGenerator, sk);
        relin_keys = genRelinKey(keyGenerator, sk);

        log_elapsed_time(start, "Generating keys...");

        seal_encryptor = newEncryptorFromPk(context->params, pk);
        seal_decryptor = newDecryptor(context->params, sk);
    }

    void HomomorphicEval::deserialize_common(istream &params_stream) {
        protobuf::CKKSParams ckks_params;
        ckks_params.ParseFromIstream(&params_stream);

        istringstream ctx_stream(ckks_params.ctx());
        Parameters params = unmarshalBinaryParameters(ctx_stream);
        context = make_shared<HEContext>(HEContext(params));

        seal_evaluator = newEvaluator(params);
        seal_encoder = newEncoder(params);

        istringstream pk_stream(ckks_params.pubkey());
        pk = unmarshalBinaryPublicKey(pk_stream);
        seal_encryptor = newEncryptorFromPk(params, pk);

        standard_params_ = ckks_params.standardparams();
    }

    /* An evaluation instance */
    HomomorphicEval::HomomorphicEval(istream &params_stream, istream &galois_key_stream, istream &relin_key_stream) {
        deserialize_common(params_stream);
        timepoint start = chrono::steady_clock::now();
        galois_keys = unmarshalBinaryRotationKeys(galois_key_stream);
        relin_keys = unmarshalBinaryEvaluationKey(relin_key_stream);
        log_elapsed_time(start, "Reading keys...");
    }

    /* A full instance */
    HomomorphicEval::HomomorphicEval(istream &params_stream, istream &galois_key_stream, istream &relin_key_stream,
                                     istream &secret_key_stream) {
        deserialize_common(params_stream);
        timepoint start = chrono::steady_clock::now();
        sk = unmarshalBinarySecretKey(secret_key_stream);
        galois_keys = unmarshalBinaryRotationKeys(galois_key_stream);
        relin_keys = unmarshalBinaryEvaluationKey(relin_key_stream);
        log_elapsed_time(start, "Reading keys...");
        seal_decryptor = newDecryptor(context->params, sk);
    }

    void HomomorphicEval::save(ostream &params_stream, ostream &galois_key_stream, ostream &relin_key_stream,
                               ostream *secret_key_stream) {
        if (secret_key_stream != nullptr) {
            (*secret_key_stream) << marshalBinarySecretKey(sk);
        }

        protobuf::CKKSParams ckks_params;
        ckks_params.set_standardparams(standard_params_);
        ckks_params.set_ctx(marshalBinaryParameters(context->params));
        ckks_params.set_pubkey(marshalBinaryPublicKey(pk));
        ckks_params.SerializeToOstream(&params_stream);

        galois_key_stream << marshalBinaryRotationKeys(galois_keys);
        relin_key_stream << marshalBinaryEvaluationKey(relin_keys);
    }

    CKKSCiphertext HomomorphicEval::encrypt(const vector<double> &coeffs) {
        return encrypt(coeffs, -1);
    }

    CKKSCiphertext HomomorphicEval::encrypt(const vector<double> &coeffs, int level) {
        int num_slots_ = num_slots();
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

        double scale = pow(2, context->log_scale());
        // order of operations is very important: floating point arithmetic is not associative
        for (int i = context->max_ciphertext_level(); i > level; i--) {
            scale = (scale * scale) / static_cast<double>(context->getQi(i));
        }

        CKKSCiphertext destination;
        destination.he_level_ = level;
        destination.scale_ = scale;

        Plaintext temp = encodeNTTAtLvlNew(context->params, seal_encoder, coeffs, level, scale);
        destination.backend_ct = encryptNew(seal_encryptor, temp);

        destination.num_slots_ = num_slots_;
        destination.initialized = true;

        return destination;
    }

    vector<double> HomomorphicEval::decrypt(const CKKSCiphertext &encrypted) const {
        return decrypt(encrypted, false);
    }

    vector<double> HomomorphicEval::decrypt(const CKKSCiphertext &encrypted, bool suppress_warnings) const {
        if (seal_decryptor.getRawHandle() == 0) {
            LOG_AND_THROW_STREAM(
                "Decryption is only possible from a deserialized instance when the secret key is provided.");
        }

        if (!suppress_warnings) {
            decryption_warning(encrypted.he_level());
        }

        Plaintext temp = decryptNew(seal_decryptor, encrypted.backend_ct);
        return decode(seal_encoder, temp, log2(num_slots()));
    }

    int HomomorphicEval::num_slots() const {
        return context->num_slots();
    }

    uint64_t HomomorphicEval::get_last_prime_internal(const CKKSCiphertext &ct) const {
        return context->getQi(ct.he_level());
    }

    void HomomorphicEval::rotate_right_inplace_internal(CKKSCiphertext &ct, int steps) {
        rotate(seal_evaluator, ct.backend_ct, -steps, galois_keys, ct.backend_ct);
    }

    void HomomorphicEval::rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) {
        rotate(seal_evaluator, ct.backend_ct, steps, galois_keys, ct.backend_ct);
    }

    void HomomorphicEval::negate_inplace_internal(CKKSCiphertext &ct) {
        neg(seal_evaluator, ct.backend_ct, ct.backend_ct);
    }

    void HomomorphicEval::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        ::add(seal_evaluator, ct1.backend_ct, ct2.backend_ct, ct1.backend_ct);
    }

    void HomomorphicEval::add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        addConst(seal_evaluator, ct.backend_ct, scalar, ct.backend_ct);
    }

    void HomomorphicEval::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        Plaintext temp = encodeNTTAtLvlNew(context->params, seal_encoder, plain, ct.he_level(), ct.scale());
        addPlain(seal_evaluator, ct.backend_ct, temp, ct.backend_ct);
    }

    void HomomorphicEval::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        ::sub(seal_evaluator, ct1.backend_ct, ct2.backend_ct, ct1.backend_ct);
    }

    void HomomorphicEval::sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        add_plain_inplace_internal(ct, -scalar);
    }

    void HomomorphicEval::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        Plaintext temp = encodeNTTAtLvlNew(context->params, seal_encoder, plain, ct.he_level(), ct.scale());
        subPlain(seal_evaluator, ct.backend_ct, temp, ct.backend_ct);
    }

    void HomomorphicEval::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        mul(seal_evaluator, ct1.backend_ct, ct2.backend_ct, ct1.backend_ct);
    }

    void HomomorphicEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        multByConst(seal_evaluator, ct.backend_ct, scalar, ct.backend_ct);
    }

    void HomomorphicEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        Plaintext temp = encodeNTTAtLvlNew(context->params, seal_encoder, plain, ct.he_level(), ct.scale());
        mulPlain(seal_evaluator, ct.backend_ct, temp, ct.backend_ct);
    }

    void HomomorphicEval::square_inplace_internal(CKKSCiphertext &ct) {
        multiply_inplace_internal(ct, ct);
    }

    void HomomorphicEval::reduce_level_to_inplace_internal(CKKSCiphertext &ct, int level) {
        while (ct.he_level() > level) {
            multiply_plain_inplace(ct, 1);
            rescale_to_next_inplace(ct);
        }
    }

    void HomomorphicEval::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        rescaleMany(seal_evaluator, ct.backend_ct, 1, ct.backend_ct);
        dropLevel(seal_evaluator, ct.backend_ct, 1);
    }

    void HomomorphicEval::relinearize_inplace_internal(CKKSCiphertext &ct) {
        relinearize(seal_evaluator, ct.backend_ct, relin_keys, ct.backend_ct);
    }
}  // namespace hit
