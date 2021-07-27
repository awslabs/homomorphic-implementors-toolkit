// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* This is an alternate interface for SEAL's Evaluator interface. It only includes a subset of
 * SEAL's Evaluator API, and those functions now have a simpler interface.
 */

#include "homomorphic.h"

#include <glog/logging.h>

#include <iomanip>
#include <thread>
#include <variant>

#include "../params.h"
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

    HomomorphicEval::HomomorphicEval(const CKKSParams &params, const vector<int> &galois_steps) {
        timepoint start = chrono::steady_clock::now();
        int max_ct_level = params.max_ct_level();
        context = make_shared<HEContext>(params);
        log_elapsed_time(start, "Creating encryption context...");

        // With the current Lattigo API, it's easiest to just generate all 2-power rotation
        // keys, up to num_slots/2.
        int num_galois_keys = galois_steps.size();
        VLOG(VLOG_VERBOSE) << "Generating keys for " << params.num_slots() << " slots and depth " << max_ct_level
                           << ", including " << num_galois_keys << " explicit Galois keys.";

        double keys_size_bytes = estimate_key_size(num_galois_keys, params.num_slots(), max_ct_level);
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
        KeyGenerator keyGenerator = newKeyGenerator(context->params);
        KeyPairHandle kp;
        if (params.btp_params.has_value()) {
            kp = genKeyPairSparse(keyGenerator, secretHammingWeight(params.btp_params.value().lattigo_btp_params));
        } else {
            kp = genKeyPair(keyGenerator);
        }
        sk = kp.sk;
        pk = kp.pk;
        galois_keys = genRotationKeysForRotations(keyGenerator, sk, galois_steps);
        relin_keys = genRelinKey(keyGenerator, sk);

        log_elapsed_time(start, "Generating keys...");

        backend_decryptor = newDecryptor(context->params, sk);

        if (params.btp_params.has_value()) {
            btp_depth = params.btp_params.value().bootstrapping_depth();
            if (btp_depth > max_ct_level) {
                LOG_AND_THROW_STREAM("Bootstrapping depth is larger than the maximum ciphertext level");
            }
            VLOG(VLOG_VERBOSE) << "Generating bootstrapping keys";
            btp_keys = genBootstrappingKey(keyGenerator, params.lattigo_params,
                                           params.btp_params.value().lattigo_btp_params, sk, relin_keys, galois_keys);
        }
    }

    HomomorphicEval::HomomorphicEval(int num_slots, int max_ct_level, int log_scale, const vector<int> &galois_steps)
        : HomomorphicEval(CKKSParams(num_slots, log_scale, max_ct_level), galois_steps) {
    }

    void HomomorphicEval::deserialize_common(istream &params_stream) {
        protobuf::CKKSParams ckks_params;
        ckks_params.ParseFromIstream(&params_stream);

        istringstream ctx_stream(ckks_params.ctx());
        Parameters params = unmarshalBinaryParameters(ctx_stream);

        if (ckks_params.has_btp_params()) {
            // make a context with support for bootstrapping
            istringstream btp_params_stream(ckks_params.btp_params());
            BootstrappingParameters btp_params = unmarshalBinaryBootstrapParameters(btp_params_stream);
            context = make_shared<HEContext>(CKKSParams(params, btp_params));
        } else {
            // make a context without support for bootstrapping
            context = make_shared<HEContext>(CKKSParams(params));
        }

        istringstream pk_stream(ckks_params.pubkey());
        pk = unmarshalBinaryPublicKey(pk_stream);
    }

    /* An evaluation instance */
    HomomorphicEval::HomomorphicEval(istream &params_stream, istream &galois_key_stream, istream &relin_key_stream) {
        deserialize_common(params_stream);

        timepoint start = chrono::steady_clock::now();
        galois_keys = unmarshalBinaryRotationKeys(galois_key_stream);
        relin_keys = unmarshalBinaryRelinearizationKey(relin_key_stream);
        log_elapsed_time(start, "Reading keys...");
    }

    /* A full instance */
    HomomorphicEval::HomomorphicEval(istream &params_stream, istream &galois_key_stream, istream &relin_key_stream,
                                     istream &secret_key_stream) {
        deserialize_common(params_stream);

        timepoint start = chrono::steady_clock::now();
        sk = unmarshalBinarySecretKey(secret_key_stream);
        galois_keys = unmarshalBinaryRotationKeys(galois_key_stream);
        relin_keys = unmarshalBinaryRelinearizationKey(relin_key_stream);
        log_elapsed_time(start, "Reading keys...");
        backend_decryptor = newDecryptor(context->params, sk);
    }

    void HomomorphicEval::save(ostream &params_stream, ostream &galois_key_stream, ostream &relin_key_stream,
                               ostream *secret_key_stream) {
        if (secret_key_stream != nullptr) {
            marshalBinarySecretKey(sk, *secret_key_stream);
        }

        protobuf::CKKSParams ckks_params;
        ostringstream ctx_stream;

        marshalBinaryParameters(context->params, ctx_stream);
        ckks_params.set_ctx(ctx_stream.str());

        if (context->btp_params.has_value()) {
            ostringstream btp_params_stream;
            marshalBinaryBootstrapParameters(context->btp_params.value(), btp_params_stream);
            ckks_params.set_btp_params(btp_params_stream.str());
        }

        ostringstream pk_stream;
        marshalBinaryPublicKey(pk, pk_stream);
        ckks_params.set_pubkey(pk_stream.str());
        ckks_params.SerializeToOstream(&params_stream);

        marshalBinaryRotationKeys(galois_keys, galois_key_stream);
        marshalBinaryRelinearizationKey(relin_keys, relin_key_stream);
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
            scale = (scale * scale) / static_cast<double>(context->get_qi(i));
        }

        CKKSCiphertext destination;
        destination.he_level_ = level;
        destination.scale_ = scale;

        Plaintext temp = encodeNTTAtLvlNew(context->params, get_encoder().ref(), coeffs, level, scale);
        destination.backend_ct = encryptNew(get_encryptor().ref(), temp);

        destination.num_slots_ = num_slots_;
        destination.initialized = true;

        return destination;
    }

    vector<double> HomomorphicEval::decrypt(const CKKSCiphertext &encrypted) {
        return decrypt(encrypted, false);
    }

    vector<double> HomomorphicEval::decrypt(const CKKSCiphertext &encrypted, bool suppress_warnings) {
        if (backend_decryptor.getRawHandle() == 0) {
            LOG_AND_THROW_STREAM(
                "Decryption is only possible from a deserialized instance when the secret key is provided.");
        }

        if (!suppress_warnings) {
            decryption_warning(encrypted.he_level());
        }

        Plaintext temp = decryptNew(backend_decryptor, encrypted.backend_ct);
        return decode(get_encoder().ref(), temp, log2(num_slots()));
    }

    int HomomorphicEval::num_slots() const {
        return context->num_slots();
    }

    uint64_t HomomorphicEval::get_last_prime_internal(const CKKSCiphertext &ct) const {
        return context->get_qi(ct.he_level());
    }

    /* Lattigo classes are not thread-safe, but HIT should expose a thread-safe API.
     * We solve this by maintaining a pool of Lattigo objects and checking them out when needed
     * and then returning them when done. This way each instance cannot be used by more than one
     * thread at a time.
     *
     * We cannot use boost::thread_specific_ptr as that requires us to either kill all child threads
     * when done (which we cannot do because we do not control them) or to explicitly NULL the values
     * in all of the boost::thread_specific_ptr objects when we're done with them
     * (but the parallel_for logic doesn't give us hooks to do so).
     */
    HomomorphicEval::PoolObject<Evaluator> HomomorphicEval::get_evaluator() {
        std::optional<Evaluator> opt = backend_evaluator.poll();
        Evaluator result = opt.has_value() ? std::move(*opt)
                                           : newEvaluator(context->params, makeEvaluationKey(relin_keys, galois_keys));
        return PoolObject<Evaluator>(std::move(result), backend_evaluator);
    }

    HomomorphicEval::PoolObject<Encoder> HomomorphicEval::get_encoder() {
        std::optional<Encoder> opt = backend_encoder.poll();
        Encoder result = opt.has_value() ? std::move(*opt) : newEncoder(context->params);
        return PoolObject<Encoder>(std::move(result), backend_encoder);
    }

    HomomorphicEval::PoolObject<Encryptor> HomomorphicEval::get_encryptor() {
        std::optional<Encryptor> opt = backend_encryptor.poll();
        Encryptor result = opt.has_value() ? std::move(*opt) : newEncryptorFromPk(context->params, pk);
        return PoolObject<Encryptor>(std::move(result), backend_encryptor);
    }

    HomomorphicEval::PoolObject<Bootstrapper> HomomorphicEval::get_bootstrapper() {
        if (!(context->btp_params.has_value())) {
            LOG_AND_THROW_STREAM("CKKS parameters do not specify bootstrapping parameters.");
        }
        std::optional<Bootstrapper> opt = backend_bootstrapper.poll();
        Bootstrapper result =
            opt.has_value() ? std::move(*opt) : newBootstrapper(context->params, context->btp_params.value(), btp_keys);
        return PoolObject<Bootstrapper>(std::move(result), backend_bootstrapper);
    }

    void HomomorphicEval::rotate_right_inplace_internal(CKKSCiphertext &ct, int steps) {
        rotate(get_evaluator().ref(), ct.backend_ct, -steps, ct.backend_ct);
    }

    void HomomorphicEval::rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) {
        rotate(get_evaluator().ref(), ct.backend_ct, steps, ct.backend_ct);
    }

    void HomomorphicEval::negate_inplace_internal(CKKSCiphertext &ct) {
        neg(get_evaluator().ref(), ct.backend_ct, ct.backend_ct);
    }

    void HomomorphicEval::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        ::add(get_evaluator().ref(), ct1.backend_ct, ct2.backend_ct, ct1.backend_ct);
    }

    void HomomorphicEval::add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        addConst(get_evaluator().ref(), ct.backend_ct, scalar, ct.backend_ct);
    }

    void HomomorphicEval::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        Plaintext temp = encodeNTTAtLvlNew(context->params, get_encoder().ref(), plain, ct.he_level(), ct.scale());
        addPlain(get_evaluator().ref(), ct.backend_ct, temp, ct.backend_ct);
    }

    void HomomorphicEval::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        ::sub(get_evaluator().ref(), ct1.backend_ct, ct2.backend_ct, ct1.backend_ct);
    }

    void HomomorphicEval::sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        add_plain_inplace_internal(ct, -scalar);
    }

    void HomomorphicEval::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        Plaintext temp = encodeNTTAtLvlNew(context->params, get_encoder().ref(), plain, ct.he_level(), ct.scale());
        subPlain(get_evaluator().ref(), ct.backend_ct, temp, ct.backend_ct);
    }

    void HomomorphicEval::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        mul(get_evaluator().ref(), ct1.backend_ct, ct2.backend_ct, ct1.backend_ct);
    }

    void HomomorphicEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        // multByConst(get_evaluator(), ct.backend_ct, scalar, ct.backend_ct);
        vector<double> temp(num_slots());
        temp.assign(num_slots(), scalar);
        multiply_plain_inplace_internal(ct, temp);
    }

    void HomomorphicEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        Plaintext temp = encodeNTTAtLvlNew(context->params, get_encoder().ref(), plain, ct.he_level(), ct.scale());
        mulPlain(get_evaluator().ref(), ct.backend_ct, temp, ct.backend_ct);
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
        rescaleMany(get_evaluator().ref(), context->params, ct.backend_ct, 1, ct.backend_ct);
    }

    void HomomorphicEval::relinearize_inplace_internal(CKKSCiphertext &ct) {
        relinearize(get_evaluator().ref(), ct.backend_ct, ct.backend_ct);
    }

    CKKSCiphertext HomomorphicEval::bootstrap_internal(const CKKSCiphertext &ct, bool rescale_for_bootstrapping) {
        // if rescale_for_bootstrapping is set, the circuit designer expects that one level will be consumed
        // _prior_ to bootstrapping in order to rescale the ciphertext for bootstrapping (which has specific
        // requirements on the scale). Note that this rescale is implicit: it's part of Lattigo's `bootstrap`
        // API, but it technically happens _prior_ to bootstrapping. This implicit rescale requires that the
        // level of the input ciphertext is > 0, otherwise we can't rescale.
        if (rescale_for_bootstrapping && ct.he_level() == 0) {
            LOG_AND_THROW_STREAM("Unable to bootstrap ciphertext at level 0 when rescale_for_bootstrapping is true.");
        }

        CKKSCiphertext bootstrapped_ct = ct;

        // Note that we don't actually *use* `rescale_for_bootstrapping`: it is a "HIT-ism" which
        // is required by other evaluators (notably the DepthFinder evaluators, since this parameter
        // affects circuit depth). However, we don't pass it to the Lattigo bootstrap API because
        // Lattigo implicitly does the rescale if it's able to. For more information, see the
        // API comment in evaluator.h.
        bootstrapped_ct.backend_ct = latticpp::bootstrap(get_bootstrapper().ref(), ct.backend_ct);
        bootstrapped_ct.scale_ = pow(2, context->log_scale());
        bootstrapped_ct.he_level_ = context->max_ciphertext_level() - btp_depth;
        return bootstrapped_ct;
    }
}  // namespace hit
