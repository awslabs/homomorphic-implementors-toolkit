// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* This is an alternate interface for SEAL's Evaluator interface. It only includes a subset of
 * SEAL's Evaluator API, and those functions now have a simpler interface.
 */

#include "homomorphic.h"

#include <glog/logging.h>

#include <iomanip>
#include <thread>

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

    HomomorphicEval::HomomorphicEval(int num_slots, int multiplicative_depth, int log_scale, bool use_standard_params,
                                     const vector<int> &galois_steps) {
        timepoint start = chrono::steady_clock::now();
        standard_params_ = use_standard_params;
        context = make_shared<HEContext>(num_slots, multiplicative_depth, log_scale);
        log_elapsed_time(start, "Creating encryption context...");

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
        KeyGenerator keyGenerator = newKeyGenerator(context->params);
        KeyPairHandle kp = genKeyPair(keyGenerator);
        sk = kp.sk;
        pk = kp.pk;
        galois_keys = genRotationKeysPow2(keyGenerator, sk);
        relin_keys = genRelinKey(keyGenerator, sk);

        log_elapsed_time(start, "Generating keys...");

        backend_decryptor = newDecryptor(context->params, sk);
    }

    void HomomorphicEval::deserialize_common(istream &params_stream) {
        protobuf::CKKSParams ckks_params;
        ckks_params.ParseFromIstream(&params_stream);

        istringstream ctx_stream(ckks_params.ctx());
        Parameters params = unmarshalBinaryParameters(ctx_stream);
        context = make_shared<HEContext>(params);

        istringstream pk_stream(ckks_params.pubkey());
        pk = unmarshalBinaryPublicKey(pk_stream);

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
        backend_decryptor = newDecryptor(context->params, sk);
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
            scale = (scale * scale) / static_cast<double>(context->get_qi(i));
        }

        CKKSCiphertext destination;
        destination.he_level_ = level;
        destination.scale_ = scale;

        Plaintext temp = encodeNTTAtLvlNew(context->params, get_encoder(), coeffs, level, scale);
        destination.backend_ct = encryptNew(get_encryptor(), temp);

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
        return decode(get_encoder(), temp, log2(num_slots()));
    }

    int HomomorphicEval::num_slots() const {
        return context->num_slots();
    }

    uint64_t HomomorphicEval::get_last_prime_internal(const CKKSCiphertext &ct) const {
        return context->get_qi(ct.he_level());
    }

    /* Lattigo classes are not thread-safe, but HIT should expose a thread-safe API. We solve
     * this problem by using boost::thread_specific_ptr on stateful Lattigo types. This means
     * that all accesses to the Lattigo objects must be guarded: we first have to ensure that
     * the object has been allocated for this thread, and allocate it if not.
     *
     * However, there is an additional subtlety. C++ creates threads, e.g., when using a parallel
     * `for_each` loop. However, it need not kill those threads at the end of the loop. In practice,
     * it seems that C++ tends to keep those idle threads around to reduce the overhead of the next
     * `for_each` invocation. This can cause a problem for us. Consider the unit tests: two tests
     * may use different parameters P1 and P2 (possibly with different ring dimensions). If thread 1
     * creates an Evaluator for P1, but C++ reuses this thread (without killing it) on a test that uses
     * P2, then our code would use an evaluator for the wrong parameter set. To avoid this, we actually
     * store a struct inside the thread_specific_ptr that maintains the type we actually care about
     * along with a copy of (not a reference to!) the parameters it was created with. This way, if
     * an evaluator is already allocated, we can check that it was allocated _with the correct parameters_.
     * If it was allocated with different parameters, we throw away the old evaluator and create a new one.
     */
    Evaluator &HomomorphicEval::get_evaluator() {
        if (backend_evaluator.get() == nullptr || !(backend_evaluator->params == context->params)) {
            ParameterizedLattigoType<Evaluator> *tmp =
                new ParameterizedLattigoType<Evaluator>(newEvaluator(context->params), context->params);
            backend_evaluator.reset(tmp);
        }
        return backend_evaluator->object;
    }

    Encoder &HomomorphicEval::get_encoder() {
        if (backend_encoder.get() == nullptr || !(backend_encoder->params == context->params)) {
            ParameterizedLattigoType<Encoder> *tmp =
                new ParameterizedLattigoType<Encoder>(newEncoder(context->params), context->params);
            backend_encoder.reset(tmp);
        }
        return backend_encoder->object;
    }

    Encryptor &HomomorphicEval::get_encryptor() {
        if (backend_encryptor.get() == nullptr || backend_encryptor->params != context->params) {
            ParameterizedLattigoType<Encryptor> *tmp =
                new ParameterizedLattigoType<Encryptor>(newEncryptorFromPk(context->params, pk), context->params);
            backend_encryptor.reset(tmp);
        }
        return backend_encryptor->object;
    }

    void HomomorphicEval::rotate_right_inplace_internal(CKKSCiphertext &ct, int steps) {
        rotate(get_evaluator(), ct.backend_ct, -steps, galois_keys, ct.backend_ct);
    }

    void HomomorphicEval::rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) {
        rotate(get_evaluator(), ct.backend_ct, steps, galois_keys, ct.backend_ct);
    }

    void HomomorphicEval::negate_inplace_internal(CKKSCiphertext &ct) {
        neg(get_evaluator(), ct.backend_ct, ct.backend_ct);
    }

    void HomomorphicEval::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        ::add(get_evaluator(), ct1.backend_ct, ct2.backend_ct, ct1.backend_ct);
    }

    void HomomorphicEval::add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        addConst(get_evaluator(), ct.backend_ct, scalar, ct.backend_ct);
    }

    void HomomorphicEval::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        Plaintext temp = encodeNTTAtLvlNew(context->params, get_encoder(), plain, ct.he_level(), ct.scale());
        addPlain(get_evaluator(), ct.backend_ct, temp, ct.backend_ct);
    }

    void HomomorphicEval::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        ::sub(get_evaluator(), ct1.backend_ct, ct2.backend_ct, ct1.backend_ct);
    }

    void HomomorphicEval::sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        add_plain_inplace_internal(ct, -scalar);
    }

    void HomomorphicEval::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        Plaintext temp = encodeNTTAtLvlNew(context->params, get_encoder(), plain, ct.he_level(), ct.scale());
        subPlain(get_evaluator(), ct.backend_ct, temp, ct.backend_ct);
    }

    void HomomorphicEval::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        mul(get_evaluator(), ct1.backend_ct, ct2.backend_ct, ct1.backend_ct);
    }

    void HomomorphicEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        // multByConst(get_evaluator(), ct.backend_ct, scalar, ct.backend_ct);
        vector<double> temp(num_slots());
        temp.assign(num_slots(), scalar);
        multiply_plain_inplace_internal(ct, temp);
    }

    void HomomorphicEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        Plaintext temp = encodeNTTAtLvlNew(context->params, get_encoder(), plain, ct.he_level(), ct.scale());
        mulPlain(get_evaluator(), ct.backend_ct, temp, ct.backend_ct);
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
        rescaleMany(get_evaluator(), ct.backend_ct, 1, ct.backend_ct);
    }

    void HomomorphicEval::relinearize_inplace_internal(CKKSCiphertext &ct) {
        relinearize(get_evaluator(), ct.backend_ct, relin_keys, ct.backend_ct);
    }
}  // namespace hit
