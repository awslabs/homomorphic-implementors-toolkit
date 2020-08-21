// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* This is an alternate interface for SEAL's Evaluator interface. It only includes a subset of
 * SEAL's Evaluator API, and those functions now have a simpler interface.
 */

#include "homomorphic.h"

#include <future>

using namespace std;
using namespace seal;

namespace hit {

    HomomorphicEval::HomomorphicEval(const shared_ptr<SEALContext> &context, CKKSEncoder &encoder, Encryptor &encryptor,
                                     const GaloisKeys &galois_keys, const RelinKeys &relin_keys, bool verbose)
        : /* This evaluator never prints anything, so CKKSEvaluator can be non-verbose */
          CKKSEvaluator(context, verbose),
          evaluator(context),
          encoder(encoder),
          encryptor(encryptor),
          galois_keys(galois_keys),
          relin_keys(relin_keys) {
        evalPolicy = launch::async;
    }

    HomomorphicEval::~HomomorphicEval() = default;

    void HomomorphicEval::reset_internal() {
    }

    void HomomorphicEval::rotate_right_inplace_internal(CKKSCiphertext &ct, int steps) {
        CKKSCiphertext dest = ct;
        evaluator.rotate_vector_inplace(ct.seal_ct, -steps, galois_keys);
    }

    void HomomorphicEval::rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) {
        evaluator.rotate_vector_inplace(ct.seal_ct, steps, galois_keys);
    }

    void HomomorphicEval::negate_inplace_internal(CKKSCiphertext &ct) {
        evaluator.negate_inplace(ct.seal_ct);
    }

    void HomomorphicEval::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // check that ciphertexts are at the same level to avoid an obscure SEAL error
        if (ct1.getLevel(context) != ct2.getLevel(context)) {
            stringstream buffer;
            buffer << "Error in HomomorphicEval::add: input levels do not match: " << ct1.getLevel(context)
                   << " != " << ct2.getLevel(context);
            throw invalid_argument(buffer.str());
        }
        evaluator.add_inplace(ct1.seal_ct, ct2.seal_ct);
    }

    void HomomorphicEval::add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        Plaintext encoded_plain;
        encoder.encode(scalar, ct.seal_ct.parms_id(), ct.seal_ct.scale(), encoded_plain);
        evaluator.add_plain_inplace(ct.seal_ct, encoded_plain);
    }

    void HomomorphicEval::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        if (plain.size() != ct.width * ct.height) {
            throw invalid_argument(
                "Error in HomomorphicEval::add_plain_internal: plaintext size does not match ciphertext size");
        }
        Plaintext temp;
        encoder.encode(plain, ct.seal_ct.parms_id(), ct.seal_ct.scale(), temp);
        evaluator.add_plain_inplace(ct.seal_ct, temp);
    }

    void HomomorphicEval::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // check that ciphertexts are at the same level to avoid an obscure SEAL error
        if (ct1.getLevel(context) != ct2.getLevel(context)) {
            stringstream buffer;
            buffer << "Error in HomomorphicEval::sub: input levels do not match: " << ct1.getLevel(context)
                   << " != " << ct2.getLevel(context);
            throw invalid_argument(buffer.str());
        }
        evaluator.sub_inplace(ct1.seal_ct, ct2.seal_ct);
    }

    void HomomorphicEval::sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        Plaintext encoded_plain;
        encoder.encode(scalar, ct.seal_ct.parms_id(), ct.seal_ct.scale(), encoded_plain);
        evaluator.sub_plain_inplace(ct.seal_ct, encoded_plain);
    }

    void HomomorphicEval::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        if (plain.size() != ct.width * ct.height) {
            throw invalid_argument(
                "Error in HomomorphicEval::sub_plain_internal: plaintext size does not match ciphertext size");
        }
        Plaintext temp;
        encoder.encode(plain, ct.seal_ct.parms_id(), ct.seal_ct.scale(), temp);
        evaluator.sub_plain_inplace(ct.seal_ct, temp);
    }

    void HomomorphicEval::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // check that ciphertexts are at the same level to avoid an obscure SEAL error
        if (ct1.getLevel(context) != ct2.getLevel(context)) {
            stringstream buffer;
            buffer << "Error in HomomorphicEval::multiply: input levels do not match: " << ct1.getLevel(context)
                   << " != " << ct2.getLevel(context);
            throw invalid_argument(buffer.str());
        }
        evaluator.multiply_inplace(ct1.seal_ct, ct2.seal_ct);
    }

    /* WARNING: Multiplying by 0 results in non-constant time behavior! Only multiply by 0 if the scalar is truly
     * public. */
    void HomomorphicEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        if (scalar != double { 0 }) {
            Plaintext encoded_plain;
            encoder.encode(scalar, ct.seal_ct.parms_id(), ct.seal_ct.scale(), encoded_plain);
            evaluator.multiply_plain_inplace(ct.seal_ct, encoded_plain);
        } else {
            double previous_scale = ct.seal_ct.scale();
            encryptor.encrypt_zero(ct.seal_ct.parms_id(), ct.seal_ct);
            // seal sets the scale to be 1, but our the debug evaluator always ensures that the SEAL scale is consistent
            // with our mirror calculation
            ct.seal_ct.scale() = previous_scale * previous_scale;
        }
    }

    void HomomorphicEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        if (plain.size() != ct.width * ct.height) {
            throw invalid_argument(
                "Error in HomomorphicEval::multiply_plain_internal: plaintext size does not match ciphertext "
                "size");
        }
        Plaintext temp;
        encoder.encode(plain, ct.seal_ct.parms_id(), ct.seal_ct.scale(), temp);
        evaluator.multiply_plain_inplace(ct.seal_ct, temp);
    }

    void HomomorphicEval::square_inplace_internal(CKKSCiphertext &ct) {
        evaluator.square_inplace(ct.seal_ct);
    }

    void HomomorphicEval::mod_down_to_inplace_internal(CKKSCiphertext &ct, const CKKSCiphertext &target) {
        if (ct.getLevel(context) < target.getLevel(context)) {
            stringstream buffer;
            buffer << "Error in modDownTo: input is at a lower level than target. Input level: "
                   << ct.getLevel(context) << ", target level: " << target.getLevel(context);
            throw invalid_argument(buffer.str());
        }
        while (ct.getLevel(context) > target.getLevel(context)) {
            multiply_plain_inplace(ct, 1);
            rescale_to_next_inplace(ct);
        }
    }

    void HomomorphicEval::mod_down_to_min_inplace_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) {
        if (ct1.getLevel(context) > ct2.getLevel(context)) {
            mod_down_to_inplace_internal(ct1, ct2);
        } else {
            mod_down_to_inplace_internal(ct2, ct1);
        }
    }

    void HomomorphicEval::mod_down_to_level_inplace_internal(CKKSCiphertext &ct, int level) {
        if (ct.getLevel(context) < level) {
            stringstream buffer;
            buffer << "Error in modDownTo: input is at a lower level than target. Input level: "
                   << ct.getLevel(context) << ", target level: " << level;
            throw invalid_argument(buffer.str());
        }
        while (ct.getLevel(context) > level) {
            multiply_plain_inplace(ct, 1);
            rescale_to_next_inplace(ct);
        }
    }

    void HomomorphicEval::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        evaluator.rescale_to_next_inplace(ct.seal_ct);
    }

    void HomomorphicEval::relinearize_inplace_internal(CKKSCiphertext &ct) {
        evaluator.relinearize_inplace(ct.seal_ct, relin_keys);
    }
}  // namespace hit