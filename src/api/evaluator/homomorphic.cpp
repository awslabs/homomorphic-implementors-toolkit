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

    CKKSCiphertext HomomorphicEval::rotate_vector_right_internal(const CKKSCiphertext &ct, int steps) {
        CKKSCiphertext dest = ct;
        evaluator.rotate_vector(ct.seal_ct, -steps, galois_keys, dest.seal_ct);
        return dest;
    }

    CKKSCiphertext HomomorphicEval::rotate_vector_left_internal(const CKKSCiphertext &ct, int steps) {
        CKKSCiphertext dest = ct;
        evaluator.rotate_vector(ct.seal_ct, steps, galois_keys, dest.seal_ct);
        return dest;
    }

    CKKSCiphertext HomomorphicEval::add_plain_scalar_internal(const CKKSCiphertext &ct, double scalar) {
        CKKSCiphertext dest = ct;
        Plaintext encoded_plain;
        encoder.encode(scalar, ct.seal_ct.parms_id(), ct.seal_ct.scale(), encoded_plain);
        evaluator.add_plain(ct.seal_ct, encoded_plain, dest.seal_ct);
        return dest;
    }

    CKKSCiphertext HomomorphicEval::add_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // check that ciphertexts are at the same level to avoid an obscure SEAL error
        if (ct1.getLevel(context) != ct2.getLevel(context)) {
            stringstream buffer;
            buffer << "PPLR: Error in HomomorphicEval::add: input levels do not match: " << ct1.getLevel(context)
                   << " != " << ct2.getLevel(context);
            throw invalid_argument(buffer.str());
        }
        CKKSCiphertext dest = ct1;
        evaluator.add_inplace(dest.seal_ct, ct2.seal_ct);
        return dest;
    }

    /* WARNING: Multiplying by 0 results in non-constant time behavior! Only multiply by 0 if the scalar is truly
     * public. */
    CKKSCiphertext HomomorphicEval::multiply_plain_scalar_internal(const CKKSCiphertext &ct, double scalar) {
        CKKSCiphertext dest = ct;
        if (scalar != 0.0) {
            Plaintext encoded_plain;
            encoder.encode(scalar, ct.seal_ct.parms_id(), ct.seal_ct.scale(), encoded_plain);
            evaluator.multiply_plain(ct.seal_ct, encoded_plain, dest.seal_ct);
        } else {
            encryptor.encrypt_zero(ct.seal_ct.parms_id(), dest.seal_ct);
            // seal sets the scale to be 1, but our the debug evaluator always ensures that the SEAL scale is consistent
            // with our mirror calculation
            dest.seal_ct.scale() = ct.seal_ct.scale() * ct.seal_ct.scale();
        }
        return dest;
    }

    CKKSCiphertext HomomorphicEval::multiply_plain_mat_internal(const CKKSCiphertext &ct, const vector<double> &plain) {
        if (plain.size() != ct.width * ct.height) {
            throw invalid_argument(
                "PPLR: Error in HomomorphicEval::multiply_plain: plaintext size does not match ciphertext size");
        }
        CKKSCiphertext dest = ct;
        Plaintext temp;
        encoder.encode(plain, ct.seal_ct.parms_id(), ct.seal_ct.scale(), temp);
        evaluator.multiply_plain_inplace(dest.seal_ct, temp);
        return dest;
    }

    CKKSCiphertext HomomorphicEval::multiply_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // check that ciphertexts are at the same level to avoid an obscure SEAL error
        if (ct1.getLevel(context) != ct2.getLevel(context)) {
            stringstream buffer;
            buffer << "PPLR: Error in HomomorphicEval::multiply: input levels do not match: " << ct1.getLevel(context)
                   << " != " << ct2.getLevel(context);
            throw invalid_argument(buffer.str());
        }
        CKKSCiphertext dest = ct1;
        evaluator.multiply_inplace(dest.seal_ct, ct2.seal_ct);
        return dest;
    }

    CKKSCiphertext HomomorphicEval::square_internal(const CKKSCiphertext &ct) {
        CKKSCiphertext dest = ct;
        evaluator.square(ct.seal_ct, dest.seal_ct);
        return dest;
    }

    void HomomorphicEval::modDownTo_internal(CKKSCiphertext &ct, const CKKSCiphertext &target) {
        if (ct.getLevel(context) < target.getLevel(context)) {
            stringstream buffer;
            buffer << "PPLR: Error in modDownTo: input is at a lower level than target. Input level: "
                   << ct.getLevel(context) << ", target level: " << target.getLevel(context);
            throw invalid_argument(buffer.str());
        }
        while (ct.getLevel(context) > target.getLevel(context)) {
            ct = multiply_plain_scalar(ct, 1);
            rescale_to_next_inplace(ct);
        }
    }

    void HomomorphicEval::modDownToMin_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) {
        if (ct1.getLevel(context) > ct2.getLevel(context)) {
            modDownTo_internal(ct1, ct2);
        } else {
            modDownTo_internal(ct2, ct1);
        }
    }

    CKKSCiphertext HomomorphicEval::modDownToLevel_internal(const CKKSCiphertext &ct, int level) {
        if (ct.getLevel(context) < level) {
            stringstream buffer;
            buffer << "PPLR: Error in modDownTo: input is at a lower level than target. Input level: "
                   << ct.getLevel(context) << ", target level: " << level;
            throw invalid_argument(buffer.str());
        }
        CKKSCiphertext y = ct;
        while (y.getLevel(context) > level) {
            y = multiply_plain_scalar(y, 1);
            rescale_to_next_inplace(y);
        }

        return y;
    }

    void HomomorphicEval::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        evaluator.rescale_to_next_inplace(ct.seal_ct);
    }

    void HomomorphicEval::relinearize_inplace_internal(CKKSCiphertext &ct) {
        evaluator.relinearize_inplace(ct.seal_ct, relin_keys);
    }
}  // namespace hit
