// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../ciphertext.h"
#include "../decryptor.h"
#include "../evaluator.h"
#include "homomorphic.h"
#include "scaleestimator.h"
#include "seal/seal.h"

/* This is the full debug evaluator. It combines all of the
 * other evaluators, thereby tracking all information
 * from DepthFinder, PlaintextEval, and ScaleEstimator,
 * as well as performing the ciphertext operations.
 */

class DebugEval : public CKKSEvaluator {
   public:
    DebugEval(const std::shared_ptr<seal::SEALContext> &context, seal::CKKSEncoder &encoder, seal::Encryptor &encryptor,
              const seal::GaloisKeys &galois_keys, const seal::RelinKeys &relin_keys, double scale,
              CKKSDecryptor &decryptor, bool verbose);

    /* For documentation on the API, see ../evaluator.h */
    ~DebugEval() override;

    DebugEval(const DebugEval &) = delete;
    DebugEval &operator=(const DebugEval &) = delete;
    DebugEval(DebugEval &&) = delete;
    DebugEval &operator=(DebugEval &&) = delete;

    // primarily used to indicate the maximum value for each *input* to the function.
    // For functions which are a no-op, this function is the only way the evaluator
    // can learn the maximum plaintext values, and thereby appropriately restrict the scale.
    void updatePlaintextMaxVal(double x);

    // return the base-2 log of the maximum plaintext value in the computation
    // this is useful for putting an upper bound on the scale parameter
    double getExactMaxLogPlainVal() const;

    // return the base-2 log of the maximum scale that can be used for this
    // computation. Using a scale larger than this will result in the plaintext
    // exceeding SEAL's maximum size, and using a scale smaller than this value
    // will unnecessarily reduce precision of the computation.
    double getEstimatedMaxLogScale() const;

   protected:
    CKKSCiphertext rotate_vector_right_internal(const CKKSCiphertext &ct, int steps) override;

    CKKSCiphertext rotate_vector_left_internal(const CKKSCiphertext &ct, int steps) override;

    CKKSCiphertext add_plain_scalar_internal(const CKKSCiphertext &ct, double scalar) override;

    CKKSCiphertext add_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) override;

    CKKSCiphertext multiply_plain_scalar_internal(const CKKSCiphertext &ct, double scalar) override;

    CKKSCiphertext multiply_plain_mat_internal(const CKKSCiphertext &ct, const std::vector<double> &plain) override;

    CKKSCiphertext multiply_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) override;

    CKKSCiphertext square_internal(const CKKSCiphertext &ct) override;

    void modDownTo_internal(CKKSCiphertext &ct, const CKKSCiphertext &target) override;

    void modDownToMin_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) override;

    CKKSCiphertext modDownToLevel_internal(const CKKSCiphertext &ct, int level) override;

    void rescale_to_next_inplace_internal(CKKSCiphertext &ct) override;

    void relinearize_inplace_internal(CKKSCiphertext &ct) override;

    // reuse this evaluator for another computation
    void reset_internal() override;

   private:
    HomomorphicEval *heEval;
    ScaleEstimator *seEval;

    void print_stats(const CKKSCiphertext &ct) const;

    CKKSDecryptor &decryptor;
    void checkScale(const CKKSCiphertext &ct) const;
    double initScale;

    CKKSCiphertext merge_cts(const CKKSCiphertext &ct_he, const CKKSCiphertext &ct_se) const;
};
