// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "seal/seal.h"
#include "seal/context.h"
#include "../ciphertext.h"
#include "plaintext.h"
#include "depthfinder.h"
#include "../evaluator.h"

/* This evaluator estimates the optimal CKKS scale to use for a computation.
 * Along the way, it tracks the scale of ciphertexts as well as their
 * theoretical maximum value.
 */
class ScaleEstimator: public CKKSEvaluator
{
public:
  ScaleEstimator(const std::shared_ptr<seal::SEALContext> &context, int poly_deg, double baseScale, bool verbose);

  /* For documentation on the API, see ../evaluator.h */
  ~ScaleEstimator() override;

  ScaleEstimator(const ScaleEstimator&) = delete;
  ScaleEstimator& operator=(const ScaleEstimator&) = delete;
  ScaleEstimator(ScaleEstimator&&) = delete;
  ScaleEstimator& operator=(ScaleEstimator&&) = delete;

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
  PlaintextEval *ptEval;
  DepthFinder *dfEval;

  void print_stats(const CKKSCiphertext &ct);
  void updateMaxLogScale(const CKKSCiphertext &ct);
  double estimatedMaxLogScale;
  const double baseScale;
  int poly_deg;

  friend class DebugEval;
};

CKKSCiphertext merge_cts(const CKKSCiphertext &ct_df, const CKKSCiphertext &ct_pt);
