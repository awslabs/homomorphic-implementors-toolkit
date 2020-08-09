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
  ScaleEstimator(const std::shared_ptr<seal::SEALContext> c, int poly_deg, double baseScale, bool verbose);

  /* For documentation on the API, see ../evaluator.h */
  ~ScaleEstimator() override;

  ScaleEstimator(const ScaleEstimator &) = delete;
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
  CKKSCiphertext rotate_vector_right_internal(const CKKSCiphertext &encrypted, int steps) override;

  CKKSCiphertext rotate_vector_left_internal(const CKKSCiphertext &encrypted, int steps) override;

  CKKSCiphertext add_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) override;

  CKKSCiphertext add_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) override;

  CKKSCiphertext multiply_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) override;

  CKKSCiphertext multiply_plain_mat_internal(const CKKSCiphertext &encrypted, const std::vector<double> &plain) override;

  CKKSCiphertext multiply_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) override;

  CKKSCiphertext square_internal(const CKKSCiphertext &ciphertext) override;

  void modDownTo_internal(CKKSCiphertext &x, const CKKSCiphertext &target) override;

  void modDownToMin_internal(CKKSCiphertext &x, CKKSCiphertext &target) override;

  CKKSCiphertext modDownToLevel_internal(const CKKSCiphertext &x, int level) override;

  void rescale_to_next_inplace_internal(CKKSCiphertext &encrypted) override;

  void relinearize_inplace_internal(CKKSCiphertext &encrypted) override;

  // reuse this evaluator for another computation
  void reset_internal() override;

private:
  PlaintextEval *ptEval;
  DepthFinder *dfEval;

  void print_stats(const CKKSCiphertext &c);
  void updateMaxLogScale(const CKKSCiphertext &c);
  double estimatedMaxLogScale;
  const double baseScale;
  int poly_deg;

  CKKSCiphertext merge_cts(const CKKSCiphertext &c1, const CKKSCiphertext &c2) const;

  friend class DebugEval;
};
