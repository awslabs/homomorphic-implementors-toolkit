// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "seal/seal.h"
#include "seal/context.h"
#include "../ciphertext.h"
#include "../evaluator.h"

/* This evaluator's sole purpose is to compute the
 * multiplicative depth of a computation.
 */
class DepthFinder: public CKKSEvaluator
{
public:
  DepthFinder(const std::shared_ptr<seal::SEALContext> &context, bool verbose);

  /* For documentation on the API, see ../evaluator.h */
  ~DepthFinder() override;

  DepthFinder(const DepthFinder&) = delete;
  DepthFinder& operator=(const DepthFinder&) = delete;
  DepthFinder(DepthFinder&&) = delete;
  DepthFinder& operator=(DepthFinder&&) = delete;

  /* Return the multiplicative depth of this computation.
   * Must be called after performing the target computation.
   * Not available for all concrete evaluators.
   */
  int getMultiplicativeDepth() const;

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
  int multiplicativeDepth;
  void print_stats(const CKKSCiphertext &ct);

  friend class ScaleEstimator;
  friend class OpCount;
};
