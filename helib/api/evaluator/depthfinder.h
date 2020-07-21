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
  DepthFinder(const std::shared_ptr<seal::SEALContext> c, bool verbose);

  /* For documentation on the API, see ../evaluator.h */
  ~DepthFinder();

  DepthFinder(const DepthFinder &) = delete;
  DepthFinder& operator=(const DepthFinder&) = delete;
  DepthFinder(DepthFinder&&) = delete;
  DepthFinder& operator=(DepthFinder&&) = delete;

  /* Return the multiplicative depth of this computation.
   * Must be called after performing the target computation.
   * Not available for all concrete evaluators.
   */
  int getMultiplicativeDepth() const;

protected:
  virtual CKKSCiphertext rotate_vector_right_internal(const CKKSCiphertext &encrypted, int steps) override;

  virtual CKKSCiphertext rotate_vector_left_internal(const CKKSCiphertext &encrypted, int steps) override;

  virtual CKKSCiphertext add_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) override;

  virtual CKKSCiphertext add_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) override;

  virtual CKKSCiphertext multiply_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) override;

  virtual CKKSCiphertext multiply_plain_mat_internal(const CKKSCiphertext &encrypted, const std::vector<double> &plain) override;

  virtual CKKSCiphertext multiply_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) override;

  virtual CKKSCiphertext square_internal(const CKKSCiphertext &x) override;

  virtual void modDownTo_internal(CKKSCiphertext &x, const CKKSCiphertext &target) override;

  virtual void modDownToMin_internal(CKKSCiphertext &x, CKKSCiphertext &target) override;

  virtual CKKSCiphertext modDownToLevel_internal(const CKKSCiphertext &x, int level) override;

  virtual void rescale_to_next_inplace_internal(CKKSCiphertext &encrypted) override;

  virtual void relinearize_inplace_internal(CKKSCiphertext &encrypted) override;

  // reuse this evaluator for another computation
  virtual void reset_internal() override;

private:
  int multiplicativeDepth;
  void print_stats(const CKKSCiphertext &c);

  friend class ScaleEstimator;
  friend class OpCount;
};
