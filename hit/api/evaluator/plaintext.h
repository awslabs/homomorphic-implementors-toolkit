// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "seal/seal.h"
#include "seal/context.h"
#include "../ciphertext.h"
#include "../evaluator.h"

/* This evaluator tracks the plaintext computation */
class PlaintextEval: public CKKSEvaluator
{
public:
  PlaintextEval(const std::shared_ptr<seal::SEALContext> c, bool verbose);

  /* For documentation on the API, see ../evaluator.h */
  ~PlaintextEval();

  PlaintextEval(const PlaintextEval &) = delete;
  PlaintextEval& operator=(const PlaintextEval&) = delete;
  PlaintextEval(PlaintextEval&&) = delete;
  PlaintextEval& operator=(PlaintextEval&&) = delete;

  // return the base-2 log of the maximum plaintext value in the computation
  // this is useful for putting an upper bound on the scale parameter
  double getExactMaxLogPlainVal() const;

  // primarily used to indicate the maximum value for each *input* to the function.
  // For functions which are a no-op, this function is the only way the evaluator
  // can learn the maximum plaintext values.
  void updatePlaintextMaxVal(double x);

protected:
  virtual CKKSCiphertext rotate_vector_right_internal(const CKKSCiphertext &encrypted, int steps) override;

  virtual CKKSCiphertext rotate_vector_left_internal(const CKKSCiphertext &encrypted, int steps) override;

  virtual CKKSCiphertext add_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) override;

  virtual CKKSCiphertext add_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) override;

  virtual CKKSCiphertext multiply_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) override;

  virtual CKKSCiphertext multiply_plain_mat_internal(const CKKSCiphertext &encrypted, const std::vector<double> &plain) override;

  virtual CKKSCiphertext multiply_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) override;

  virtual CKKSCiphertext square_internal(const CKKSCiphertext &ciphertext) override;

  virtual void modDownTo_internal(CKKSCiphertext &x, const CKKSCiphertext &target) override;

  virtual void modDownToMin_internal(CKKSCiphertext &x, CKKSCiphertext &y) override;

  virtual CKKSCiphertext modDownToLevel_internal(const CKKSCiphertext &x, int level) override;

  virtual void rescale_to_next_inplace_internal(CKKSCiphertext &encrypted) override;

  virtual void relinearize_inplace_internal(CKKSCiphertext &encrypted) override;

  // reuse this evaluator for another computation
  virtual void reset_internal() override;

private:
  void print_stats(const CKKSCiphertext &c);
  void updateMaxLogPlainVal(const CKKSCiphertext &c);
  double ptMaxLog;

  friend class ScaleEstimator;
};
