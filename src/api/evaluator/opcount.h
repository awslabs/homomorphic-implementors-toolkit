// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "seal/seal.h"
#include "seal/context.h"
#include "../ciphertext.h"
#include "../evaluator.h"
#include "depthfinder.h"

/* This evaluator tracks the plaintext computation */
class OpCount: public CKKSEvaluator
{
public:
  OpCount(const std::shared_ptr<seal::SEALContext> c, bool verbose);

  /* For documentation on the API, see ../evaluator.h */
  ~OpCount();

  OpCount(const OpCount &) = delete;
  OpCount& operator=(const OpCount&) = delete;
  OpCount(OpCount&&) = delete;
  OpCount& operator=(OpCount&&) = delete;

  /* Print the total number of operations performed in this computation. */
  void printOpCount() const;

  // recursive call to DepthFinder
  int getMultiplicativeDepth() const;

protected:
  virtual CKKSCiphertext rotate_vector_right_internal(const CKKSCiphertext &encrypted, int steps) override;

  virtual CKKSCiphertext rotate_vector_left_internal(const CKKSCiphertext &encrypted, int steps) override;

  virtual CKKSCiphertext add_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) override;

  virtual CKKSCiphertext add_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) override;

  virtual CKKSCiphertext multiply_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) override;

  virtual CKKSCiphertext multiply_plain_mat_internal(const CKKSCiphertext &encrypted, const std::vector<double> &plain) override;

  virtual CKKSCiphertext multiply_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) override;

  virtual CKKSCiphertext square_internal(const CKKSCiphertext &x) override;

  virtual void modDownTo_internal(CKKSCiphertext &x, const CKKSCiphertext &target) override;

  virtual void modDownToMin_internal(CKKSCiphertext &x, CKKSCiphertext &y) override;

  virtual CKKSCiphertext modDownToLevel_internal(const CKKSCiphertext &x, int level) override;

  virtual void rescale_to_next_inplace_internal(CKKSCiphertext &encrypted) override;

  virtual void relinearize_inplace_internal(CKKSCiphertext &encrypted) override;

  // reuse this evaluator for another computation
  virtual void reset_internal() override;

private:
  int multiplies = 0;
  int additions = 0;
  int rotations = 0;
  int modDowns = 0;
  int modDownMuls = 0;

  DepthFinder *dfEval;
};