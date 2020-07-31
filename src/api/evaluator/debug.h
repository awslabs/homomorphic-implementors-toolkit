// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "seal/seal.h"
#include "../ciphertext.h"
#include "../decryptor.h"
#include "homomorphic.h"
#include "scaleestimator.h"
#include "../evaluator.h"

/* This is the full debug evaluator. It combines all of the
 * other evaluators, thereby tracking all information
 * from DepthFinder, PlaintextEval, and ScaleEstimator,
 * as well as performing the ciphertext operations.
 */

class DebugEval: public CKKSEvaluator
{
public:
  DebugEval(const std::shared_ptr<seal::SEALContext> c, seal::CKKSEncoder &enc, seal::Encryptor &encryptor,
            const seal::GaloisKeys &gkeys, const seal::RelinKeys &relin_keys,
            double scale, CKKSDecryptor &d, bool verbose);

  /* For documentation on the API, see ../evaluator.h */
  ~DebugEval();

  DebugEval(const DebugEval &) = delete;
  DebugEval& operator=(const DebugEval&) = delete;
  DebugEval(DebugEval&&) = delete;
  DebugEval& operator=(DebugEval&&) = delete;

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
  virtual CKKSCiphertext rotate_vector_right_internal(const CKKSCiphertext &encrypted, int steps) override;

  virtual CKKSCiphertext rotate_vector_left_internal(const CKKSCiphertext &encrypted, int steps) override;

  virtual CKKSCiphertext add_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) override;

  virtual CKKSCiphertext add_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) override;

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
  HomomorphicEval *heEval;
  ScaleEstimator *seEval;

  void print_stats(const CKKSCiphertext &c);

  CKKSDecryptor &decryptor;
  void checkScale(const CKKSCiphertext &x) const;
  double initScale;

  CKKSCiphertext merge_cts(const CKKSCiphertext &c1, const CKKSCiphertext &c2) const;
};
