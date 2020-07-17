// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "seal/seal.h"
#include "seal/context.h"
#include "../ciphertext.h"
#include "../evaluator.h"
#include "homomorphic.h"

/* This evaluator is a thin wrapper around
 * SEAL's evaluator API. It actually does
 * computation on SEAL ciphertexts.
 */
class HomomorphicEval: public CKKSEvaluator
{
public:
  /* This provides the 'production' evaluator, which just offers an improved
   * API without debug information.
   *
   * All of these parameters contain only public information. The GaloisKeys
   * and RelinKeys are part of the CKKS scheme's "evaluation keys".
   */
  HomomorphicEval(const std::shared_ptr<seal::SEALContext> c, seal::CKKSEncoder &encoder, seal::Encryptor &encryptor,
                  const seal::GaloisKeys &gkeys, const seal::RelinKeys &relin_keys, bool verbose=false);

  /* For documentation on the API, see ../evaluator.h */
  ~HomomorphicEval();

  HomomorphicEval(const HomomorphicEval &) = delete;
  HomomorphicEval& operator=(const HomomorphicEval&) = delete;
  HomomorphicEval(HomomorphicEval&&) = delete;
  HomomorphicEval& operator=(HomomorphicEval&&) = delete;

protected:
  virtual CKKSCiphertext rotate_vector_right_internal(const CKKSCiphertext &encrypted, int steps) override;

  virtual CKKSCiphertext rotate_vector_left_internal(const CKKSCiphertext &encrypted, int steps) override;

  virtual CKKSCiphertext add_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) override;

  virtual CKKSCiphertext add_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) override;

  /* WARNING: Multiplying by 0 results in non-constant time behavior! Only multiply by 0 if the scalar is truly public. */
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
  seal::Evaluator evaluator;
  seal::CKKSEncoder &encoder;
  seal::Encryptor &encryptor;
  // It would be nice to mark these `const`. However, I'm using
  // "move" semantics in CKKSInstance.cpp where they are generated to avoid
  // having two copies of the keys. This doesn't work if I have `const` types
  // involved because the copy constructor is invoked rather than the `move`
  // constructor. Someone with more C++ knowledge may be able to improve
  // the situation.
  const seal::GaloisKeys &galois_keys;
  const seal::RelinKeys &relin_keys;

  friend class DebugEval;
};
