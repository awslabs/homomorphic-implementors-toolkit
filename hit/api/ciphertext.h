// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "seal/seal.h"
#include "seal/context.h"
#include "../matrix.h"
#include "protobuf/ciphertext.pb.h" // NOLINT

/* This is a wrapper around the SEAL `Ciphertext` type.
 * It tracks the plaintext dimension, since in PPLR,
 * plaintexts are objects from linear algebra.
 * This allows us to ensure that we are only performing
 * homomorphic linear algebra operations on ciphertexts
 * whose underlying plaintext dimensions match up.
 */

/* In PPLR, a plaintext can either be a generic matrix,
 * a row vector, or a column vector.
 * There is also an option to be a "row matrix" which means
 * that a row vector was multiplied by a matrix, but it has not
 * undergone a rowSum yet. Similarly for COL_MAT
 */
enum CTEncoding { MATRIX, COL_VEC, ROW_VEC, COL_MAT, ROW_MAT, UNINITIALIZED };

struct CKKSCiphertext {
  seal::Ciphertext sealct;
  int height; // NOLINT(modernize-use-default-member-init)
  int width; // NOLINT(modernize-use-default-member-init)
  int encoded_height; // NOLINT(modernize-use-default-member-init)
  int encoded_width; // NOLINT(modernize-use-default-member-init)
  CTEncoding encoding; // NOLINT(modernize-use-default-member-init)

  // the next three items are for used by some evaluators to track additional metadata

  // heLevel is used by the depthFinder
  int heLevel; // NOLINT(modernize-use-default-member-init)

  // `plain` is used by the Plaintext evaluator
  Vector encoded_pt;

  // `scale` is used by the ScaleEstimator evaluator
  double scale; // NOLINT(modernize-use-default-member-init)

  // A default constructor is useful since we often write, e.g, `Ciphertext &a;`
  CKKSCiphertext();

  CKKSCiphertext(const std::shared_ptr<seal::SEALContext> &context, const protobuf::hit::Ciphertext &proto_ct);

  // Copy all members except the ciphertext itself
  void copyMetadataFrom(const CKKSCiphertext &src);

  // Return the SEAL `chain_index` of this ciphertext.
  // This essentially refers to how many primes are in the modulus.
  // A ciphertext starts with many primes (corresponding to the highest chain_index/level)
  // but we remove primes to scale down the noise. A single prime (the lowest level) corresponds
  // to level 0.
  int getLevel(const std::shared_ptr<seal::SEALContext> &context) const;

  std::vector<double> getPlaintext() const;

  protobuf::hit::Ciphertext* save() const;
  void save(protobuf::hit::Ciphertext *proto_ct) const;
};
