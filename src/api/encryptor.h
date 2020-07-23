// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "seal/seal.h"
#include "seal/context.h"
#include "ciphertext.h"
#include "../matrix.h"

/* This class offers a higher-level API compared to SEAL's `Encryptor` class.
 * In particular, encryption produces dimension-aware CKKSCiphertexts rather
 * than SEAL's Ciphertext type. Furthermore, the input is a C++ vector rather
 * than a CKKS Plaintext. This has two advantages: first, the encryption API
 * implicitly performs CKKS encoding for matrices. But for vectors, it also
 * encodes the vector as an matrix (see pplr.cpp for more details) before
 * encoding with CKKS. In short, this API hides all of the encoding details
 * for both linear algebra and CKKS.
 */

class CKKSEncryptor
{
public:
  // constructor for Meta and Plaintext mode
  // Ciphertexts include basic metadata like dimensions.
  // If `includePlaintext`, then ciphertexts additionally include padded plaintext.
  CKKSEncryptor(const std::shared_ptr<seal::SEALContext> context, int numSlots, bool includePlaintext);

  // constructor for Homomorphic and Debug modes
  CKKSEncryptor(const std::shared_ptr<seal::SEALContext> context, seal::CKKSEncoder *enc,
                seal::Encryptor *encryptor, bool debug=false);

  void encryptMatrix(const Matrix, double scale, CKKSCiphertext &destination, int lvl = -1);

  void encryptColVec(const std::vector<double> &plain, int matHeight, double scale, CKKSCiphertext &destination, int lvl = -1);

  void encryptRowVec(const std::vector<double> &plain, int matWidth, double scale, CKKSCiphertext &destination, int lvl = -1);
private:
  // the encryption mode tells the encryptor which values to set during encryption
  // For example, we don't want to include the plaintext in the ciphertext when
  // in production, but we need to include it in plaintext or debug mode.
  // ENC_META sets ciphertext metadata (like size, encoding, heLevel, and scale),
  //   but does not include plaintext or ciphertext
  // ENC_PLAIN includes all of ENC_META, but also sets the plaintext
  // ENC_NORMAL includes basic metadata like encoding and dimensions,
  //   but does not include the plaintext. This mode actually encrypts
  //   the plaintext to produce a ciphertext.
  // ENC_DEBUG sets all the metadata from ENC_PLAIN but additionally encrypts
  //   the plaintext.
  enum EncryptMode {ENC_META, ENC_PLAIN, ENC_NORMAL, ENC_DEBUG};
  EncryptMode mode;

  seal::CKKSEncoder *encoder;
  seal::Encryptor *encryptor;
  const std::shared_ptr<seal::SEALContext> context;
  int numSlots;
};
