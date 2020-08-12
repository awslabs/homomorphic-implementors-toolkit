// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "decryptor.h"
#include "../common.h"

CKKSDecryptor::CKKSDecryptor(const std::shared_ptr<seal::SEALContext> &context, seal::CKKSEncoder *encoder, const seal::SecretKey &secret_key):
  encoder(encoder), context(context) {
  decryptor = new seal::Decryptor(context, secret_key);
}

CKKSDecryptor::~CKKSDecryptor() {
  delete(decryptor);
}

std::vector<double> CKKSDecryptor::decrypt(const CKKSCiphertext &encrypted, bool verbose) {
  seal::Plaintext temp;

  int lvl = encrypted.getLevel(context);
  if(lvl != 0 && verbose) {
    std::cout << "WARNING: Decrypting a ciphertext that is not at level 0! Consider starting with a smaller modulus to improve performance!" << std::endl;
  }

  decryptor->decrypt(encrypted.seal_ct, temp);

  std::vector<double> temp_vec;
  encoder->decode(temp, temp_vec);

  return decodePlaintext(temp_vec, encrypted.encoding, encrypted.height, encrypted.width, encrypted.encoded_height, encrypted.encoded_width);
}
