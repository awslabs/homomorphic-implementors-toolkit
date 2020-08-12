// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* This is an alternate interface for SEAL's Evaluator interface. It only includes a subset of
 * SEAL's Evaluator API, and those functions now have a simpler interface.
 */

#include "homomorphic.h"
#include <future>

using namespace std;
using namespace seal;

HomomorphicEval::HomomorphicEval(const shared_ptr<SEALContext> &c, CKKSEncoder &encoder, Encryptor &encryptor,
                                 const GaloisKeys &gkeys, const RelinKeys &relin_keys, bool verbose):
  /* This evaluator never prints anything, so CKKSEvaluator can be non-verbose */
  CKKSEvaluator(c, verbose), evaluator(c), encoder(encoder), encryptor(encryptor),
  galois_keys(gkeys), relin_keys(relin_keys) {
    evalPolicy = launch::async;
}

HomomorphicEval::~HomomorphicEval() = default;

void HomomorphicEval::reset_internal() {}

CKKSCiphertext HomomorphicEval::rotate_vector_right_internal(const CKKSCiphertext &encrypted, int steps) {
  CKKSCiphertext dest = encrypted;
  evaluator.rotate_vector(encrypted.sealct, -steps, galois_keys, dest.sealct);
  return dest;
}

CKKSCiphertext HomomorphicEval::rotate_vector_left_internal(const CKKSCiphertext &encrypted, int steps) {
  CKKSCiphertext dest = encrypted;
  evaluator.rotate_vector(encrypted.sealct, steps, galois_keys, dest.sealct);
  return dest;
}

CKKSCiphertext HomomorphicEval::add_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) {
  CKKSCiphertext dest = encrypted;
  Plaintext encoded_plain;
  encoder.encode(plain, encrypted.sealct.parms_id(), encrypted.sealct.scale(), encoded_plain);
  evaluator.add_plain(encrypted.sealct, encoded_plain, dest.sealct);
  return dest;
}

CKKSCiphertext HomomorphicEval::add_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) {
  // check that ciphertexts are at the same level to avoid an obscure SEAL error
  if(encrypted1.getLevel(context) != encrypted2.getLevel(context)) {
    stringstream buffer;
    buffer << "PPLR: Error in HomomorphicEval::add: input levels do not match: " << encrypted1.getLevel(context) << " != " << encrypted2.getLevel(context);
    throw invalid_argument(buffer.str());
  }
  CKKSCiphertext dest = encrypted1;
  evaluator.add_inplace(dest.sealct, encrypted2.sealct);
  return dest;
}

/* WARNING: Multiplying by 0 results in non-constant time behavior! Only multiply by 0 if the scalar is truly public. */
CKKSCiphertext HomomorphicEval::multiply_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) {
  CKKSCiphertext dest = encrypted;
  if(plain != 0.0) {
    Plaintext encoded_plain;
    encoder.encode(plain, encrypted.sealct.parms_id(), encrypted.sealct.scale(), encoded_plain);
    evaluator.multiply_plain(encrypted.sealct, encoded_plain, dest.sealct);
  }
  else {
    encryptor.encrypt_zero(encrypted.sealct.parms_id(), dest.sealct);
    // seal sets the scale to be 1, but our the debug evaluator always ensures that the SEAL scale is consistent with our mirror calculation
    dest.sealct.scale() = encrypted.sealct.scale()*encrypted.sealct.scale();
  }
  return dest;
}

CKKSCiphertext HomomorphicEval::multiply_plain_mat_internal(const CKKSCiphertext &encrypted, const vector<double> &plain) {
  if (plain.size() != encrypted.width*encrypted.height) {
    throw invalid_argument("PPLR: Error in HomomorphicEval::multiply_plain: plaintext size does not match ciphertext size");
  }
  CKKSCiphertext dest = encrypted;
  Plaintext temp;
  encoder.encode(plain, encrypted.sealct.parms_id(), encrypted.sealct.scale(), temp);
  evaluator.multiply_plain_inplace(dest.sealct, temp);
  return dest;
}

CKKSCiphertext HomomorphicEval::multiply_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) {
  // check that ciphertexts are at the same level to avoid an obscure SEAL error
  if(encrypted1.getLevel(context) != encrypted2.getLevel(context)) {
    stringstream buffer;
    buffer << "PPLR: Error in HomomorphicEval::multiply: input levels do not match: " << encrypted1.getLevel(context) << " != " << encrypted2.getLevel(context);
    throw invalid_argument(buffer.str());
  }
  CKKSCiphertext dest = encrypted1;
  evaluator.multiply_inplace(dest.sealct, encrypted2.sealct);
  return dest;
}

CKKSCiphertext HomomorphicEval::square_internal(const CKKSCiphertext &ciphertext) {
  CKKSCiphertext dest = ciphertext;
  evaluator.square(ciphertext.sealct, dest.sealct);
  return dest;
}

void HomomorphicEval::modDownTo_internal(CKKSCiphertext &x, const CKKSCiphertext &target) {
  if(x.getLevel(context) < target.getLevel(context)) {
    stringstream buffer;
    buffer << "PPLR: Error in modDownTo: input is at a lower level than target. Input level: "
           << x.getLevel(context) << ", target level: " << target.getLevel(context);
    throw invalid_argument(buffer.str());
  }
  while(x.getLevel(context) > target.getLevel(context)) {
    x = multiply_plain_scalar(x,1);
    rescale_to_next_inplace(x);
  }
}

void HomomorphicEval::modDownToMin_internal(CKKSCiphertext &x, CKKSCiphertext &y) {
  if(x.getLevel(context) > y.getLevel(context)) {
    modDownTo_internal(x,y);
  }
  else {
    modDownTo_internal(y,x);
  }
}

CKKSCiphertext HomomorphicEval::modDownToLevel_internal(const CKKSCiphertext &x, int level) {
  if(x.getLevel(context) < level) {
    stringstream buffer;
    buffer << "PPLR: Error in modDownTo: input is at a lower level than target. Input level: "
           << x.getLevel(context) << ", target level: " << level;
    throw invalid_argument(buffer.str());
  }
  CKKSCiphertext y = x;
  while(y.getLevel(context) > level) {
    y = multiply_plain_scalar(y,1);
    rescale_to_next_inplace(y);
  }

  return y;
}

void HomomorphicEval::rescale_to_next_inplace_internal(CKKSCiphertext &encrypted) {
  evaluator.rescale_to_next_inplace(encrypted.sealct);
}

void HomomorphicEval::relinearize_inplace_internal(CKKSCiphertext &encrypted) {
  evaluator.relinearize_inplace(encrypted.sealct, relin_keys);
}
