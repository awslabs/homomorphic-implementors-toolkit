// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "opcount.h"
#include <iomanip>

using namespace std;
using namespace seal;

OpCount::OpCount(const shared_ptr<SEALContext> c, bool verbose): CKKSEvaluator(c, verbose) {
  dfEval = new DepthFinder(c,verbose);
}

OpCount::~OpCount() {
  delete dfEval;
}

void OpCount::reset_internal() {
  multiplies = 0;
  additions = 0;
  rotations = 0;
  modDowns = 0;
  modDownMuls = 0;

  dfEval->reset_internal();
}

void OpCount::printOpCount() const {
  cout  << endl << "Multiplications: " << multiplies << endl;
  cout << "ModDownMuls: " << modDownMuls << endl;
  cout << "Additions: " << additions << endl;
  cout << "Rotations: " << rotations << endl;
  cout << "ModDownTos: " << modDowns << endl << endl;
}

int OpCount::getMultiplicativeDepth() const {
  return dfEval->getMultiplicativeDepth();
}

CKKSCiphertext OpCount::rotate_vector_right_internal(const CKKSCiphertext &encrypted, int steps) {
  dfEval->rotate_vector_right_internal(encrypted, steps);
  rotations++;
  return encrypted;
}

CKKSCiphertext OpCount::rotate_vector_left_internal(const CKKSCiphertext &encrypted, int steps) {
  dfEval->rotate_vector_left_internal(encrypted, steps);
  rotations++;
  return encrypted;
}

CKKSCiphertext OpCount::add_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) {
  dfEval->add_internal(encrypted1, encrypted2);
  additions++;
  return encrypted1;
}

CKKSCiphertext OpCount::add_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) {
  dfEval->add_plain_scalar_internal(encrypted, plain);
  additions++;
  return encrypted;
}

CKKSCiphertext OpCount::multiply_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) {
  dfEval->multiply_plain_scalar_internal(encrypted, plain);
  multiplies++;
  return encrypted;
}

CKKSCiphertext OpCount::multiply_plain_mat_internal(const CKKSCiphertext &encrypted, const vector<double> &plain) {
  dfEval->multiply_plain_mat_internal(encrypted, plain);
  multiplies++;
  return encrypted;
}

CKKSCiphertext OpCount::multiply_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) {
  dfEval->multiply_internal(encrypted1, encrypted2);
  multiplies++;
  return encrypted1;
}

CKKSCiphertext OpCount::square_internal(const CKKSCiphertext &ciphertext) {
  dfEval->square_internal(ciphertext);
  multiplies++;
  return ciphertext;
}

void OpCount::modDownTo_internal(CKKSCiphertext &x, const CKKSCiphertext &target) {
  if(x.heLevel-target.heLevel > 0) {
    modDowns++;
  }
  modDownMuls += (x.heLevel-target.heLevel);
  dfEval->modDownTo_internal(x, target);
}

void OpCount::modDownToMin_internal(CKKSCiphertext &x, CKKSCiphertext &y) {
  if(abs(x.heLevel - y.heLevel) > 0) {
    modDowns++;
  }
  modDownMuls += abs(x.heLevel-y.heLevel);
  dfEval->modDownToMin_internal(x,y);
}

CKKSCiphertext OpCount::modDownToLevel_internal(const CKKSCiphertext &x, int level) {
  if(x.heLevel-level > 0) {
    modDowns++;
  }
  modDownMuls += (x.heLevel-level);
  CKKSCiphertext y = dfEval->modDownToLevel_internal(x, level);
  return y;
}

void OpCount::rescale_to_next_inplace_internal(CKKSCiphertext &encrypted) {
  dfEval->rescale_to_next_inplace_internal(encrypted);
}

void OpCount::relinearize_inplace_internal(CKKSCiphertext &encrypted) {
  dfEval->relinearize_inplace_internal(encrypted);
}
