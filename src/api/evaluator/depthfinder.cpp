// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "depthfinder.h"

using namespace std;
using namespace seal;

DepthFinder::DepthFinder(const shared_ptr<SEALContext> c, bool verbose): CKKSEvaluator(c, verbose), multiplicativeDepth(0) { }

DepthFinder::~DepthFinder() = default;

void DepthFinder::reset_internal() {
  multiplicativeDepth = 0;
}

// print some debug info
void DepthFinder::print_stats(const CKKSCiphertext &c) {
  cout << "    + Level: " << c.heLevel << endl;
}

CKKSCiphertext DepthFinder::rotate_vector_right_internal(const CKKSCiphertext &encrypted, int) {
  VERBOSE(print_stats(encrypted));
  return encrypted;
}

CKKSCiphertext DepthFinder::rotate_vector_left_internal(const CKKSCiphertext &encrypted, int) {
  VERBOSE(print_stats(encrypted));
  return encrypted;
}

CKKSCiphertext DepthFinder::add_plain_scalar_internal(const CKKSCiphertext &encrypted, double) {
  VERBOSE(print_stats(encrypted));
  return encrypted;
}

CKKSCiphertext DepthFinder::add_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) {
  // check that ciphertexts are at the same level to avoid an obscure SEAL error
  if(encrypted1.heLevel != encrypted2.heLevel) {
    stringstream buffer;
    buffer << "PPLR: Error in DepthFinder::add: input levels do not match: " << encrypted1.heLevel << " != " << encrypted2.heLevel;
    throw invalid_argument(buffer.str());
  }
  VERBOSE(print_stats(encrypted1));
  return encrypted1;
}

CKKSCiphertext DepthFinder::multiply_plain_scalar_internal(const CKKSCiphertext &encrypted, double) {
  VERBOSE(print_stats(encrypted));
  return encrypted;
}

CKKSCiphertext DepthFinder::multiply_plain_mat_internal(const CKKSCiphertext &encrypted, const std::vector<double> &) {
  VERBOSE(print_stats(encrypted));
  return encrypted;
}

CKKSCiphertext DepthFinder::multiply_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) {
  // check that ciphertexts are at the same level to avoid an obscure SEAL error
  if(encrypted1.heLevel != encrypted2.heLevel) {
    stringstream buffer;
    buffer <<"PPLR: Error in DepthFinder::multiply: input levels do not match: " << encrypted1.heLevel << " != " << encrypted2.heLevel;
    throw invalid_argument(buffer.str());
  }
  VERBOSE(print_stats(encrypted1));
  return encrypted1;
}

CKKSCiphertext DepthFinder::square_internal(const CKKSCiphertext &x) {
  VERBOSE(print_stats(x));
  return x;
}

void DepthFinder::modDownTo_internal(CKKSCiphertext &x, const CKKSCiphertext &target) {
  if(x.heLevel >= target.heLevel) {
    x.heLevel = target.heLevel;
  }
  else {
    throw invalid_argument("x level is below target level");
  }
  VERBOSE(print_stats(x));
}

void DepthFinder::modDownToMin_internal(CKKSCiphertext &x, CKKSCiphertext &y) {
  int minLevel = min(x.heLevel, y.heLevel);
  x.heLevel = minLevel;
  y.heLevel = minLevel;
  // doesn't matter which input I print stats for since we only
  // print the level, and both have the same level at this point.
  VERBOSE(print_stats(x));
}

CKKSCiphertext DepthFinder::modDownToLevel_internal(const CKKSCiphertext &x, int level) {
  CKKSCiphertext y = x;
  if(x.heLevel >= level) {
    y.heLevel = level;
  }
  else {
    throw invalid_argument("x level is below target level");
  }
  VERBOSE(print_stats(y));
  return y;
}

void DepthFinder::rescale_to_next_inplace_internal(CKKSCiphertext &encrypted) {
  int topHELevel = context->first_context_data()->chain_index();
  encrypted.heLevel--;
  multiplicativeDepth = max(multiplicativeDepth, topHELevel-encrypted.heLevel);
  VERBOSE(print_stats(encrypted));
}

void DepthFinder::relinearize_inplace_internal(CKKSCiphertext &) {}

int DepthFinder::getMultiplicativeDepth() const {
  return multiplicativeDepth;
}


