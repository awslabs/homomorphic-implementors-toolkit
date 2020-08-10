// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "plaintext.h"
#include "../../common.h"
#include <iomanip>

// This is an approximation of -infity, since infNorm(x) >= 0 = 2^-infinity
double initialPtMaxLog = -100;

PlaintextEval::PlaintextEval(const std::shared_ptr<seal::SEALContext> &c, bool verbose):
  CKKSEvaluator(c, verbose), ptMaxLog(initialPtMaxLog) { }

PlaintextEval::~PlaintextEval() = default;

void PlaintextEval::reset_internal() {
  ptMaxLog = initialPtMaxLog;
}

// print some debug info
void PlaintextEval::print_stats(const CKKSCiphertext &c) {
  // extract just the elements we care about from the real plaintext
  std::vector<double> exactPlaintext = c.getPlaintext();
  double exactPlaintextMaxVal = lInfNorm(exactPlaintext);
  std::cout << "    + Plaintext dimension: " << c.height << "x" << c.width << std::endl;
  std::cout << "    + Scale: " << std::setprecision(4) << log2(c.scale) << " bits" << std::endl;
  std::cout << "    + Exact plaintext logmax: " << log2(exactPlaintextMaxVal) << " bits (scaled: " <<
          log2(c.scale)+log2(exactPlaintextMaxVal) << " bits)" << std::endl;

  int maxPrintSize = 8;
  std::cout << "    + Exact plaintext: < ";
  for(int j = 0; j < std::min(maxPrintSize, (int)exactPlaintext.size()); j++) {
    std::cout << std::setprecision(8) << exactPlaintext[j] << ", ";
  }
  if (exactPlaintext.size() > maxPrintSize) {
    std::cout << "... ";
  }
  std::cout << ">" << std::endl;
}

void PlaintextEval::updateMaxLogPlainVal(const CKKSCiphertext &c) {
  double exactPlaintextMaxVal = lInfNorm(c.getPlaintext());
  //std::cout << "Updating ptMaxVal: " << log2(exactPlaintextMaxVal) << std::endl;

  ptMaxLog = std::max(ptMaxLog, log2(exactPlaintextMaxVal));
}

void PlaintextEval::updatePlaintextMaxVal(double x) {
  // takes the actual max value, we need to set the log of it
  ptMaxLog = std::max(ptMaxLog, log2(x));
}

CKKSCiphertext PlaintextEval::rotate_vector_right_internal(const CKKSCiphertext &encrypted, int steps) {
  CKKSCiphertext dest = encrypted;
  std::vector<double> rot_temp;
  // reserve a full-size std::vector
  int pt_size = encrypted.encoded_pt.size();
  rot_temp.reserve(pt_size);

  // the `for` loop adds elements to the back of the std::vector
  // we start by adding elements from the end of `encrypted.encoded_pt`
  for(int i = pt_size-steps; i < pt_size; i++) {
    rot_temp.push_back(encrypted.encoded_pt[i]);
  }
  // next start at the front of `encrypted.encoded_pt` and add until full
  for(int i = 0; i < pt_size-steps; i++) {
    rot_temp.push_back(encrypted.encoded_pt[i]);
  }

  dest.encoded_pt = rot_temp;
  // does not change ptMaxLog
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext PlaintextEval::rotate_vector_left_internal(const CKKSCiphertext &encrypted, int steps) {
  CKKSCiphertext dest = encrypted;
  std::vector<double> rot_temp;
  // reserve a full-size std::vector
  int pt_size = encrypted.encoded_pt.size();
  rot_temp.reserve(pt_size);
  // start filling from the offset
  for(int i = steps; i < pt_size; i++) {
    rot_temp.push_back(encrypted.encoded_pt[i]);
  }
  // next, add the remaining elements from the front of `encrypted.encoded_pt`
  for(int i = 0; i < steps; i++) {
    rot_temp.push_back(encrypted.encoded_pt[i]);
  }

  dest.encoded_pt = rot_temp;
  // does not change ptMaxLog
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext PlaintextEval::add_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) {
  CKKSCiphertext dest = encrypted1;
  dest.encoded_pt = encrypted1.encoded_pt + encrypted2.encoded_pt;
  updateMaxLogPlainVal(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext PlaintextEval::add_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) {
  CKKSCiphertext dest = encrypted;
  Vector coeffVec(encrypted.encoded_pt.size(), plain);
  dest.encoded_pt = encrypted.encoded_pt+coeffVec;
  updateMaxLogPlainVal(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext PlaintextEval::multiply_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) {
  CKKSCiphertext dest = encrypted;
  dest.encoded_pt = plain * encrypted.encoded_pt;
  updateMaxLogPlainVal(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext PlaintextEval::multiply_plain_mat_internal(const CKKSCiphertext &encrypted, const std::vector<double> &plain) {
  CKKSCiphertext dest = encrypted;
  seal::Plaintext temp;
  std::vector<double> temp_dec = plain;

  if(plain.size() != encrypted.encoded_pt.size()) {
    std::stringstream buffer;
    buffer << "plaintext.multiply_plain_mat_internal: public input has the wrong size: " << plain.size() << " != " << encrypted.encoded_pt.size();
    throw std::invalid_argument(buffer.str());
  }

  for(int i = 0; i < encrypted.encoded_pt.size(); i++) {
    dest.encoded_pt[i] = encrypted.encoded_pt[i] * temp_dec[i];
  }
  updateMaxLogPlainVal(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext PlaintextEval::multiply_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) {
  if(encrypted1.encoded_pt.size() != encrypted2.encoded_pt.size()) {
    throw std::invalid_argument("INTERNAL ERROR: Plaintext size mismatch");
  }
  CKKSCiphertext dest = encrypted1;
  for(int i = 0; i < encrypted1.encoded_pt.size(); i++) {
    dest.encoded_pt[i] = encrypted1.encoded_pt[i] * encrypted2.encoded_pt[i];
  }
  updateMaxLogPlainVal(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext PlaintextEval::square_internal(const CKKSCiphertext &ciphertext) {
  CKKSCiphertext dest = ciphertext;
  for(int i = 0; i < ciphertext.encoded_pt.size(); i++) {
    dest.encoded_pt[i] = ciphertext.encoded_pt[i]*ciphertext.encoded_pt[i];
  }
  updateMaxLogPlainVal(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

void PlaintextEval::modDownTo_internal(CKKSCiphertext &x, const CKKSCiphertext &) {
  // does not change ptMaxLog
  VERBOSE(print_stats(x));
}

void PlaintextEval::modDownToMin_internal(CKKSCiphertext &x, CKKSCiphertext &y) {
  // does not change ptMaxLog
  VERBOSE(print_stats(x));
  VERBOSE(print_stats(y));
}

CKKSCiphertext PlaintextEval::modDownToLevel_internal(const CKKSCiphertext &x, int) {
  // does not change ptMaxLog
  VERBOSE(print_stats(x));
  return x;
}

void PlaintextEval::rescale_to_next_inplace_internal(CKKSCiphertext &encrypted) {
  // does not change ptMaxLog
  VERBOSE(print_stats(encrypted));
}

void PlaintextEval::relinearize_inplace_internal(CKKSCiphertext &encrypted) {
  // does not change ptMaxLog
  VERBOSE(print_stats(encrypted));
}

double PlaintextEval::getExactMaxLogPlainVal() const {
  return ptMaxLog;
}
