// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "plaintext.h"
#include "../../common.h"
#include <iomanip>

// This is an approximation of -infity, since infNorm(x) >= 0 = 2^-infinity
double initialPtMaxLog = -100;

PlaintextEval::PlaintextEval(const std::shared_ptr<seal::SEALContext> &context, bool verbose):
  CKKSEvaluator(context, verbose), ptMaxLog(initialPtMaxLog) { }

PlaintextEval::~PlaintextEval() = default;

void PlaintextEval::reset_internal() {
  ptMaxLog = initialPtMaxLog;
}

// print some debug info
void print_stats(const CKKSCiphertext &ct) {
  // extract just the elements we care about from the real plaintext
  std::vector<double> exactPlaintext = ct.getPlaintext();
  double exactPlaintextMaxVal = lInfNorm(exactPlaintext);
  std::cout << "    + Plaintext dimension: " << ct.height << "x" << ct.width << std::endl;
  std::cout << "    + Scale: " << std::setprecision(4) << log2(ct.scale) << " bits" << std::endl;
  std::cout << "    + Exact plaintext logmax: " << log2(exactPlaintextMaxVal) << " bits (scaled: " <<
          log2(ct.scale)+log2(exactPlaintextMaxVal) << " bits)" << std::endl;

  int maxPrintSize = 8;
  std::cout << "    + Exact plaintext: < ";
  for(int j = 0; j < std::min(maxPrintSize, static_cast<int>(exactPlaintext.size())); j++) {
    std::cout << std::setprecision(8) << exactPlaintext[j] << ", ";
  }
  if (exactPlaintext.size() > maxPrintSize) {
    std::cout << "... ";
  }
  std::cout << ">" << std::endl;
}

void PlaintextEval::updateMaxLogPlainVal(const CKKSCiphertext &ct) {
  double exactPlaintextMaxVal = lInfNorm(ct.getPlaintext());
  //std::cout << "Updating ptMaxVal: " << log2(exactPlaintextMaxVal) << std::endl;

  ptMaxLog = std::max(ptMaxLog, log2(exactPlaintextMaxVal));
}

void PlaintextEval::updatePlaintextMaxVal(double x) {
  // takes the actual max value, we need to set the log of it
  ptMaxLog = std::max(ptMaxLog, log2(x));
}

CKKSCiphertext PlaintextEval::rotate_vector_right_internal(const CKKSCiphertext &ct, int steps) {
  CKKSCiphertext dest = ct;
  std::vector<double> rot_temp;
  // reserve a full-size std::vector
  int pt_size = ct.encoded_pt.size();
  rot_temp.reserve(pt_size);

  // the `for` loop adds elements to the back of the std::vector
  // we start by adding elements from the end of `ct.encoded_pt`
  for(int i = pt_size-steps; i < pt_size; i++) {
    rot_temp.push_back(ct.encoded_pt[i]);
  }
  // next start at the front of `ct.encoded_pt` and add until full
  for(int i = 0; i < pt_size-steps; i++) {
    rot_temp.push_back(ct.encoded_pt[i]);
  }

  dest.encoded_pt = rot_temp;
  // does not change ptMaxLog
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext PlaintextEval::rotate_vector_left_internal(const CKKSCiphertext &ct, int steps) {
  CKKSCiphertext dest = ct;
  std::vector<double> rot_temp;
  // reserve a full-size std::vector
  int pt_size = ct.encoded_pt.size();
  rot_temp.reserve(pt_size);
  // start filling from the offset
  for(int i = steps; i < pt_size; i++) {
    rot_temp.push_back(ct.encoded_pt[i]);
  }
  // next, add the remaining elements from the front of `ct.encoded_pt`
  for(int i = 0; i < steps; i++) {
    rot_temp.push_back(ct.encoded_pt[i]);
  }

  dest.encoded_pt = rot_temp;
  // does not change ptMaxLog
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext PlaintextEval::add_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
  CKKSCiphertext dest = ct1;
  dest.encoded_pt = ct1.encoded_pt + ct2.encoded_pt;
  updateMaxLogPlainVal(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext PlaintextEval::add_plain_scalar_internal(const CKKSCiphertext &ct, double scalar) {
  CKKSCiphertext dest = ct;
  Vector coeffVec(ct.encoded_pt.size(), scalar);
  dest.encoded_pt = ct.encoded_pt+coeffVec;
  updateMaxLogPlainVal(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext PlaintextEval::multiply_plain_scalar_internal(const CKKSCiphertext &ct, double scalar) {
  CKKSCiphertext dest = ct;
  dest.encoded_pt = scalar * ct.encoded_pt;
  updateMaxLogPlainVal(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext PlaintextEval::multiply_plain_mat_internal(const CKKSCiphertext &ct, const std::vector<double> &plain) {
  CKKSCiphertext dest = ct;
  seal::Plaintext temp;
  std::vector<double> temp_dec = plain;

  if(plain.size() != ct.encoded_pt.size()) {
    std::stringstream buffer;
    buffer << "plaintext.multiply_plain_mat_internal: public input has the wrong size: " << plain.size() << " != " << ct.encoded_pt.size();
    throw std::invalid_argument(buffer.str());
  }

  for(int i = 0; i < ct.encoded_pt.size(); i++) {
    dest.encoded_pt[i] = ct.encoded_pt[i] * temp_dec[i];
  }
  updateMaxLogPlainVal(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext PlaintextEval::multiply_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
  if(ct1.encoded_pt.size() != ct2.encoded_pt.size()) {
    throw std::invalid_argument("INTERNAL ERROR: Plaintext size mismatch");
  }
  CKKSCiphertext dest = ct1;
  for(int i = 0; i < ct1.encoded_pt.size(); i++) {
    dest.encoded_pt[i] = ct1.encoded_pt[i] * ct2.encoded_pt[i];
  }
  updateMaxLogPlainVal(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext PlaintextEval::square_internal(const CKKSCiphertext &ct) {
  CKKSCiphertext dest = ct;
  for(int i = 0; i < ct.encoded_pt.size(); i++) {
    dest.encoded_pt[i] = ct.encoded_pt[i]*ct.encoded_pt[i];
  }
  updateMaxLogPlainVal(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

void PlaintextEval::modDownTo_internal(CKKSCiphertext &ct, const CKKSCiphertext &) {
  // does not change ptMaxLog
  VERBOSE(print_stats(ct));
}

void PlaintextEval::modDownToMin_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) {
  // does not change ptMaxLog
  VERBOSE(print_stats(ct1));
  VERBOSE(print_stats(ct2));
}

CKKSCiphertext PlaintextEval::modDownToLevel_internal(const CKKSCiphertext &ct, int) {
  // does not change ptMaxLog
  VERBOSE(print_stats(ct));
  return ct;
}

void PlaintextEval::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
  // does not change ptMaxLog
  VERBOSE(print_stats(ct));
}

void PlaintextEval::relinearize_inplace_internal(CKKSCiphertext &ct) {
  // does not change ptMaxLog
  VERBOSE(print_stats(ct));
}

double PlaintextEval::getExactMaxLogPlainVal() const {
  return ptMaxLog;
}
