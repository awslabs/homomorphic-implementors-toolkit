// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "debug.h"
#include "../evaluator.h"
#include "../../common.h"
#include <iomanip>

using namespace std;
using namespace seal;

DebugEval::DebugEval(const shared_ptr<SEALContext> &c, CKKSEncoder &encoder, Encryptor &encryptor,
                     const GaloisKeys &gkeys, const RelinKeys &relin_keys,
                     double scale, CKKSDecryptor &d, bool verbose):
  CKKSEvaluator(c, verbose), decryptor(d), initScale(scale) {
  heEval = new HomomorphicEval(c, encoder, encryptor, gkeys, relin_keys, verbose);
  seEval = new ScaleEstimator(c, 2*encoder.slot_count(), scale, verbose);
}

DebugEval::~DebugEval() {
  delete heEval;
  delete seEval;
}

void DebugEval::reset_internal() {
  heEval->reset_internal();
  seEval->reset_internal();
}

// Verify that the ciphertext is either at its expected scale (based on its level),
// or is at the square of its expected scale.
void DebugEval::checkScale(const CKKSCiphertext &x) const {
  auto context_data = context->first_context_data();
  double expectedScale = initScale;
  while (context_data->chain_index() > x.heLevel) {
    expectedScale = (expectedScale*expectedScale) / (double)context_data->parms().coeff_modulus().back().value();
    context_data = context_data->next_context_data();
  }
  if(x.sealct.scale() != expectedScale && x.sealct.scale() != expectedScale*expectedScale) {
    throw invalid_argument("CHECK_SCALE: Expected " + to_string(expectedScale) + "^{1,2}, got " + to_string(x.sealct.scale()));
  }
}

// print some debug info
void DebugEval::print_stats(const CKKSCiphertext &c) {
  double norm = 0;

  // decrypt to compute the approximate plaintext
  vector<double> homomPlaintext = decryptor.decrypt(c, false);
  vector<double> exactPlaintext = c.getPlaintext();

  norm = diff2Norm(exactPlaintext, homomPlaintext);
  if(abs(log2(c.scale)-log2(c.sealct.scale())) > 0.1) {
    stringstream buffer;
    buffer << "INTERNAL ERROR: SCALE COMPUTATION IS INCORRECT: " << log2(c.scale) << " != " << c.sealct.scale();
    throw invalid_argument(buffer.str());
  }

  VERBOSE(cout << setprecision(8) << "    + Approximation norm: " << norm << endl);

  int maxPrintSize = 8;
  VERBOSE(cout << "    + Homom Result:   < ");
  for(int i = 0; i < min(maxPrintSize, (int)homomPlaintext.size()); i++) {
    VERBOSE(cout << setprecision(8) << homomPlaintext[i] << ", ");
  }
  if (homomPlaintext.size() > maxPrintSize) {
    VERBOSE(cout << "... ");
  }
  VERBOSE(cout << ">" << endl);

  if(norm > MAX_NORM) {
    stringstream buffer;
    buffer << "DebugEvaluator: plaintext and ciphertext divergence: " <<
              norm << " > " << MAX_NORM << ". Scale is " << log2(seEval->baseScale) << ".";

    maxPrintSize = 32;
    cout << "    + DEBUG Expected result: <";
    for(int i = 0; i < min(maxPrintSize,(int)exactPlaintext.size()); i++) {
      cout << setprecision(8) << exactPlaintext[i];
      if(i < exactPlaintext.size()-1) {
        cout << ", ";
      }
    }
    if (exactPlaintext.size() > maxPrintSize) {
      cout << "..., ";
    }
    cout << ">" << endl;

    cout << "    + DEBUG Actual result:   <";
    for(int i = 0; i < min(maxPrintSize,(int)homomPlaintext.size()); i++) {
      cout << setprecision(8) << homomPlaintext[i];
      if(i < exactPlaintext.size()-1) {
        cout << ", ";
      }
    }
    if (homomPlaintext.size() > maxPrintSize) {
      cout << "..., ";
    }
    cout << ">" << endl;

    Plaintext encoded_plain;
    heEval->encoder.encode(c.encoded_pt.data(), seEval->baseScale, encoded_plain);

    vector<double> decoded_plain;
    heEval->encoder.decode(encoded_plain, decoded_plain);

    // the exactPlaintext and homomPlaintext should have the same length.
    // decoded_plain is full-dimensional, however. This may not match
    // the dimension of exactPlaintext if the plaintext in question is a
    // vector, so we need to truncate the decoded value.
    vector<double> truncated_decoded_plain(decoded_plain.begin(),decoded_plain.begin()+exactPlaintext.size());
    double norm2 = diff2Norm(exactPlaintext, truncated_decoded_plain);
    double norm3 = diff2Norm(truncated_decoded_plain, homomPlaintext);

    cout << "Encoding norm: " << norm2 << endl;
    cout << "Encryption norm: " << norm3 << endl;

    throw invalid_argument(buffer.str());
  }
  VERBOSE(cout << endl);
}

CKKSCiphertext DebugEval::merge_cts(const CKKSCiphertext &c1, const CKKSCiphertext &c2) const {
  CKKSCiphertext t = c1;
  t.copyMetadataFrom(c2);
  return t;
}

CKKSCiphertext DebugEval::rotate_vector_right_internal(const CKKSCiphertext &encrypted, int steps) {
  // recursive calls
  checkScale(encrypted);
  CKKSCiphertext dest_he = heEval->rotate_vector_right_internal(encrypted, steps);
  CKKSCiphertext dest_se = seEval->rotate_vector_right_internal(encrypted, steps);
  CKKSCiphertext dest = merge_cts(dest_he, dest_se);

  print_stats(dest);
  checkScale(dest);
  return dest;
}

CKKSCiphertext DebugEval::rotate_vector_left_internal(const CKKSCiphertext &encrypted, int steps) {
  // recursive calls
  checkScale(encrypted);
  CKKSCiphertext dest_he = heEval->rotate_vector_left_internal(encrypted, steps);
  CKKSCiphertext dest_se = seEval->rotate_vector_left_internal(encrypted, steps);
  CKKSCiphertext dest = merge_cts(dest_he, dest_se);

  print_stats(dest);
  checkScale(dest);
  return dest;
}

CKKSCiphertext DebugEval::add_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) {
  // recursive calls
  checkScale(encrypted);
  CKKSCiphertext dest_he = heEval->add_plain_scalar_internal(encrypted, plain);
  CKKSCiphertext dest_se = seEval->add_plain_scalar_internal(encrypted, plain);
  CKKSCiphertext dest = merge_cts(dest_he, dest_se);

  print_stats(dest);
  checkScale(dest);
  return dest;
}

CKKSCiphertext DebugEval::add_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) {
  // recursive calls
  checkScale(encrypted1);
  checkScale(encrypted2);
  CKKSCiphertext dest_he = heEval->add_internal(encrypted1, encrypted2);
  CKKSCiphertext dest_se = seEval->add_internal(encrypted1, encrypted2);
  CKKSCiphertext dest = merge_cts(dest_he, dest_se);

  print_stats(dest);
  checkScale(dest);
  return dest;
}

CKKSCiphertext DebugEval::multiply_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) {
  // recursive calls
  checkScale(encrypted);
  CKKSCiphertext dest_he = heEval->multiply_plain_scalar_internal(encrypted, plain);
  CKKSCiphertext dest_se = seEval->multiply_plain_scalar_internal(encrypted, plain);
  CKKSCiphertext dest = merge_cts(dest_he, dest_se);

  print_stats(dest);
  checkScale(dest);
  return dest;
}

CKKSCiphertext DebugEval::multiply_plain_mat_internal(const CKKSCiphertext &encrypted, const vector<double> &plain) {
  // recursive calls
  checkScale(encrypted);
  CKKSCiphertext dest_he = heEval->multiply_plain_mat_internal(encrypted, plain);
  CKKSCiphertext dest_se = seEval->multiply_plain_mat_internal(encrypted, plain);
  CKKSCiphertext dest = merge_cts(dest_he, dest_se);

  print_stats(dest);
  checkScale(dest);
  return dest;
}

CKKSCiphertext DebugEval::multiply_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) {
  // recursive calls
  checkScale(encrypted1);
  checkScale(encrypted2);
  CKKSCiphertext dest_he = heEval->multiply_internal(encrypted1, encrypted2);
  CKKSCiphertext dest_se = seEval->multiply_internal(encrypted1, encrypted2);
  CKKSCiphertext dest = merge_cts(dest_he, dest_se);

  print_stats(dest);
  checkScale(dest);
  return dest;
}

CKKSCiphertext DebugEval::square_internal(const CKKSCiphertext &ciphertext) {
  // recursive calls
  checkScale(ciphertext);
  CKKSCiphertext dest_he = heEval->square_internal(ciphertext);
  CKKSCiphertext dest_se = seEval->square_internal(ciphertext);
  CKKSCiphertext dest = merge_cts(dest_he, dest_se);

  print_stats(dest);
  checkScale(dest);
  return dest;
}

void DebugEval::modDownTo_internal(CKKSCiphertext &x, const CKKSCiphertext &target) {
  // recursive calls
  checkScale(x);
  checkScale(target);
  heEval->modDownTo_internal(x, target);
  seEval->modDownTo_internal(x, target);

  print_stats(x);
  checkScale(x);
}

void DebugEval::modDownToMin_internal(CKKSCiphertext &x, CKKSCiphertext &y) {
  // recursive calls
  heEval->modDownToMin_internal(x, y);
  seEval->modDownToMin_internal(x, y);

  print_stats(x);
  print_stats(y);
}

CKKSCiphertext DebugEval::modDownToLevel_internal(const CKKSCiphertext &x, int level) {
  // recursive calls
  checkScale(x);
  CKKSCiphertext dest_he = heEval->modDownToLevel_internal(x, level);
  CKKSCiphertext dest_se = seEval->modDownToLevel_internal(x, level);
  CKKSCiphertext dest = merge_cts(dest_he, dest_se);

  print_stats(dest);
  checkScale(dest);
  return dest;
}

void DebugEval::rescale_to_next_inplace_internal(CKKSCiphertext &encrypted) {
  auto context_data = getContextData(encrypted);
  uint64_t p = context_data->parms().coeff_modulus().back().value();
  double prime_bit_len = log2(p);

  checkScale(encrypted);
  // recursive calls
  heEval->rescale_to_next_inplace_internal(encrypted);
  seEval->rescale_to_next_inplace_internal(encrypted);

  // for some reason, the default is to print doubles with no decimal places.
  // To get decimal places, add `<< fixed << setprecision(2)` before printing the log.
  // Note that you'll need a lot of decimal places because these values are very close
  // to an integer.
  VERBOSE(cout << "    + Scaled plaintext down by the ~" <<
          prime_bit_len << "-bit prime " << hex << p << dec << endl);

  print_stats(encrypted);
  checkScale(encrypted);
}

void DebugEval::relinearize_inplace_internal(CKKSCiphertext &encrypted) {
  // recursive calls
  checkScale(encrypted);
  heEval->relinearize_inplace_internal(encrypted);
  seEval->relinearize_inplace_internal(encrypted);

  print_stats(encrypted);
  checkScale(encrypted);
}

void DebugEval::updatePlaintextMaxVal(double x) {
  seEval->updatePlaintextMaxVal(x);
}

double DebugEval::getExactMaxLogPlainVal() const {
  return seEval->getExactMaxLogPlainVal();
}

double DebugEval::getEstimatedMaxLogScale() const {
  return seEval->getEstimatedMaxLogScale();
}
