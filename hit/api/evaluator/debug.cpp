// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "debug.h"
#include "../evaluator.h"
#include "../../common.h"
#include <iomanip>

DebugEval::DebugEval(const std::shared_ptr<seal::SEALContext> &context, seal::CKKSEncoder &encoder, seal::Encryptor &encryptor,
                     const seal::GaloisKeys &galois_keys, const seal::RelinKeys &relin_keys,
                     double scale, CKKSDecryptor &decryptor, bool verbose):
  CKKSEvaluator(context, verbose), decryptor(decryptor), initScale(scale) {
  heEval = new HomomorphicEval(context, encoder, encryptor, galois_keys, relin_keys, verbose);
  seEval = new ScaleEstimator(context, static_cast<int>(2*encoder.slot_count()), scale, verbose);
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
void DebugEval::checkScale(const CKKSCiphertext &ct) const {
  auto context_data = context->first_context_data();
  double expectedScale = initScale;
  while (context_data->chain_index() > ct.he_level) {
    expectedScale = (expectedScale*expectedScale) / static_cast<double>(context_data->parms().coeff_modulus().back().value());
    context_data = context_data->next_context_data();
  }
  if(ct.seal_ct.scale() != expectedScale && ct.seal_ct.scale() != expectedScale*expectedScale) {
    throw std::invalid_argument("CHECK_SCALE: Expected " + std::to_string(expectedScale) + "^{1,2}, got " + std::to_string(ct.seal_ct.scale()));
  }
}

// print some debug info
void DebugEval::print_stats(const CKKSCiphertext &c) {
  double norm = 0;

  // decrypt to compute the approximate plaintext
  std::vector<double> homomPlaintext = decryptor.decrypt(c, false);
  std::vector<double> exactPlaintext = c.getPlaintext();

  norm = diff2Norm(exactPlaintext, homomPlaintext);
  if(abs(log2(c.scale)-log2(c.seal_ct.scale())) > 0.1) {
    std::stringstream buffer;
    buffer << "INTERNAL ERROR: SCALE COMPUTATION IS INCORRECT: " << log2(c.scale) << " != " << c.seal_ct.scale();
    throw std::invalid_argument(buffer.str());
  }

  VERBOSE(std::cout << std::setprecision(8) << "    + Approximation norm: " << norm << std::endl);

  int maxPrintSize = 8;
  VERBOSE(std::cout << "    + Homom Result:   < ");
  for(int i = 0; i < std::min(maxPrintSize, static_cast<int>(homomPlaintext.size())); i++) {
    VERBOSE(std::cout << std::setprecision(8) << homomPlaintext[i] << ", ");
  }
  if (homomPlaintext.size() > maxPrintSize) {
    VERBOSE(std::cout << "... ");
  }
  VERBOSE(std::cout << ">" << std::endl);

  if(norm > MAX_NORM) {
    std::stringstream buffer;
    buffer << "DebugEvaluator: plaintext and ciphertext divergence: " <<
              norm << " > " << MAX_NORM << ". Scale is " << log2(seEval->baseScale) << ".";

    maxPrintSize = 32;
    std::cout << "    + DEBUG Expected result: <";
    for(int i = 0; i < std::min(maxPrintSize, static_cast<int>(exactPlaintext.size())); i++) {
      std::cout << std::setprecision(8) << exactPlaintext[i];
      if(i < exactPlaintext.size()-1) {
        std::cout << ", ";
      }
    }
    if (exactPlaintext.size() > maxPrintSize) {
      std::cout << "..., ";
    }
    std::cout << ">" << std::endl;

    std::cout << "    + DEBUG Actual result:   <";
    for(int i = 0; i < std::min(maxPrintSize, static_cast<int>(homomPlaintext.size())); i++) {
      std::cout << std::setprecision(8) << homomPlaintext[i];
      if(i < exactPlaintext.size()-1) {
        std::cout << ", ";
      }
    }
    if (homomPlaintext.size() > maxPrintSize) {
      std::cout << "..., ";
    }
    std::cout << ">" << std::endl;

    seal::Plaintext encoded_plain;
    heEval->encoder.encode(c.encoded_pt.data(), seEval->baseScale, encoded_plain);

    std::vector<double> decoded_plain;
    heEval->encoder.decode(encoded_plain, decoded_plain);

    // the exactPlaintext and homomPlaintext should have the same length.
    // decoded_plain is full-dimensional, however. This may not match
    // the dimension of exactPlaintext if the plaintext in question is a
    // std::vector, so we need to truncate the decoded value.
    std::vector<double> truncated_decoded_plain(decoded_plain.begin(),decoded_plain.begin()+exactPlaintext.size());
    double norm2 = diff2Norm(exactPlaintext, truncated_decoded_plain);
    double norm3 = diff2Norm(truncated_decoded_plain, homomPlaintext);

    std::cout << "Encoding norm: " << norm2 << std::endl;
    std::cout << "Encryption norm: " << norm3 << std::endl;

    throw std::invalid_argument(buffer.str());
  }
  VERBOSE(std::cout << std::endl);
}

DebugEval::CKKSCiphertext merge_cts(const CKKSCiphertext &ct_he, const CKKSCiphertext &ct_se) const {
  CKKSCiphertext t = ct_he;
  t.copyMetadataFrom(ct_se);
  return t;
}

CKKSCiphertext DebugEval::rotate_vector_right_internal(const CKKSCiphertext &ct, int steps) {
  // recursive calls
  checkScale(ct);
  CKKSCiphertext dest_he = heEval->rotate_vector_right_internal(ct, steps);
  CKKSCiphertext dest_se = seEval->rotate_vector_right_internal(ct, steps);
  CKKSCiphertext dest = merge_cts(dest_he, dest_se);

  print_stats(dest);
  checkScale(dest);
  return dest;
}

CKKSCiphertext DebugEval::rotate_vector_left_internal(const CKKSCiphertext &ct, int steps) {
  // recursive calls
  checkScale(ct);
  CKKSCiphertext dest_he = heEval->rotate_vector_left_internal(ct, steps);
  CKKSCiphertext dest_se = seEval->rotate_vector_left_internal(ct, steps);
  CKKSCiphertext dest = merge_cts(dest_he, dest_se);

  print_stats(dest);
  checkScale(dest);
  return dest;
}

CKKSCiphertext DebugEval::add_plain_scalar_internal(const CKKSCiphertext &ct, double scalar) {
  // recursive calls
  checkScale(ct);
  CKKSCiphertext dest_he = heEval->add_plain_scalar_internal(ct, scalar);
  CKKSCiphertext dest_se = seEval->add_plain_scalar_internal(ct, scalar);
  CKKSCiphertext dest = merge_cts(dest_he, dest_se);

  print_stats(dest);
  checkScale(dest);
  return dest;
}

CKKSCiphertext DebugEval::add_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
  // recursive calls
  checkScale(ct1);
  checkScale(ct2);
  CKKSCiphertext dest_he = heEval->add_internal(ct1, ct2);
  CKKSCiphertext dest_se = seEval->add_internal(ct1, ct2);
  CKKSCiphertext dest = merge_cts(dest_he, dest_se);

  print_stats(dest);
  checkScale(dest);
  return dest;
}

CKKSCiphertext DebugEval::multiply_plain_scalar_internal(const CKKSCiphertext &ct, double scalar) {
  // recursive calls
  checkScale(ct);
  CKKSCiphertext dest_he = heEval->multiply_plain_scalar_internal(ct, scalar);
  CKKSCiphertext dest_se = seEval->multiply_plain_scalar_internal(ct, scalar);
  CKKSCiphertext dest = merge_cts(dest_he, dest_se);

  print_stats(dest);
  checkScale(dest);
  return dest;
}

CKKSCiphertext DebugEval::multiply_plain_mat_internal(const CKKSCiphertext &ct, const std::vector<double> &plain) {
  // recursive calls
  checkScale(ct);
  CKKSCiphertext dest_he = heEval->multiply_plain_mat_internal(ct, plain);
  CKKSCiphertext dest_se = seEval->multiply_plain_mat_internal(ct, plain);
  CKKSCiphertext dest = merge_cts(dest_he, dest_se);

  print_stats(dest);
  checkScale(dest);
  return dest;
}

CKKSCiphertext DebugEval::multiply_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
  // recursive calls
  checkScale(ct1);
  checkScale(ct2);
  CKKSCiphertext dest_he = heEval->multiply_internal(ct1, ct2);
  CKKSCiphertext dest_se = seEval->multiply_internal(ct1, ct2);
  CKKSCiphertext dest = merge_cts(dest_he, dest_se);

  print_stats(dest);
  checkScale(dest);
  return dest;
}

CKKSCiphertext DebugEval::square_internal(const CKKSCiphertext &ct) {
  // recursive calls
  checkScale(ct);
  CKKSCiphertext dest_he = heEval->square_internal(ct);
  CKKSCiphertext dest_se = seEval->square_internal(ct);
  CKKSCiphertext dest = merge_cts(dest_he, dest_se);

  print_stats(dest);
  checkScale(dest);
  return dest;
}

void DebugEval::modDownTo_internal(CKKSCiphertext &ct, const CKKSCiphertext &target) {
  // recursive calls
  checkScale(ct);
  checkScale(target);
  heEval->modDownTo_internal(ct, target);
  seEval->modDownTo_internal(ct, target);

  print_stats(ct);
  checkScale(ct);
}

void DebugEval::modDownToMin_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) {
  // recursive calls
  heEval->modDownToMin_internal(ct1, ct2);
  seEval->modDownToMin_internal(ct1, ct2);

  print_stats(ct1);
  print_stats(ct2);
}

CKKSCiphertext DebugEval::modDownToLevel_internal(const CKKSCiphertext &ct, int level) {
  // recursive calls
  checkScale(ct);
  CKKSCiphertext dest_he = heEval->modDownToLevel_internal(ct, level);
  CKKSCiphertext dest_se = seEval->modDownToLevel_internal(ct, level);
  CKKSCiphertext dest = merge_cts(dest_he, dest_se);

  print_stats(dest);
  checkScale(dest);
  return dest;
}

void DebugEval::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
  auto context_data = getContextData(ct);
  uint64_t p = context_data->parms().coeff_modulus().back().value();
  double prime_bit_len = log2(p);

  checkScale(ct);
  // recursive calls
  heEval->rescale_to_next_inplace_internal(ct);
  seEval->rescale_to_next_inplace_internal(ct);

  // for some reason, the default is to print doubles with no decimal places.
  // To get decimal places, add `<< fixed << std::setprecision(2)` before printing the log.
  // Note that you'll need a lot of decimal places because these values are very close
  // to an integer.
  VERBOSE(std::cout << "    + Scaled plaintext down by the ~" <<
          prime_bit_len << "-bit prime " << std::hex << p << std::dec << std::endl);

  print_stats(ct);
  checkScale(ct);
}

void DebugEval::relinearize_inplace_internal(CKKSCiphertext &ct) {
  // recursive calls
  checkScale(ct);
  heEval->relinearize_inplace_internal(ct);
  seEval->relinearize_inplace_internal(ct);

  print_stats(ct);
  checkScale(ct);
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
