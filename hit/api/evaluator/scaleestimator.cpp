// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "scaleestimator.h"
#include "../../common.h"
#include "../../sealutils.h"
#include <iomanip>

ScaleEstimator::ScaleEstimator(const std::shared_ptr<seal::SEALContext> &context, int poly_deg, double baseScale, bool verbose):
  CKKSEvaluator(context, verbose), baseScale(baseScale), poly_deg(poly_deg) {
  ptEval = new PlaintextEval(context,verbose);
  dfEval = new DepthFinder(context,verbose);
  // if scale is too close to 60, SEAL throws the error "encoded values are too large" during encoding.
  estimatedMaxLogScale = PLAINTEXT_LOG_MAX-60;
  auto context_data = context->first_context_data();
  for(const auto &prime : context_data->parms().coeff_modulus()) {
    estimatedMaxLogScale += log2(prime.value());
  }
}

ScaleEstimator::~ScaleEstimator() {
  delete dfEval;
  delete ptEval;
}

void ScaleEstimator::reset_internal() {
  estimatedMaxLogScale = PLAINTEXT_LOG_MAX-60;
  auto context_data = context->first_context_data();
  for(const auto &prime : context_data->parms().coeff_modulus()) {
    estimatedMaxLogScale += log2(prime.value());
  }
  ptEval->reset_internal();
  dfEval->reset_internal();
}

// print some debug info
void ScaleEstimator::print_stats(const CKKSCiphertext &c) {
  double exactPlaintextMaxVal = lInfNorm(c.getPlaintext());
  double logModulus = 0;
  auto context_data = getContextData(c);
  for(const auto &prime : context_data->parms().coeff_modulus()) {
    logModulus += log2(prime.value());
  }
  std::cout << "    + Plaintext logmax: " << log2(exactPlaintextMaxVal) <<
          " bits (scaled: " << log2(c.scale)+log2(exactPlaintextMaxVal) << " bits)" << std::endl;
  std::cout << "    + Total modulus size: " << std::setprecision(4) << logModulus << " bits" << std::endl;
  std::cout << "    + Theoretical max log scale: " << getEstimatedMaxLogScale() << " bits" << std::endl;
}

// At all times, we need c.scale*lInfNorm(c.getPlaintext()) <~ q/4
// Define c.scale = i*baseScale for i \in {1,2}
// If(i > c.he_level): estimatedMaxLogScale \le (PLAINTEXT_LOG_MAX-log2(lInfNorm(c.getPlaintext()))/(i-c.he_level))
// Else if (i == c.he_level): log2(lInfNorm(c.getPlaintext())) <= 58
// Else [i < c.he_level]: estimatedMaxLogScale \ge <something less than 0> [so we skip this]

void ScaleEstimator::updateMaxLogScale(const CKKSCiphertext &c) {
  // update the estimatedMaxLogScale
  int scaleExp = round(log2(c.scale)/log2(baseScale));
  if(scaleExp != 1 && scaleExp != 2) {
    std::stringstream buffer;
    buffer << "INTERNAL ERROR: scaleExp is not 1 or 2: got " << scaleExp << "\t" << log2(c.scale) << "\t" << log2(baseScale);
    throw std::invalid_argument(buffer.str());
  }
  if (scaleExp > c.he_level) {
    estimatedMaxLogScale = std::min(estimatedMaxLogScale, (PLAINTEXT_LOG_MAX-log2(lInfNorm(c.getPlaintext())))/(scaleExp-c.he_level));
  }
  else if(scaleExp == c.he_level && log2(lInfNorm(c.getPlaintext())) > PLAINTEXT_LOG_MAX) {
    std::stringstream buffer;
    buffer << "Plaintext exceeded " << PLAINTEXT_LOG_MAX << " bits, which exceeds SEAL's capacity. Overflow is imminent.";
    throw std::invalid_argument(buffer.str());
  }
  // else: scaleExp < c.he_level.
  // In this case, the constraint becomes estimatedMaxLogScale > (something less than 0).
  // this is bogus, so nothing to do.
}

CKKSCiphertext ScaleEstimator::merge_cts(const CKKSCiphertext &ct_df, const CKKSCiphertext &ct_pt) const {
  CKKSCiphertext t = ct_pt;
  t.he_level = ct_df.he_level;
  return t;
}

CKKSCiphertext ScaleEstimator::rotate_vector_right_internal(const CKKSCiphertext &ct, int steps) {
  CKKSCiphertext dest_df = dfEval->rotate_vector_right_internal(ct, steps);
  CKKSCiphertext dest_pt = ptEval->rotate_vector_right_internal(ct, steps);
  CKKSCiphertext dest = merge_cts(dest_df, dest_pt);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext ScaleEstimator::rotate_vector_left_internal(const CKKSCiphertext &ct, int steps) {
  CKKSCiphertext dest_df = dfEval->rotate_vector_left_internal(ct, steps);
  CKKSCiphertext dest_pt = ptEval->rotate_vector_left_internal(ct, steps);
  CKKSCiphertext dest = merge_cts(dest_df, dest_pt);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext ScaleEstimator::add_plain_scalar_internal(const CKKSCiphertext &ct, double scalar) {
  // recursive call up the stack
  CKKSCiphertext dest_df = dfEval->add_plain_scalar_internal(ct, scalar);
  CKKSCiphertext dest_pt = ptEval->add_plain_scalar_internal(ct, scalar);
  CKKSCiphertext dest = merge_cts(dest_df, dest_pt);

  updateMaxLogScale(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext ScaleEstimator::add_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
  // recursive call up the stack
  CKKSCiphertext dest_df = dfEval->add_internal(ct1, ct2);
  CKKSCiphertext dest_pt = ptEval->add_internal(ct1, ct2);
  CKKSCiphertext dest = merge_cts(dest_df, dest_pt);

  updateMaxLogScale(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext ScaleEstimator::multiply_plain_scalar_internal(const CKKSCiphertext &ct, double scalar) {
  // recursive call up the stack
  CKKSCiphertext dest_df = dfEval->multiply_plain_scalar_internal(ct, scalar);
  CKKSCiphertext dest_pt = ptEval->multiply_plain_scalar_internal(ct, scalar);
  CKKSCiphertext dest = merge_cts(dest_df, dest_pt);

  dest.scale *= dest.scale;
  updateMaxLogScale(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext ScaleEstimator::multiply_plain_mat_internal(const CKKSCiphertext &ct, const std::vector<double> &plain) {
  // recursive call up the stack
  CKKSCiphertext dest_df = dfEval->multiply_plain_mat_internal(ct, plain);
  CKKSCiphertext dest_pt = ptEval->multiply_plain_mat_internal(ct, plain);
  CKKSCiphertext dest = merge_cts(dest_df, dest_pt);

  double plain_max = 0;
  for(int i = 0; i < ct.height*ct.width; i++) {
    plain_max = std::max(plain_max, abs(plain[i]));
  }
  dest.scale = ct.scale * ct.scale;
  updateMaxLogScale(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext ScaleEstimator::multiply_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
  // recursive call up the stack
  CKKSCiphertext dest_df = dfEval->multiply_internal(ct1, ct2);
  CKKSCiphertext dest_pt = ptEval->multiply_internal(ct1, ct2);
  CKKSCiphertext dest = merge_cts(dest_df, dest_pt);

  dest.scale = ct1.scale * ct2.scale;
  updateMaxLogScale(dest);

  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext ScaleEstimator::square_internal(const CKKSCiphertext &ct) {
  // recursive call up the stack
  CKKSCiphertext dest_df = dfEval->square_internal(ct);
  CKKSCiphertext dest_pt = ptEval->square_internal(ct);
  CKKSCiphertext dest = merge_cts(dest_df, dest_pt);

  dest.scale *= ct.scale;
  updateMaxLogScale(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

void ScaleEstimator::modDownTo_internal(CKKSCiphertext &ct, const CKKSCiphertext &target) {

  if(ct.he_level == target.he_level && ct.scale != target.scale) {
    throw std::invalid_argument("modDownTo: levels match, but scales do not.");
  }

  // recursive call up the stack
  dfEval->modDownTo_internal(ct, target);
  ptEval->modDownTo_internal(ct, target);

  ct.scale = target.scale;

  // recursive call updated he_level, so we need to update maxLogScale
  updateMaxLogScale(ct);
  VERBOSE(print_stats(ct));
}

void ScaleEstimator::modDownToMin_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) {
  if(ct1.he_level == ct2.he_level && ct1.scale != ct2.scale) {
    throw std::invalid_argument("modDownToMin: levels match, but scales do not.");
  }

  if(ct1.he_level > ct2.he_level) {
    ct1.scale = ct2.scale;
  }
  else {
    ct2.scale = ct1.scale;
  }

  // recursive call up the stack
  dfEval->modDownToMin_internal(ct1, ct2);
  ptEval->modDownToMin_internal(ct1, ct2);

  // recursive call updated he_level, so we need to update maxLogScale
  updateMaxLogScale(ct1);
  updateMaxLogScale(ct2);
  VERBOSE(print_stats(ct1));
  VERBOSE(print_stats(ct2));
}

CKKSCiphertext ScaleEstimator::modDownToLevel_internal(const CKKSCiphertext &ct, int level) {
  int lvlDiff = ct.he_level-level;

  if(level < 0) {
    throw std::invalid_argument("modDownToLevel: level must be >= 0.");
  }

  // recursive call up the stack
  CKKSCiphertext dest_df = dfEval->modDownToLevel_internal(ct, level);
  CKKSCiphertext dest_pt = ptEval->modDownToLevel_internal(ct, level);
  CKKSCiphertext dest = merge_cts(dest_df, dest_pt);

  // reset he_level for dest
  dest.he_level += lvlDiff;
  while(dest.he_level > level) {
    uint64_t p = getLastPrime(context, dest.he_level);
    dest.he_level--;
    dest.scale = (dest.scale*dest.scale)/p;
  }
  // dest's level is now reset to level

  // recursive call updated he_level, so we need to update maxLogScale
  updateMaxLogScale(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

void ScaleEstimator::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
  // get the last prime *before* making any recursive calls.
  // in particular, the DepthFinder call will change the he_level
  // of the ciphertext, causing `getContextData` to get the wrong
  // prime, resulting in mayhem.
  auto context_data = getContextData(ct);
  uint64_t p = context_data->parms().coeff_modulus().back().value();

  // recursive call up the stack
  dfEval->rescale_to_next_inplace_internal(ct);
  ptEval->rescale_to_next_inplace_internal(ct);

  ct.scale /= p;
  updateMaxLogScale(ct);
  VERBOSE(print_stats(ct));
}

void ScaleEstimator::relinearize_inplace_internal(CKKSCiphertext &) {}

void ScaleEstimator::updatePlaintextMaxVal(double x) {
  // account for a freshly-ct ciphertext
  // if this is a depth-0 computation *AND* the parameters are such that it is a no-op,
  // this is the only way we can account for the values in the input. We have to encrypt them,
  // and if the scale is ~2^60, encoding will (rightly) fail
  int topHELevel = context->first_context_data()->chain_index();
  if (topHELevel == 0) {
    estimatedMaxLogScale = std::min(estimatedMaxLogScale, (PLAINTEXT_LOG_MAX-log2(x)));
  }
}

double ScaleEstimator::getExactMaxLogPlainVal() const {
  return ptEval->getExactMaxLogPlainVal();
}

double ScaleEstimator::getEstimatedMaxLogScale() const {
  /* During the evaluation, updateMaxLogScale computed the maximum scale
   * implied by the "correctness" constraint (to prevent the computation
   * from overflowing). But there is another constraint: SEAL limits the
   * maximum size of the modulus (in bits) based on the poly_modulus_degree.
   * We take that constraint into account when reporting the maximum log(scale).
   *
   * Specifically, a SEAL modulus is the product of k primes p_i, where
   * log2(p_1)=log2(p_k)=60 and log2(p_i)=s=log(scale). Thus s must be less
   * than (maxModBits-120)/(k-2)
   */
  int maxModBits = polyDegreeToMaxModBits(poly_deg);
  int topHELevel = context->first_context_data()->chain_index();

  double estimated_log_scale = std::min(static_cast<double>(PLAINTEXT_LOG_MAX),estimatedMaxLogScale);
  if(topHELevel > 0) {
    return std::min(estimated_log_scale, (maxModBits-120)/static_cast<double>(topHELevel));
  }
  return estimated_log_scale;
}
