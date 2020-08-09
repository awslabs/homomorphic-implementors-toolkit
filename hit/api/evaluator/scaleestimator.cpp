// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "scaleestimator.h"
#include "../../common.h"
#include "../../sealutils.h"
#include <iomanip>

using namespace std;
using namespace seal;

ScaleEstimator::ScaleEstimator(const shared_ptr<SEALContext> c, int poly_deg, double baseScale, bool verbose):
  CKKSEvaluator(c, verbose), baseScale(baseScale), poly_deg(poly_deg) {
  ptEval = new PlaintextEval(c,verbose);
  dfEval = new DepthFinder(c,verbose);
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
  cout << "    + Plaintext logmax: " << log2(exactPlaintextMaxVal) <<
          " bits (scaled: " << log2(c.scale)+log2(exactPlaintextMaxVal) << " bits)" << endl;
  cout << "    + Total modulus size: " << setprecision(4) << logModulus << " bits" << endl;
  cout << "    + Theoretical max log scale: " << getEstimatedMaxLogScale() << " bits" << endl;
}

// At all times, we need c.scale*lInfNorm(c.getPlaintext()) <~ q/4
// Define c.scale = i*baseScale for i \in {1,2}
// If(i > c.heLevel): estimatedMaxLogScale \le (PLAINTEXT_LOG_MAX-log2(lInfNorm(c.getPlaintext()))/(i-c.heLevel))
// Else if (i == c.heLevel): log2(lInfNorm(c.getPlaintext())) <= 58
// Else [i < c.heLevel]: estimatedMaxLogScale \ge <something less than 0> [so we skip this]

void ScaleEstimator::updateMaxLogScale(const CKKSCiphertext &c) {
  // update the estimatedMaxLogScale
  int scaleExp = round(log2(c.scale)/log2(baseScale));
  if(scaleExp != 1 && scaleExp != 2) {
    stringstream buffer;
    buffer << "INTERNAL ERROR: scaleExp is not 1 or 2: got " << scaleExp << "\t" << log2(c.scale) << "\t" << log2(baseScale);
    throw invalid_argument(buffer.str());
  }
  if (scaleExp > c.heLevel) {
    estimatedMaxLogScale = min(estimatedMaxLogScale, (PLAINTEXT_LOG_MAX-log2(lInfNorm(c.getPlaintext())))/(scaleExp-c.heLevel));
  }
  else if(scaleExp == c.heLevel && log2(lInfNorm(c.getPlaintext())) > PLAINTEXT_LOG_MAX) {
    stringstream buffer;
    buffer << "Plaintext exceeded " << PLAINTEXT_LOG_MAX << " bits, which exceeds SEAL's capacity. Overflow is imminent.";
    throw invalid_argument(buffer.str());
  }
  // else: scaleExp < c.heLevel.
  // In this case, the constraint becomes estimatedMaxLogScale > (something less than 0).
  // this is bogus, so nothing to do.
}

CKKSCiphertext ScaleEstimator::merge_cts(const CKKSCiphertext &df_output, const CKKSCiphertext &pt_output) const {
  CKKSCiphertext t = pt_output;
  t.heLevel = df_output.heLevel;
  return t;
}

CKKSCiphertext ScaleEstimator::rotate_vector_right_internal(const CKKSCiphertext &encrypted, int steps) {
  CKKSCiphertext dest_df = dfEval->rotate_vector_right_internal(encrypted, steps);
  CKKSCiphertext dest_pt = ptEval->rotate_vector_right_internal(encrypted, steps);
  CKKSCiphertext dest = merge_cts(dest_df, dest_pt);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext ScaleEstimator::rotate_vector_left_internal(const CKKSCiphertext &encrypted, int steps) {
  CKKSCiphertext dest_df = dfEval->rotate_vector_left_internal(encrypted, steps);
  CKKSCiphertext dest_pt = ptEval->rotate_vector_left_internal(encrypted, steps);
  CKKSCiphertext dest = merge_cts(dest_df, dest_pt);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext ScaleEstimator::add_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) {
  // recursive call up the stack
  CKKSCiphertext dest_df = dfEval->add_plain_scalar_internal(encrypted, plain);
  CKKSCiphertext dest_pt = ptEval->add_plain_scalar_internal(encrypted, plain);
  CKKSCiphertext dest = merge_cts(dest_df, dest_pt);

  updateMaxLogScale(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext ScaleEstimator::add_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) {
  // recursive call up the stack
  CKKSCiphertext dest_df = dfEval->add_internal(encrypted1, encrypted2);
  CKKSCiphertext dest_pt = ptEval->add_internal(encrypted1, encrypted2);
  CKKSCiphertext dest = merge_cts(dest_df, dest_pt);

  updateMaxLogScale(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext ScaleEstimator::multiply_plain_scalar_internal(const CKKSCiphertext &encrypted, double plain) {
  // recursive call up the stack
  CKKSCiphertext dest_df = dfEval->multiply_plain_scalar_internal(encrypted, plain);
  CKKSCiphertext dest_pt = ptEval->multiply_plain_scalar_internal(encrypted, plain);
  CKKSCiphertext dest = merge_cts(dest_df, dest_pt);

  dest.scale *= dest.scale;
  updateMaxLogScale(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext ScaleEstimator::multiply_plain_mat_internal(const CKKSCiphertext &encrypted, const vector<double> &plain) {
  // recursive call up the stack
  CKKSCiphertext dest_df = dfEval->multiply_plain_mat_internal(encrypted, plain);
  CKKSCiphertext dest_pt = ptEval->multiply_plain_mat_internal(encrypted, plain);
  CKKSCiphertext dest = merge_cts(dest_df, dest_pt);

  double plain_max = 0;
  for(int i = 0; i < encrypted.height*encrypted.width; i++) {
    plain_max = max(plain_max, abs(plain[i]));
  }
  dest.scale = encrypted.scale * encrypted.scale;
  updateMaxLogScale(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext ScaleEstimator::multiply_internal(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) {
  // recursive call up the stack
  CKKSCiphertext dest_df = dfEval->multiply_internal(encrypted1, encrypted2);
  CKKSCiphertext dest_pt = ptEval->multiply_internal(encrypted1, encrypted2);
  CKKSCiphertext dest = merge_cts(dest_df, dest_pt);

  dest.scale = encrypted1.scale * encrypted2.scale;
  updateMaxLogScale(dest);

  VERBOSE(print_stats(dest));
  return dest;
}

CKKSCiphertext ScaleEstimator::square_internal(const CKKSCiphertext &ciphertext) {
  // recursive call up the stack
  CKKSCiphertext dest_df = dfEval->square_internal(ciphertext);
  CKKSCiphertext dest_pt = ptEval->square_internal(ciphertext);
  CKKSCiphertext dest = merge_cts(dest_df, dest_pt);

  dest.scale *= ciphertext.scale;
  updateMaxLogScale(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

void ScaleEstimator::modDownTo_internal(CKKSCiphertext &x, const CKKSCiphertext &target) {

  if(x.heLevel == target.heLevel && x.scale != target.scale) {
    throw invalid_argument("modDownTo: levels match, but scales do not.");
  }

  // recursive call up the stack
  dfEval->modDownTo_internal(x, target);
  ptEval->modDownTo_internal(x, target);

  x.scale = target.scale;

  // recursive call updated heLevel, so we need to update maxLogScale
  updateMaxLogScale(x);
  VERBOSE(print_stats(x));
}

void ScaleEstimator::modDownToMin_internal(CKKSCiphertext &x, CKKSCiphertext &y) {
  if(x.heLevel == y.heLevel && x.scale != y.scale) {
    throw invalid_argument("modDownToMin: levels match, but scales do not.");
  }

  if(x.heLevel > y.heLevel) {
    x.scale = y.scale;
  }
  else {
    y.scale = x.scale;
  }

  // recursive call up the stack
  dfEval->modDownToMin_internal(x, y);
  ptEval->modDownToMin_internal(x, y);

  // recursive call updated heLevel, so we need to update maxLogScale
  updateMaxLogScale(x);
  updateMaxLogScale(y);
  VERBOSE(print_stats(x));
  VERBOSE(print_stats(y));
}

CKKSCiphertext ScaleEstimator::modDownToLevel_internal(const CKKSCiphertext &x, int level) {
  int lvlDiff = x.heLevel-level;

  if(level < 0) {
    throw invalid_argument("modDownToLevel: level must be >= 0.");
  }

  // recursive call up the stack
  CKKSCiphertext dest_df = dfEval->modDownToLevel_internal(x, level);
  CKKSCiphertext dest_pt = ptEval->modDownToLevel_internal(x, level);
  CKKSCiphertext dest = merge_cts(dest_df, dest_pt);

  // reset heLevel for dest
  dest.heLevel += lvlDiff;
  while(dest.heLevel > level) {
    uint64_t p = getLastPrime(context, dest.heLevel);
    dest.heLevel--;
    dest.scale = (dest.scale*dest.scale)/p;
  }
  // dest's level is now reset to level

  // recursive call updated heLevel, so we need to update maxLogScale
  updateMaxLogScale(dest);
  VERBOSE(print_stats(dest));
  return dest;
}

void ScaleEstimator::rescale_to_next_inplace_internal(CKKSCiphertext &encrypted) {
  // get the last prime *before* making any recursive calls.
  // in particular, the DepthFinder call will change the heLevel
  // of the ciphertext, causing `getContextData` to get the wrong
  // prime, resulting in mayhem.
  auto context_data = getContextData(encrypted);
  uint64_t p = context_data->parms().coeff_modulus().back().value();

  // recursive call up the stack
  dfEval->rescale_to_next_inplace_internal(encrypted);
  ptEval->rescale_to_next_inplace_internal(encrypted);

  encrypted.scale /= p;
  updateMaxLogScale(encrypted);
  VERBOSE(print_stats(encrypted));
}

void ScaleEstimator::relinearize_inplace_internal(CKKSCiphertext &) {}

void ScaleEstimator::updatePlaintextMaxVal(double x) {
  // account for a freshly-encrypted ciphertext
  // if this is a depth-0 computation *AND* the parameters are such that it is a no-op,
  // this is the only way we can account for the values in the input. We have to encrypt them,
  // and if the scale is ~2^60, encoding will (rightly) fail
  int topHELevel = context->first_context_data()->chain_index();
  if (topHELevel == 0) {
    estimatedMaxLogScale = min(estimatedMaxLogScale, (PLAINTEXT_LOG_MAX-log2(x)));
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

  if(topHELevel > 0) {
    return min((double)PLAINTEXT_LOG_MAX, min(estimatedMaxLogScale, (maxModBits-120)/(double)topHELevel));
  }
  else {
    return min((double)PLAINTEXT_LOG_MAX,estimatedMaxLogScale);
  }
}
