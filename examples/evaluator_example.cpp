// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/api/evaluator.h"
#include "hit/api/evaluator/homomorphic.h"
#include "hit/api/evaluator/plaintext.h"
#include "hit/api/evaluator/depthfinder.h"
#include "hit/api/evaluator/opcount.h"
#include "hit/api/evaluator/scaleestimator.h"
#include "hit/api/evaluator/debug.h"

#include "hit/common.h"
#include <iostream>
#include <glog/logging.h>

using namespace std;
using namespace hit;

/* This file provides a demonstration of how to use this CKKS library and its many evaluators. */

/* The HIT library provides an interface for low-level homomorphic operations
 * like addition and multiplication. Higher level functions are composed of
 * these primitive operations. As an example, we will demonstrate how to
 * evaluate a polynomial homomorphically. This is a useful technique in HE
 * because polynomials are relatively simple to evaluate compared to
 * non-polynomial functions. Specifically, we will compute a degree-3
 * approximation to the sigmoid function. The function will be applied to each
 * plaintext slot independently. The real function is \sigma(x) = 1/(1+e^{-x}).
 * We instead use a least-squares cubic polynomial approximation
 * \sigma'(x) = -0.0015x^3 + 0.15x + 0.5.
 * The code below is strongly inspired by the SEAL example 4_ckks_basics.cpp.
 *
 * We compute the approximation using the following circuit:
 *
 *  Lvl                                                                    Scale
 *   i      x     x      x       -0.0015    x      0.15                      s
 *           \   /        \         /        \      /
 *  i-1       x^2          -0.0015*x          0.15*x       1               s^2/p_i
 *             \              /                \          /
 *              \            /                  \        /
 *               \          /                    \      /
 *  i-2           -0.0015*x^3                     0.15*x            (s^2/p_i)^2/p_{i-1}
 *                     \                            /
 *                      \                          /
 *                       \                        /
 *                        \                      /
 *                         \                    /
 *                          \                  /
 *  i-2                      -0.0015*x^3+0.15*x            0.5      (s^2/p_i)^2/p_{i-1}
 *                                \                        /
 *                                 \                      /
 *  i-2                             -0.0015*x^3+0.15*x+0.5          (s^2/p_i)^2/p_{i-1}
 *
 * Inputs to addition or multiplication must be at the same level
 * of the tree. Constants can be inserted at any level of the tree.
 * Multiplication (even by a constant) consumes a level, while addition
 * never consumes a level.
 *
 * ASSUMPTIONS:
 *  - x1_encrypted is a linear ciphertext
 *
 * CONSUMES TWO HE LEVELS
 */
const double sigmoid_c3 = -0.0002;
const double sigmoid_c1 = 0.0843;
const double sigmoid_c0 = 0.5;
// the cubic is a good approximation to sigmoid on the range [-approxRange,approxRange]
const int approxRange = 16;

CKKSCiphertext sigmoid(const CKKSCiphertext &x1_encrypted, CKKSEvaluator &eval) {

  // x2 means x^2
  CKKSCiphertext x2_encrypted = eval.square(x1_encrypted);
  /* Multiplying two ciphertexts results in a quadratic ciphertext.
   * We need to relinearize before continuing.
   */
  eval.relinearize_inplace(x2_encrypted);

  /* The multiplication also squared the *scale factor* on the plaintext.
   * We need to reduce this by "rescaling". In addition to a modulus switch,
   * rescaling reduces the plaintext scale by a factor equal to the prime that
   * was switched away. If we've chosen our params correctly, this should bring
   * the scale close to the scale of x1_encrypted.
   */
  eval.rescale_to_next_inplace(x2_encrypted);

  /* Now x2_encrypted is at a different level than x1_encrypted, which prevents us
   * from multiplying them to compute x^3. Since we still
   * need to multiply the x^3 term with 0.0015, we compute 0.0015*x
   * first and multiply that with x^2 to obtain 0.0015*x^3. The reason is that
   * multiplying x1 by a scalar *also* requires a mod switch to reduce the scale,
   * which will bring -0.0015*x and x^2 to the same levels.
   */
  // coeff3_x1_encrypted is sigmoid_c3*x^1
  CKKSCiphertext coeff3_x1_encrypted = eval.multiply_plain(x1_encrypted, sigmoid_c3);
  eval.rescale_to_next_inplace(coeff3_x1_encrypted);

  /* Since x2_encrypted and coeff3_x1_encrypted have the same exact scale and use
   * the same encryption parameters, we can multiply them together. We write the
   * result to coeff3_x3_encrypted, relinearize, and rescale. Note that
   * coeff3_x3_encrypted has been scaled down twice relative to x1_encrypted.
   */
  // coeff3_x3_encrypted is sigmoid_c3*x^3
  CKKSCiphertext coeff3_x3_encrypted = eval.multiply(x2_encrypted, coeff3_x1_encrypted);
  eval.relinearize_inplace(coeff3_x3_encrypted);
  eval.rescale_to_next_inplace(coeff3_x3_encrypted);

  /* Next we compute the degree one term. All this requires is one multiply_plain
   * with 0.15.
   */
  // coeff1_x1_encrypted is sigmoid_c1*x^1
  CKKSCiphertext coeff1_x1_encrypted = eval.multiply_plain(x1_encrypted, sigmoid_c1);
  eval.rescale_to_next_inplace(coeff1_x1_encrypted);

  /* coeff3_x3_encrypted is at level i-2, while coeff1_x1_encrypted is at level i-1.
   * We need to add these two terms together, but that requires them to be at the same
   * level. We solve this problem by multiplying coeff1_x1_encrypted by the scalar 1.
   */
  eval.reduce_level_to_inplace(coeff1_x1_encrypted, coeff3_x3_encrypted.he_level());

  // add 0.5 and 0.15*x
  CKKSCiphertext result = eval.add_plain(coeff1_x1_encrypted, sigmoid_c0);

  // add 0.0015*x^3 with result
  return eval.add(result, coeff3_x3_encrypted);;
}

vector<double> random_vector(int dim, double maxNorm) {
    vector<double> x;
    x.reserve(dim);

    for (int i = 0; i < dim; i++) {
        // generate a random double between -maxNorm and maxNorm
        double a = -maxNorm + ((static_cast<double>(random())) / (static_cast<double>(RAND_MAX))) * (2 * maxNorm);
        x.push_back(a);
    }
    return x;
}

/* Now that we have written a function, let's evaluate it. */
int main(int, char **argv) {// NOLINT(bugprone-exception-escape)
  // Initialize Google's logging library.
  google::InitGoogleLogging(argv[0]);
  // Dump useful information when the program crashes on certain signals such as SIGSEGV.
  google::InstallFailureSignalHandler();

  // *********** Generate Random Input ***********
  /* Generate a random input and compute the expecte result
   * of applying the sigmoid approximation to each component
   */
  srand(time(nullptr));
  int slots = 4096;
  LOG(INFO) << "Generating random input vector of length " << slots << "...";
  vector<double> x = random_vector(slots, approxRange);

  // *********** Generate Expected Result ***********
  LOG(INFO) << "Generating expected result...";
  vector<double> exactResult;
  exactResult.reserve(slots);
  for(int i = 0; i < slots; i++) {
    // compute the expected result
    double y = x[i];
    double sigx = sigmoid_c3*y*y*y+sigmoid_c1*y+sigmoid_c0;
    exactResult.push_back(sigx);
  }


  // *********** Verify Correctness of Homomorphic Algorithm ***********
  /* The algorithm for computing the sigmoid approximation homomorphically
   * is quite different from how you would compute this approximation in
   * the clear: compare the `for` loop above to the `sigmoid` function,
   * they don't look very similar! Since `sigmoid` is so complex, we should
   * check that it computes the right thing. Rather than doing a the
   * computation on ciphertexts, which introduces additional complexity and
   * opportunites for possible errors, we can just run the homomorphic
   * algorithm directly on plaintexts. It should give us the expected answer!
   *
   * Create a CKKSInstance that holds a Plaintext evaluator. This will cause
   * ciphertexts to hold a "shadow" plaintext, and the evaluator will perform
   * the operation on this shadow plaintext rather than on the ciphertext.
   * Creating the instance requires the desired number of plaintext slots,
   * which must be a power of two.
   * With this evaluator, there are no ciphertexts involved, so the computation
   * is relatively fast.
   */
  /* We treat our input as a column vector, but we need to encode it into a
   * CKKS plaintext. We will target a plaintext with dimension 4096, which
   * means will encode the vector as a 32x128 matrix.
   */
  LOG(INFO) << "Using the Plaintext evaluator to test the correctness of the algorithm...";
  PlaintextEval ptInst = PlaintextEval(slots);
  // Encode and encrypt the input
  CKKSCiphertext x_enc_pt;
  x_enc_pt = ptInst.encrypt(x);
  // Evaluate the function with the Plaintext evaluator,
  // and assign the result to x_enc_pt
  x_enc_pt = sigmoid(x_enc_pt, ptInst);
  // Compare the plaintext inside x_enc_pt to the expected result
  // getPlaintext() decodes the shadow plaintext
  double errNorm = diff2_norm(exactResult, x_enc_pt.plaintext());
  if(errNorm < 0.0001) {
    LOG(INFO) << "\tHomomorphic algorithm matches cleartext algorithm.";
  }
  else {
    throw invalid_argument("Results from homomorphic and cleartext algorithms do not match!");
  }


  // *********** Compute Multiplicative Depth ***********
  /* Before we can run the algorithm on encrypted inputs, we have to know
   * what encryption parameters to use. The first parameter we need is the
   * multiplicative depth of the `sigmoid` algorithm.
   * I spent a lot of time drawing the diagram above sigmoid and carefully
   * computing its multiplicative depth. This is a very
   * tedious process, and you have to redo it if you make any changes to the
   * algorithm. Thus it's best left to a computer. To compute the
   * multiplicative depth of the function, we use the DepthFinder evaluator
   * We construct a CKKSInstance using the basic constructor, which contains
   * a DepthFinder evaluator.
   */
  LOG(INFO) << "Using the DepthFinder evaluator to compute the multiplicative depth of the sigmoid function...";
  DepthFinder dfInst = DepthFinder();
  // Encrypt the input
  CKKSCiphertext x_enc_df;
  /* Re-encrypt the input, for two reasons. The first is that
   * we over-wrote x_enc_pt. The second is that the Plaintext
   * encryptor may not initialize all of the values needed by
   * the DepthFinder evaluator, since the two evaluators are
   * independent.
   */
  x_enc_df = dfInst.encrypt(x);
  // Evaluate the function with the DepthFinder evaluator,
  // and assign the result to x_enc_df
  x_enc_df = sigmoid(x_enc_df, dfInst);
  // Obtain the multiplicative depth
  int multDepth = dfInst.get_multiplicative_depth();
  // Note that the multiplicative depth is two less than the required number of primes.
  // This is because SEAL requires a "special" modulus that doesn't count towards the
  // depth, and you always have to have at least one modulus.
  LOG(INFO) << "\tMultiplicative depth=" << multDepth;


  // *********** Compute Scale Factor ***********
  /* The next parameter we need for the homomorphic computation is the scale
   * factor. If the scale factor is too large, the computation will overflow,
   * and the result will be random noise. If the scale factor is smaller than
   * strictly necessary, we give up precision of the answer, and again, it can
   * be inaccurate. If the scale factor is much too small, the answer signal
   * can be overwhelmed by the noise in the computation, making it just as bad
   * as choosing too large of a scale factor.
   * The scale factor is determined by
   *  1) The maximum (absolute) value of the input
   *  2) The function you are computing
   * Rather that take all of these factors into consideration, it's again
   * best to let the computer do the work. We'll construct a new CKKSInstance
   * and run the computation a third time on the plaintext. Note that this
   * step requires knowledge of the multiplicative depth of the computation,
   * so it must be run serially after the DepthFinder step.
   */
  LOG(INFO) << "Using the ScaleEstimator evaluator to compute the optimal CKKS scale factor...";
  ScaleEstimator scaleInst = ScaleEstimator(slots, multDepth);
  // Re-encrypt the input
  CKKSCiphertext x_enc_scale;
  x_enc_scale = scaleInst.encrypt(x);
  // Evaluate the function with the ScaleEstimator evaluator,
  // and assign the result to x_enc_scale
  x_enc_scale = sigmoid(x_enc_scale, scaleInst);
  // Obtain the multiplicative depth
  int logScale = floor(scaleInst.get_estimated_max_log_scale());
  LOG(INFO) << "\tThe maximum possible scale for this input is 2^" << logScale;


  // *********** Once more, with Encrypted Inputs ***********
  /* Armed with the requisite encryption parameters, we can now
   * construct a evaluator that works on encrypted inputs.
   */
  LOG(INFO) << "Running the computation on ciphertexts...";
  HomomorphicEval homomInst = HomomorphicEval(slots, multDepth, logScale, true);
  // Re-encrypt the input
  CKKSCiphertext x_enc_homom;
  x_enc_homom = homomInst.encrypt(x);
  // Evaluate the function with the Normal homomorphic evaluator,
  // and assign the result to x_enc_homom
  x_enc_homom = sigmoid(x_enc_homom, homomInst);
  // Decrypt the result
  vector<double> homom_result = homomInst.decrypt(x_enc_homom);
  // See if the test passed
  double errNorm_homom = diff2_norm(exactResult, homom_result);
  if(errNorm_homom < 0.0001) {
    LOG(INFO) << "\tHomomorphic result matches cleartext result.";
  }
  else {
    throw invalid_argument("Check your CKKS parameters and try again!");
  }


  // *********** View Debug Output ***********
  /* If anything fails, or if you want to see more details about your
   * computation, use the debug evaluator. By defining environment variable 'GLOG_v=1', it provides verbose output
   * regarding all aspects of the computation in real-time.
   */
  LOG(INFO) << "Running the computation in debug mode...";
  DebugEval debugInst = DebugEval(slots, multDepth, logScale, true);
  // Re-encrypt the input
  CKKSCiphertext x_enc_debug;
  x_enc_debug = debugInst.encrypt(x);
  // Evaluate the function with the Normal homomorphic evaluator,
  // and assign the result to x_enc_debug
  x_enc_debug = sigmoid(x_enc_debug, debugInst);
  // No need to do anything here; the output is printed during
  // evaluation.


  /* *********** Evaluator Heierarchy ***********
   *
   *                      CKKSEvaluator (Base class for all evaluators)
   *                     /      |      \
   *                    /       |       \
   *                   /        |        \
   *                  /         |         \
   *         Homomorphic    Plaintext    DepthFinder
   *               \            \            /
   *                \            \          /
   *                 \            \        /
   *                  \         ScaleEstimator
   *                   \               /
   *                    \             /
   *                     \           /
   *                      \         /
   *                       \       /
   *                        \     /
   *                         Debug
   *
   * This diagram shows the relationship between the evaluators. Note that this
   * shows their logical relationship; the actual OOP inheritance is different
   * (and not important). The example
   * uses all five to show how they work, but in practice, you may use fewer
   * than that. For example, you can check the plaintext result using the
   * Plaintext evaluator, the ScaleEstimator evaluator, or the Debug
   * evaluator. Since you may be using the ScaleEstimator already, there's
   * no need for a separate Plaintext evaluator.
   */
}
