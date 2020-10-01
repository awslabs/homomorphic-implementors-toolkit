// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/hit.h"
#include <glog/logging.h>

using namespace std;
using namespace hit;

// defined in example_1_ckks.cpp
extern vector<double> random_vector(int dim, double maxNorm);
// defined in example_2_plaintext.cpp
extern vector<double> poly_eval_plaintext(vector<double> xs);
extern CKKSCiphertext poly_eval_homomorphic_v1(CKKSEvaluator &eval, CKKSCiphertext &ct);

/* In the previous example, we saw how to use HIT to validate that a circuit
 * works correctly on plaintexts. While that is a good start, the point of
 * homomorphic circuit design is to evaluate the circuit on ciphertexts! To
 * do that, we need cryptosystem parameters. HIT demystifies the process of
 * selecting encryption system parameters by providing evaluators which
 * compute suggested encryption parameters. HIT does help a bit in this area:
 * if the requested depth and scale are not compatible with the requested number
 * of slots, HIT will throw a runtime error when trying to make a CKKS instance
 * indicating that a larger plaintext must be used.
 *
 *
 * ******** Plaintext Slots ********
 * It's up to the user to determine the number of plaintext slots that should
 * be in each ciphertext. A smaller number of slots results in better performance,
 * but, as noted in Example 1, limits the size of the ciphertext modulus, which
 * in turn limits the precision of the computation and/or the depth of circuits
 * which can be evaluated. Thus, to evaluate deeper circuits, evaluate with
 * more precision, or to pack more plaintext slots into a single ciphertext, you
 * can increase the number of plaintext slots.
 *
 *
 * ******** Circuit Depth ********
 * The first paramter we will need to determine is the maximum circuit depth
 * we should support. If this depth is too low, we will not be able to evaluate
 * our target function. If the maximum circuit depth is unnecessarily large, we
 * risk either having to reduce the scale (and thus the precision of the result)
 * or increasing the number of plaintext slots, which dramatically decreases
 * performance. One way to compute circuit depth is to carefully track the levels
 * of each ciphertext in the computation, as we have done in the comments in
 * `poly_eval_homomorphic_v1()`. From that we can see the input has level i,
 * and the output has level i-3, so the multiplicative depth of the circuit is three.
 * However, this manual tracking quickly gets out of hand:
 *  - It's difficult to track and record these levels in the first place
 *  - If we made an error in the circuit, we may have to update the levels of
 *    ciphertexts throughout the circuit.
 *  - Manually tracking ciphertext levels only works for small circuits,
 *    it's infeasible for large circuits.
 * Instead, we will use HIT's `DepthFinder` instance type to compute the depth
 * of the function we want to evaluate.
 */
void example_3_driver() {
	int num_slots = 8192;

	// Create a CKKS instance to compute circuit depth. This instance type needs _no_ parameters.
	DepthFinder df_inst = DepthFinder();

	// Generate a plaintext with `num_slots` random coefficients, each with absolute value < `plaintext_inf_norm`
	int plaintext_inf_norm = 10;
	vector<double> plaintext = random_vector(num_slots, plaintext_inf_norm);

	// Encrypt the plaintext. This evaluator only tracks ciphertext metadata;
	// the CKKSCiphertext does not contain a real ciphertext or the plaintext.
	CKKSCiphertext df_ciphertext = df_inst.encrypt(plaintext);

	// Now we can evaluate our homomorphic circuit on this input, ignoring the output
	// While evaluating this circuit, the DepthFinder instance emits logs indicating the level
	// of the output of each gate, which can be seen <TODO>
	poly_eval_homomorphic_v1(df_inst, df_ciphertext);

	// Finally, we can ask the evaluator for the circuit's depth.
	int max_depth = df_inst.get_multiplicative_depth();
	LOG(INFO) << "poly_eval_homomorphic_v1 has multiplicative depth " << max_depth;

/* ******** CKKS Scale ********
 * The next parameter we will need is the CKKS scale. You should use the largest scale
 * possible, since it results in the most precision in the homomorphic computation.
 * The scale is bounded above because the scaled plaintext can never exceed the
 * ciphertext modulus, otherwise the plaintext wraps around the modulus and is lost.
 * Imagine a ciphertext at level 0. SEAL recommends a 60-bit ciphertext
 * modulus at this level, so in order to avoid overflow, we must satisfy inf_norm(plaintext)*scale < 2^60.
 * By evaluating the circuit on a representative plaintext, we can get a good idea of the
 * maximum scale.
 */

	// Assume that the plaintext generated above is representative.
	// The ScaleEstimator instance type requires the maximum depth of the circuits which
	// will be evaluated, so we pass in the value computed with the DepthFinder instance.
	ScaleEstimator se_inst = ScaleEstimator(num_slots, max_depth);

	// Don't reuse ciphertexts between instance types!
	CKKSCiphertext se_ciphertext = se_inst.encrypt(plaintext);

	// Now we can evaluate our homomorphic circuit on this input, ignoring the output
	// While evaluating this circuit, the ScaleEstimator instance emits logs for the maximum
	// plaintext value, number of ciphertext modulus bits, and estimated max log scale at
	// the output of each gate. This logging can be enabled by setting <TODO>
	poly_eval_homomorphic_v1(se_inst, se_ciphertext);

	// After evaluating the circuit on the representative input, we can ask the
	// ScaleEstimator to estimate the maximum log scale we can use with ciphertexts.
	int log_scale = se_inst.get_estimated_max_log_scale();

/* ******** Ciphertext Evaluation ********
 * Having used HIT to help determine the circuit depth and the maximum scale
 * we can use, we can now set up an instance which actually does homomorphic
 * computation.
 */
	HomomorphicEval he_inst = HomomorphicEval(num_slots, max_depth, log_scale);

	// Don't reuse ciphertexts between instance types!
	CKKSCiphertext he_ciphertext = he_inst.encrypt(plaintext);

	// Now we can evaluate our homomorphic circuit on this input
	CKKSCiphertext ct_result = poly_eval_homomorphic_v1(he_inst, he_ciphertext);

	vector<double> actual_result = he_inst.decrypt(ct_result);

	// Next, we will evaluate the plaintext function on the plaintext input
	vector<double> expected_result = poly_eval_plaintext(plaintext);

	// Compute the |expected-actual|/|expected|, where |*| denotes the 2-norm.
	// If this value is small, then the expected and actual results closely agree,
	// up to floating point roundoff (note that since the PlaintextEval only operates on
	// plaintexts, there is no CKKS noise to introduce additional error.)
	LOG(INFO) << "Relative difference between input and decrypted output: " << relative_error(expected_result, actual_result);

/* ******** Debug Evaluator ********
 * Notice that this is subtley different than what we did in Example 2: here we are comparing
 * the plaintext computation to the *encrypted* computation. Even if the difference between
 * the two vectors was small in Example 2, they may not be here! There are several ways in
 * which a circuit which works on plaintext values may fail on ciphertexts. For instance,
 * the plaintext value may become too large and wrap around the ciphertext modulus,
 * producing a random output on decryption. Because our function passes a test with the
 * PlaintextEval instance, we know that the algorithm is mostly correct, but we've got some
 * problems *only* due to the details of CKKS homomorphic encryption. This narrows down the
 * search space for the error. However, we now need a way to look at the value inside plaintexts
 * *as the encrypted computation proceeds*. The PlaintextEval instance can't do this for us; it
 * does not do any homomorhic computation, and the HomomorphicEval instance doesn't allow us to
 * see inside the ciphertexts. Instead, we should run the comptuation with the DebugEval instance.
 * This runs the homomorphic comptutation in parallel with the plaintext computation, and compares
 * the plaintext computation to the decrypted homomorphic computation at each gate. This allows you
 * to pinpoint exactly where the homomorphic computation went off the rails. You use the DebugEval
 * instance just like the HomomorphicEval instance.
 */
	DebugEval dbg_inst = DebugEval(num_slots, max_depth, log_scale);

	// Don't reuse ciphertexts between instance types!
	CKKSCiphertext dbg_ciphertext = dbg_inst.encrypt(plaintext);

	// Now we can evaluate our homomorphic circuit on this input, ignoring the output
	poly_eval_homomorphic_v1(dbg_inst, dbg_ciphertext);

/* When you set <TODO>, the DebugEval instance logs the first few coefficients of the
 * decrypted homomorphic computation at each gate. When the evaluator detects a divergence
 * between the plaintext and homomorphic computations, it prints out additional information.
 * <TODO> be more precise here.
 */

/* ******** OpCount Evaluator ********
 * Let's look at one final evaluator before moving on. When comparing large circuits, it is
 * useful to know how many gates (and of what type) are evaluated in each circuit. The OpCount evaluator
 * provides exactly this information. Let's see how to use it below.
 */
	// The OpCount instance type doesn't need any arguments.
	OpCount oc_inst = OpCount();

	// Don't reuse ciphertexts between instance types!
	CKKSCiphertext oc_ciphertext = oc_inst.encrypt(plaintext);

	// Now we can evaluate our homomorphic circuit on this input, ignoring the output
	poly_eval_homomorphic_v1(oc_inst, oc_ciphertext);

	// We can now ask the OpCount evaluator to print (to the log) a tally of each type of gate.
	// This log output is visible when <TODO>
	oc_inst.print_op_count();
}
