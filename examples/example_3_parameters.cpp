// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/api/evaluator/depthfinder.h"
#include "hit/common.h"

using namespace std;
using namespace hit;

// defined in example_1_ckks.cpp
extern vector<double> randomVector(int dim, double maxNorm);
// defined in example_2_plaintext.cpp
extern vector<double> poly_eval_plaintext(vector<double> xs);
extern CKKSCiphertext poly_eval_homomorphic_v1(CKKSEvaluator &eval, CKKSCiphertext &ct);

/* In the previous example, we saw how to use HIT to validate that a circuit
 * works correctly on plaintexts. While that is a good start, the point of
 * homomorphic circuit design is to evaluate the circuit on ciphertexts! To
 * do that, we need cryptosystem parameters. HIT demystifies the process of
 * selecting encryption system parameters by providing evaluators which
 * compute suggested encryption parameters.
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
	// Create a CKKS instance to compute circuit depth. This instance type needs _no_ parameters.
	DepthFinder inst = DepthFinder();

	// Generate a plaintext with `num_slots` random coefficients, each with absolute value < `plaintext_inf_norm`
	int plaintext_inf_norm = 10;
	vector<double> plaintext = randomVector(num_slots, plaintext_inf_norm);

	// Encrypt the plaintext. This evaluator only tracks ciphertext metadata;
	// the CKKSCiphertext does not contain a real ciphertext or the plaintext.
	CKKSCiphertext ciphertext = inst.encrypt(plaintext);

	// Now we can evaluate our homomorphic circuit on this input, ignoring the output
	poly_eval_homomorphic_v1(inst, ciphertext);

	// Finally, we can ask the evaluator for the circuit's depth.
	int max_depth = inst.get_multiplicative_depth();
	cout << "poly_eval_homomorphic_v1 has multiplicative depth " << max_depth << endl;

/* ******** CKKS Scale ********
 * The next parameter we will need is the CKKS scale. You should use the largest scale
 * possible, since it results in the most precision in the homomorphic computation.
 * The scale is bounded above because the scaled plaintext can never exceed the
 * ciphertext modulus, otherwise the plaintext wraps around the modulus and is lost.
 * Imagine a ciphertext at level 0. SEAL recommends a 60-bit ciphertext
 * modulus at this level, so in order to avoid overflow, we must satisfy inf_norm(plaintext)*scale < 2^60.
 * By evaluating the circuit on a representative plaintext, we can get a good idea of the

