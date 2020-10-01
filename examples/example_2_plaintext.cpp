// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/hit.h"

using namespace std;
using namespace hit;

// defined in example_1_ckks.cpp
extern vector<double> random_vector(int dim, double maxNorm);

/* The Homomorphic Implementor's Tookit (HIT) is a library to simplify the
 * design and implementation of homomorphic circuits for the CKKS homomorphic
 * encryption scheme. HIT uses Microsoft SEAL
 * as its underlying homomorphic encryption implementation, but it also
 * provides more functionality and higher-level APIs to simplify circuit
 * development.
 *
 * In this tutorial, we will implement a homomorphic circuit using HIT. Our
 * first goal will be to implement batch polynomial evaluation on encrypted
 * inputs. We will evaluate the polynomial f(x) = c_3*x^3 + c_1*x + c_0 for
 * the constants below.
 */
const double c_0 = 0.5;
const double c_1 = 0.0843;
const double c_3 = -0.0002;
/* First, we'll implement a plaintext version of the function we want to
 * implement.
 */
vector<double> poly_eval_plaintext(vector<double> xs) {
	vector<double> results;
	results.reserve(xs.size());
	for(const auto x : xs) {
		double y = c_3*x*x*x + c_1*x + c_0;
		results.push_back(y);
	}
	return results;
}
/* HIT provides an interface for low-level homomorphic operations
 * like addition and multiplication. For this demo, we will evaluate the
 * polynomial on each plaintext slot. This is a useful technique in HE
 * because polynomials are relatively simple to evaluate compared to
 * non-polynomial functions. It is frequently convenient to approximate
 * a non-polynomial function by a polynomial for homomorphic evaluation.
 *
 * We compute the approximation using the following circuit:
 *
 *  Lvl                                                              Scale
 *   i      x     x     x     c_3      x     c_1                      s
 *           \   /       \     /        \     /
 *  i-1       x^2         c_3*x          c_1*x        1             s^2/p_i
 *             \           /               \         /
 *              \         /                 \       /
 *               \       /                   \     /
 *  i-2           c_3*x^3                     c_1*x            (s^2/p_i)^2/p_{i-1}
 *                     \                       /
 *                      \                     /
 *                       \                   /
 *                        \                 /
 *                         \               /
 *                          \             /
 *  i-2                      c_3*x^3+c_1*x           c_0      (s^2/p_i)^2/p_{i-1}
 *                                \                   /
 *                                 \                 /
 *  i-2                             c_3*x^3+c_1*x+c_0          (s^2/p_i)^2/p_{i-1}
 *
 * Inputs to addition or multiplication must be at the same level
 * of the tree. Constants can be inserted at any level of the tree.
 * Multiplication (even by a constant) consumes a level, while addition
 * never consumes a level.
 * Just as the plaintext version of this function took a vector
 * and returned a vector, the homomorphic version will take an encrypted
 * vector (one ciphertext) and return an encrypted vector (one ciphertext).
 * After each operation, we include a comment indicating
 * the output variable, whether it is a linear or quadratic ciphertext,
 * its approximate scale (either the encryption scale or its square),
 * and the HE level of the variable. We assume that the input is a linear
 * ciphertext with nominal scale and level `i`.
 */
CKKSCiphertext poly_eval_homomorphic_v1(CKKSEvaluator &eval, CKKSCiphertext &ct) {
	// eval.square performs "Hadamard multiplication" on the encrypted vector,
	// squaring each component of the vector.
	CKKSCiphertext ct_squared = eval.square(ct);              // ct_squared, quadratic, scale^2, level i
	// the result is a quadratic ciphertext with a squared scale
	// before doing further operations, we need to *relinearize* and *rescale*
	eval.relinearize_inplace(ct_squared);                     // ct_squared, linear, scale^2, level i
	eval.rescale_to_next_inplace(ct_squared);                 // ct_squared, linear, scale, level i-1
	// ct_squared is now a linear ciphertext with nominal scale

	// Next, we comput c_3*ct
	CKKSCiphertext c3_ct = eval.multiply_plain(ct, c_3);      // c3_ct, linear, scale^2, level i
	// Since c3_ct is linear, we don't need to relinearize,
	// but we do need to rescale
	eval.rescale_to_next_inplace(c3_ct);                      // c3_ct, linear, scale, level i-1

	// term2 = c_1*ct is similar
	CKKSCiphertext term2 = eval.multiply_plain(ct, c_1);      // term2, linear, scale^2, level i
	eval.rescale_to_next_inplace(term2);                      // term2, linear, scale, level i-1

	// Now we can compute the second layer of the circuit,
	// starting with term1 (c_3*ct^3)
	CKKSCiphertext term1 = eval.multiply(c3_ct, ct_squared);  // term1, quadratic, scale^2, level i-1
	// relinearize and rescale
	eval.relinearize_inplace(term1);                          // term1, linear, scale^2, level i-1
	eval.rescale_to_next_inplace(term1);                      // term1, linear, scale, level i-2
	// To add these terms together, we need both arguments
	// at the same level, so we will reduce the level of
	// term2 to the level of term1 by mutliplying by the
	// scalar 1 and then rescaling. This combination
	// (possibly repeated until the first argument is
	// at the target level) is encapsulated as `reduce_level_to`
	eval.reduce_level_to_inplace(term2, term1);               // term2, linear, scale, level-2
	// Addition of ciphertexts induces component-wise addition
	// on the plaintexts. Addition of linear ciphertexts results
	// in a linear ciphertext, and does not change the ciphertext scale
	CKKSCiphertext poly_result = eval.add(term1, term2);       // poly_result, linear, scale, level i-2
	// Addition of a constant adds the constant to each plaintext coefficient.
	eval.add_plain_inplace(poly_result, c_0);                  // poly_result, linear, scale, level i-2
	return poly_result;
}
/* Phew. That's a lot. Even ignoring the maintenance operations, does `poly_eval_homomorphic_v1`
 * compute the same function as `poly_eval_plaintext`? We could create a `HomomorphicEval` instance
 * as in the last example, but then we'd have to choose cryptosystem parameters. A plaintext could
 * have exceeded the maximum capacity of a ciphertext and overflowed. It's hard
 * to know what scale should be used, or even what the multiplicative depth of the circuit is.
 * Fortunately, HIT provides an easy way to verify that a circuit is correct *without* worrying
 * about maintenance operations or cryptosystem paramteters via the `Plaintext` evaluator.
 * With this evaluator, "encryption" doesn't encrypt at all, it just puts the raw plaintext
 * into the `CKKSCiphertext` object, and performs all operations on the plaintext directly
 * rather than via the encryption homomorphism. This allows you to verify that a circuit is
 * correct on plaintext inputs, without rewriting any code!
 * It's important to note that this evaluator
 * should be used with care since raw plaintext is inserted into a `CKKSCiphertext`, so it
 * is not secure to use in production.
 */
void example_2_driver() {
	// Create a CKKS instance which operates on plaintexts.
	// To ensure consistency between inputs and ensure that inputs would be valid
	// if we were doing encryption, you must specify the number of slots your plaintexts
	// will have.
	int num_slots = 4096;
	PlaintextEval inst = PlaintextEval(num_slots);

	// Generate a plaintext with `num_slots` random coefficients, each with absolute value < `plaintext_inf_norm`
	int plaintext_inf_norm = 10;
	vector<double> plaintext = random_vector(num_slots, plaintext_inf_norm);

	// First, we will evaluate the plaintext function on the plaintext input
	vector<double> expected_result = poly_eval_plaintext(plaintext);

	// Encrypt the plaintext; there is no need to worry about
	// the encryption level with the PlaintextEval instance.
	// This "ciphertext" only holds the raw plaintext; SEAL is never called.
	CKKSCiphertext ciphertext = inst.encrypt(plaintext);

	// Now we can evaluate our homomorphic circuit on this input
	CKKSCiphertext ct_out = poly_eval_homomorphic_v1(inst, ciphertext);

	// Next, we want to extract the plaintext to compare the result
	vector<double> actual_result = ct_out.plaintext();
	// Note that calling decrypt with the Plaintext instance type is an error
	// since the ct_out doesn't actually contain a ciphertext.
	// vector<double> actual_result = inst.decrypt(ct_out); // ERROR

	// Compute the |expected-actual|/|expected|, where |*| denotes the 2-norm.
	// If this value is small, then the expected and actual results closely agree,
	// up to floating point roundoff (note that since the PlaintextEval only operates on
	// plaintexts, there is no CKKS noise to introduce additional error.)
	cout << "Relative difference between input and decrypted output: " << relative_error(expected_result, actual_result) << endl;
}
/* Since the normalized difference of the vectors is small, we can be sure that the "core" of our circuit
 * (i.e., excluding ciphertext maintenance operations) is correct! What if this value was large?
 * The plaintext evaluator has a verbose logging mode which outputs the value of the plaintext after each
 * gate so you can see *exactly* where the computation diverged from your expectation. This logging can
 * be enabled by <TODO>
 */
