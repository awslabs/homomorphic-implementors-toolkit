// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* In the previous example, we saw how to use HIT to validate that a circuit
 * works correctly on plaintexts. While that is a good start, the point of
 * homomorphic circuit design is to evaluate the circuit on ciphertexts! To
 * do that, we need cryptosystem parameters. HIT demystifies the process of
 * selecting encryption system parameters by providing evaluators which
 * suggest encryption parameters.
 *
 *
 * ******** Circuit Depth ********
 * The first paramter we will need to determine is the maximum circuit depth
 * we should support. If this depth is too low, we will not be able to evaluate
 * our target function. If the maximum circuit depth is unnecessarily large, we
 * risk either having to reduce the scale (and thus the precision of the result)
 * or increasing the number of plaintext slots, which dramatically decreases
 * performance.
 */

extern vector<double> poly_eval_plaintext(vector<double> xs);
extern CKKSCiphertext poly_eval_homomorphic_v1(CKKSEvaluator &eval, CKKSCiphertext &ct);
