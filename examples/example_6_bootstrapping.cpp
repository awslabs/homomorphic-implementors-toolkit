// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/hit.h"
#include <fstream>
#include <glog/logging.h>

using namespace std;
using namespace hit;

// defined in example_1_ckks.cpp
extern vector<double> random_vector(int dim, double maxNorm);

// defined in example_2_plaintext.cpp
extern vector<double> poly_eval_plaintext(const vector<double> &xs);
extern CKKSCiphertext poly_eval_homomorphic_v1(CKKSEvaluator &eval, CKKSCiphertext &ct);

/* This example demonstrates the use of CKKS bootstrapping, which enables fixed-size
 * parameters to be used to evaluate an arbitrary depth circuit. CKKS bootstrapping
 * works differently from bootstrapping in other schemes because it introduces
 * additional noise in the computation, so it is best used in convergent computations
 * that are robust to small perturbations, e.g., minimization problems.
 */
void example_6_driver() {
    // Bootstrapping parameters are complex, and explaining each parameter is beyond the scope
    // of this tutorial, so for this example we use default parameters provided by Lattigo.
    CKKSParams params(latticpp::getBootstrappingParams(latticpp::BootstrapParams_Set4));

    // We can now create a HomomorphicEvaluator for these parameters, which automatically
    // generates all keys needed by bootstrapping. Note that by not providing the `galois_steps`
    // we do not (necessarily) support any explicit rotations, only those implicitly used in
    // the bootstrapping circuit.
    HomomorphicEval he_inst = HomomorphicEval(params);

    // Encrypt a plaintext
    int plaintext_inf_norm = 1;
    vector<double> plaintext = random_vector(params.num_slots(), plaintext_inf_norm);
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

    // Now, we will bootstrap the ciphertext
    CKKSCiphertext bootstrapped_ct = he_inst.bootstrap(ct_result);

    // Decrypt again so we can compare the value pre- and post-bootstrapping
    vector<double> bootstrapped_result = he_inst.decrypt(bootstrapped_ct);

    LOG(INFO) << "Relative difference between pre- and post- bootstrapped results: " << relative_error(actual_result, bootstrapped_result);
}
