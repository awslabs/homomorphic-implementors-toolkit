// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <future>
#include "ciphertext.h"
#include "seal/context.h"
#include "seal/seal.h"

/* An abstract class with an evaluator API.
 * All evaluators should extend this class.
 *
 * The API is a wrapper around the SEAL `Evaluator` class.
 * The wrapper provides simplified APIs compared to the SEAL Evaluator class.
 */

#define VERBOSE(x) \
    if (verbose) { \
        x;         \
    }

#define ContextDataPtr std::shared_ptr<const seal::SEALContext::ContextData>

class CKKSEvaluator {
   public:
    /* Since the intended usage of this class is for applications to take a
     * `CKKSEvaluator` which is instantiated using a subclass, this class
     * must define a virtual destructor. Otherwise, calling `delete` on a
     * `CKKSEvaluator` which actually is a subclass results in undefined
     * behavior.
     * https://www.geeksforgeeks.org/virtual-destructor/
     */
    virtual ~CKKSEvaluator();

    CKKSEvaluator(const CKKSEvaluator &) = delete;
    CKKSEvaluator &operator=(const CKKSEvaluator &) = delete;
    CKKSEvaluator(CKKSEvaluator &&) = delete;
    CKKSEvaluator &operator=(CKKSEvaluator &&) = delete;

    // reuse this evaluator for another computation
    void reset();

    /* Rotate a plaintext vector cyclically to the right.
     */
    CKKSCiphertext rotate_vector_right(const CKKSCiphertext &ct, int steps);

    /* Rotate a plaintext vector cyclically to the left.
     */
    CKKSCiphertext rotate_vector_left(const CKKSCiphertext &ct, int steps);

    /* Add a scalar to (each slot of) the ciphertext, and place the result in `dest`.
     * The plaintext is encoded with the same scale as the ciphertext.
     */
    CKKSCiphertext add_plain_scalar(const CKKSCiphertext &ct, double scalar);

    /* Add two ciphertexts (inducing component-wise addition on plaintexts)
     * and store the result in the first parameter.
     */
    CKKSCiphertext add(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2);

    /* Multiply the ciphertext by the plaintext, and store the result in `dest`.
     * The plaintext is encoded using the same scale as the ciphertext.
     *
     * WARNING: Multiplying by 0 results in non-constant time behavior! Only multiply by 0 if the scalar is truly
     * public.
     */
    CKKSCiphertext multiply_plain_scalar(const CKKSCiphertext &ct, double scalar);

    /* Multiply the ciphertext by the plaintext. This API is different than the corresponding SEAL API:
     * it takes a C++ vector whose size is the same as the size of the plaintext encrypted by the ciphertext,
     * and is interpreted as a matrix (i.e., no linear algebra encoding is performed).
     * The plaintext is encoded using the same scale as the ciphertext.
     */
    CKKSCiphertext multiply_plain_mat(const CKKSCiphertext &ct, const std::vector<double> &plain);

    /* Multiply two ciphertexts (inducing component-wise multiplication on
     * plaintexts) and store the result in the first parameter.
     */
    CKKSCiphertext multiply(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2);

    /* Multiply the first input by itself, and store the result in the second
     * parameter.
     */
    CKKSCiphertext square(const CKKSCiphertext &ct);

    /* Reduce the HE level of `x` to the level of the `target.
     */
    void modDownTo(CKKSCiphertext &ct, const CKKSCiphertext &target);

    /* Reduce the HE level of both inputs to the lower of the two levels.
     */
    void modDownToMin(CKKSCiphertext &ct1, CKKSCiphertext &ct2);

    /* Reduce the HE level of `x` to level `level`, which has
     * level+1 moduli. `level` must be >= 0.
     */
    CKKSCiphertext modDownToLevel(const CKKSCiphertext &ct, int level);

    /* Remove a prime from the modulus (i.e. go down one level) and scale
     * down the plaintext by that prime.
     */
    void rescale_to_next_inplace(CKKSCiphertext &ct);

    /* Ciphertexts in BGV-style encryption schemes, like CKKS, are polynomials
     * in the (unknown) secret. A fresh ciphertext is a linear polynomial
     * (i.e., c(S) = c_0 + c_1*S), which we store simply as its coefficient
     * list [c_0, c_1]. Most ciphertext operations require ciphertexts to be
     * a linear polynomial in the secret key. However, multiplying two (linear)
     * ciphertexts multiplies the corresponding polynomials, resulting in a
     * quadratic polynomial. All HE schemes with this property have a special
     * operation called "relinearization" that uses a special set of keys
     * (`relin_keys`) to convert this quadratic ciphertext back into a linear
     * ciphertext that encrypts the same plaintext.
     */
    void relinearize_inplace(CKKSCiphertext &ct);

    // parallel evaluation strategy for this evaluator
    // most evaluators require serial execution since they aren't thread safe
    // but thread-safe evaluators can change this value.
    std::launch evalPolicy = std::launch::deferred;

   protected:
    virtual CKKSCiphertext rotate_vector_right_internal(const CKKSCiphertext &ct, int steps) = 0;
    virtual CKKSCiphertext rotate_vector_left_internal(const CKKSCiphertext &ct, int steps) = 0;
    virtual CKKSCiphertext add_plain_scalar_internal(const CKKSCiphertext &ct, double scalar) = 0;
    virtual CKKSCiphertext add_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) = 0;
    virtual CKKSCiphertext multiply_plain_scalar_internal(const CKKSCiphertext &ct, double scalar) = 0;
    virtual CKKSCiphertext multiply_plain_mat_internal(const CKKSCiphertext &ct, const std::vector<double> &plain) = 0;
    virtual CKKSCiphertext multiply_internal(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) = 0;
    virtual CKKSCiphertext square_internal(const CKKSCiphertext &ct) = 0;
    virtual void modDownTo_internal(CKKSCiphertext &ct, const CKKSCiphertext &target) = 0;
    virtual void modDownToMin_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) = 0;
    virtual CKKSCiphertext modDownToLevel_internal(const CKKSCiphertext &ct, int level) = 0;
    virtual void rescale_to_next_inplace_internal(CKKSCiphertext &ct) = 0;
    virtual void relinearize_inplace_internal(CKKSCiphertext &ct) = 0;
    virtual void reset_internal() = 0;

    CKKSEvaluator(std::shared_ptr<seal::SEALContext> context, bool verbose);

    ContextDataPtr getContextData(const CKKSCiphertext &ct);

    const std::shared_ptr<seal::SEALContext> context;

    bool verbose;
};

// ensure that metadata for two arguments matches
bool is_valid_args(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2);
