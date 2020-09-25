// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <future>
#include <shared_mutex>

#include "ciphertext.h"
#include "seal/context.h"
#include "seal/seal.h"
#include "../CKKSInstance.h"

/* An abstract class with an evaluator API.
 * All evaluators should extend this class.
 *
 * The API is a wrapper around the SEAL `Evaluator` class.
 * The wrapper provides simplified APIs compared to the SEAL Evaluator class.
 */


/* Ciphertexts have three properties:
 *  - Their level
 *  - Whether the 'degree' of the ciphertext polynomial (in the secret key) is 'linear' or 'quadratic'
 *  - Whether the scale factor is 'nominal' (roughly the same as it was when freshly encrypted)
 *    or 'squared' (roughly the square of the nominal scale). The "roughly" here is important:
 *    ciphertexts at different levels both with nominal scale in reality have *different* scales.
 *    See <TODO> for details.
 * Each homomorphic operation accepts ciphertexts with some subset of these properties, which
 * we denote using the terms above.
 */


#define ContextDataPtr std::shared_ptr<const seal::SEALContext::ContextData>

namespace hit {

    class CKKSEvaluator : public CKKSInstance {
       public:
        /* Since the intended usage of this class is for applications to take a
         * `CKKSEvaluator` which is instantiated using a subclass, this class
         * must define a virtual destructor. Otherwise, calling `delete` on a
         * `CKKSEvaluator` which actually is a subclass results in undefined
         * behavior.
         * https://www.geeksforgeeks.org/virtual-destructor/
         */
        virtual ~CKKSEvaluator() = default;

        CKKSEvaluator(const CKKSEvaluator &) = delete;
        CKKSEvaluator &operator=(const CKKSEvaluator &) = delete;
        CKKSEvaluator(CKKSEvaluator &&) = delete;
        CKKSEvaluator &operator=(CKKSEvaluator &&) = delete;

        /******************
         * Evaluation API *
         ******************/

        /* Rotate a plaintext vector cyclically to the right by any positive number of steps:
         *     rotate_right(<1,2,3,4>, 1) = <4,1,2,3>
         * Input: A linear ciphertext with nominal or squared scale
         *        and the number of steps to rotate.
         * Output: A ciphertext with the same properties as the input.
         */
        CKKSCiphertext rotate_right(const CKKSCiphertext &ct, int steps);


        /* Rotate a plaintext vector cyclically to the right by any positive number of steps:
         *     rotate_right(<1,2,3,4>, 1) = <4,1,2,3>
         * Input: A linear ciphertext with nominal or squared scale
         *        and the number of steps to rotate.
         * Output (Inplace): A ciphertext with the same properties as the input.
         */
        void rotate_right_inplace(CKKSCiphertext &ct, int steps);


        /* Rotate a plaintext vector cyclically to the left by any positive number of steps:
         *     rotate_left(<1,2,3,4>, 1) = <2,3,4,1>
         * Input: A linear ciphertext with nominal or squared scale
         *        and the number of steps to rotate.
         * Output: A ciphertext with the same properties as the input.
         */
        CKKSCiphertext rotate_left(const CKKSCiphertext &ct, int steps);


        /* Rotate a plaintext vector cyclically to the left by any positive number of steps:
         *     rotate_left(<1,2,3,4>, 1) = <2,3,4,1>
         * Input: A linear ciphertext with nominal or squared scale
         *        and the number of steps to rotate.
         * Output (Inplace): A ciphertext with the same properties as the input.
         */
        void rotate_left_inplace(CKKSCiphertext &ct, int steps);


        /* Negate each plaintext coefficient.
         * Input: An arbitrary ciphertext (any degree and any scale)
         * Output (Inplace): A ciphertext with the same properties as the input.
         */
        void negate_inplace(CKKSCiphertext &ct);


        /* Add a scalar to each plaintext slot.
         * Input: An arbitrary ciphertext (any degree and any scale) and a public scalar
         * Output: A ciphertext with the same properties as the input.
         */
        CKKSCiphertext add_plain(const CKKSCiphertext &ct, double scalar);


        /* Add a scalar to each plaintext slot.
         * Input: An arbitrary ciphertext (any degree and any scale) and a public scalar
         * Output (Inplace): A ciphertext with the same properties as the input.
         */
        void add_plain_inplace(CKKSCiphertext &ct, double scalar);


        /* Add a public plaintext component-wise to the encrypted plaintext.
         * Input: An arbitrary ciphertext (any degree and any scale) and a public plaintext
         * Output: A ciphertext with the same properties as the input.
         */
        CKKSCiphertext add_plain(const CKKSCiphertext &ct, const std::vector<double> &plain);


        /* Add a public plaintext component-wise to the encrypted plaintext.
         * Input: An arbitrary ciphertext (any degree and any scale) and a public plaintext
         * Output (Inplace): A ciphertext with the same properties as the input.
         */
        void add_plain_inplace(CKKSCiphertext &ct, const std::vector<double> &plain);


        /* Add two encrypted plaintexts, component-wise.
         * Input: Two ciphertexts at the same level whose scales match (can be nominal or squared).
         *        Note that ciphertext degrees do not need to match.
         * Output: A ciphertext whose level and scale is the same as the inputs, and whose
         *         degree is the maximum of the two input degrees.
         */
        CKKSCiphertext add(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2);


        /* Add two encrypted plaintexts, component-wise.
         * Input: Two ciphertexts at the same level whose scales match (can be nominal or squared).
         *        Note that ciphertext degrees do not need to match.
         * Output (Inplace): A ciphertext whose level and scale is the same as the inputs, and whose
         *                   degree is the maximum of the two input degrees.
         */
        void add_inplace(CKKSCiphertext &ct1, const CKKSCiphertext &ct2);


        /* Add two encrypted plaintexts, component-wise.
         * Input: A non-empty vector of ciphertexts. The ciphertexts must be at the same level,
         *        and their scales must be equal.
         *        Note that ciphertext degrees do not need to match.
         * Output: A ciphertext whose level and scale is the same as the inputs, and whose
         *         degree is the maximum of the input degrees.
         */
        CKKSCiphertext add_many(const std::vector<CKKSCiphertext> &cts);


        /* Negate each plaintext coefficient.
         * Input: An arbitrary ciphertext (any degree and any scale)
         * Output: A ciphertext with the same properties as the input.
         */
        CKKSCiphertext negate(const CKKSCiphertext &ct);


        /* Subtract a scalar from each plaintext slot.
         * Input: An arbitrary ciphertext (any degree and any scale) and a public scalar
         * Output: A ciphertext with the same properties as the input.
         */
        CKKSCiphertext sub_plain(const CKKSCiphertext &ct, double scalar);


        /* Subtract a scalar from each plaintext slot.
         * Input: An arbitrary ciphertext (any degree and any scale) and a public scalar
         * Output (Inplace): A ciphertext with the same properties as the input.
         */
        void sub_plain_inplace(CKKSCiphertext &ct, double scalar);


        /* Subtract a public plaintext component-wise from the encrypted plaintext.
         * Input: An arbitrary ciphertext (any degree and any scale) and a public plaintext
         * Output: A ciphertext with the same properties as the input.
         */
        CKKSCiphertext sub_plain(const CKKSCiphertext &ct, const std::vector<double> &plain);


        /* Subtract a public plaintext component-wise from the encrypted plaintext.
         * Input: An arbitrary ciphertext (any degree and any scale) and a public plaintext
         * Output (Inplace): A ciphertext with the same properties as the input.
         */
        void sub_plain_inplace(CKKSCiphertext &ct, const std::vector<double> &plain);


        /* Subtract one encrypted plaintext from another, component-wise.
         * Input: Two ciphertexts at the same level whose scales match (can be nominal or squared).
         *        Note that ciphertext degrees do not need to match.
         * Output: A ciphertext whose level and scale is the same as the inputs, and whose
         *         degree is the maximum of the two input degrees (see NOTE).
         * NOTE: This operation throws an invalid_argument exception if the result is a constant
         *       ciphertext, since this results in a "transparent ciphertext" which does not
         *       require the secret key to decrypt. One way this can happen is if one ciphertext
         *       is a scalar shift of the other. In this case, the ciphertexts only differ in
         *       their constant coefficient, so any higher-order terms are cancelled out.
         */
        CKKSCiphertext sub(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2);

        /* Subtract one encrypted plaintext from another, component-wise.
         * Input: Two ciphertexts at the same level whose scales match (can be nominal or squared).
         *        Note that ciphertext degrees do not need to match.
         * Output (Inplace): A ciphertext whose level and scale is the same as the inputs, and whose
         *                   degree is the maximum of the two input degrees (see NOTE).
         * NOTE: This operation throws an invalid_argument exception if the result is a constant
         *       ciphertext, since this results in a "transparent ciphertext" which does not
         *       require the secret key to decrypt. One way this can happen is if one ciphertext
         *       is a scalar shift of the other. In this case, the ciphertexts only differ in
         *       their constant coefficient, so any higher-order terms are cancelled out.
         */
        void sub_inplace(CKKSCiphertext &ct1, const CKKSCiphertext &ct2);


        /* Multiply two ciphertexts (inducing component-wise multiplication on
         * plaintexts) and store the result in the a new ciphertext.
         * linear/nominal
         */
        CKKSCiphertext multiply(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2);


        /* Multiply two ciphertexts (inducing component-wise multiplication on
         * plaintexts) and store the result in the first parameter.
         * linear/nominal
         */
        void multiply_inplace(CKKSCiphertext &ct1, const CKKSCiphertext &ct2);


        /* Multiply the ciphertext by the plaintext, and store the result in `dest`.
         * The plaintext is encoded using the same scale as the ciphertext.
         * linear/nominal
         *
         * WARNING: Multiplying by 0 results in non-constant time behavior! Only multiply by 0 if the scalar is truly
         * public.
         */
        CKKSCiphertext multiply_plain(const CKKSCiphertext &ct, double scalar);


        /* Multiply the ciphertext by the plaintext, and store the result in the first parameter.
         * The plaintext is encoded using the same scale as the ciphertext.
         * linear/nominal
         *
         * WARNING: Multiplying by 0 results in non-constant time behavior! Only multiply by 0 if the scalar is truly
         * public.
         */
        void multiply_plain_inplace(CKKSCiphertext &ct, double scalar);


        /* Multiply the ciphertext by the plaintext. This API is different than the corresponding SEAL API:
         * it takes a C++ vector whose size is the same as the size of the plaintext encrypted by the ciphertext,
         * and is interpreted as a matrix (i.e., no linear algebra encoding is performed).
         * The plaintext is encoded using the same scale as the ciphertext.
         * linear/nominal
         */
        CKKSCiphertext multiply_plain(const CKKSCiphertext &ct, const std::vector<double> &plain);


        /* Multiply the ciphertext by the plaintext, inplace. This API is different than the corresponding SEAL API:
         * it takes a C++ vector whose size is the same as the size of the plaintext encrypted by the ciphertext,
         * and is interpreted as a matrix (i.e., no linear algebra encoding is performed).
         * The plaintext is encoded using the same scale as the ciphertext.
         * linear/nominal
         */
        void multiply_plain_inplace(CKKSCiphertext &ct, const std::vector<double> &plain);


        /* Multiply the first input by itself, and store the result in a new ciphertext.
         * linear/nominal
         */
        CKKSCiphertext square(const CKKSCiphertext &ct);


        /* Square the input inplace.
         * linear/nominal
         */
        void square_inplace(CKKSCiphertext &ct);


        /* Reduce the HE level of `x` to the level of the `target`.
         * linear/nominal
         */
        CKKSCiphertext reduce_level_to(const CKKSCiphertext &ct, const CKKSCiphertext &target);


        /* Reduce the HE level of `x` to the level of the `target`, inplace.
         * linear/nominal
         */
        void reduce_level_to_inplace(CKKSCiphertext &ct, const CKKSCiphertext &target);


        /* Reduce the HE level of both inputs to the lower of the two levels.
         * This can modify at most one of the inputs.
         * linear/nominal
         */
        void reduce_level_to_min_inplace(CKKSCiphertext &ct1, CKKSCiphertext &ct2);


        /* Reduce the HE level of `x` to level `level`, which has
         * level+1 moduli. `level` must be >= 0.
         * linear/nominal
         */
        CKKSCiphertext reduce_level_to(const CKKSCiphertext &ct, int level);


        /* Reduce the HE level of `x` to level `level`, which has
         * level+1 moduli. `level` must be >= 0. Store the result in the first arugment.
         * linear/nominal
         */
        void reduce_level_to_inplace(CKKSCiphertext &ct, int level);


        /* Remove a prime from the modulus (i.e. go down one level) and scale
         * down the plaintext by that prime.
         * linear/nominal -> allowed, but bad
         * linear/squared -> linear/nominal
         * quadratic/squared -> quadratic/nominal
         */
        CKKSCiphertext rescale_to_next(const CKKSCiphertext &ct);


        /* Remove a prime from the modulus (i.e. go down one level) and scale
         * down the plaintext by that prime. Store the result inplace.
         * linear/nominal -> allowed, but bad
         * linear/squared -> linear/nominal
         * quadratic/squared -> quadratic/nominal
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
         * linear/nominal -> no-op
         * linear/squared -> linear/squared
         * quadratic/squared -> linear/squared
         */
        void relinearize_inplace(CKKSCiphertext &ct);

       protected:
        virtual void rotate_right_inplace_internal(CKKSCiphertext &ct, int steps) = 0;
        virtual void rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) = 0;
        virtual void negate_inplace_internal(CKKSCiphertext &ct) = 0;
        virtual void add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) = 0;
        virtual void add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) = 0;
        virtual void add_plain_inplace_internal(CKKSCiphertext &ct, const std::vector<double> &plain) = 0;
        virtual void sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) = 0;
        virtual void sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) = 0;
        virtual void sub_plain_inplace_internal(CKKSCiphertext &ct, const std::vector<double> &plain) = 0;
        virtual void multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) = 0;
        virtual void multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) = 0;
        virtual void multiply_plain_inplace_internal(CKKSCiphertext &ct, const std::vector<double> &plain) = 0;
        virtual void square_inplace_internal(CKKSCiphertext &ct) = 0;
        virtual void reduce_level_to_inplace_internal(CKKSCiphertext &ct, int level) = 0;
        virtual void rescale_to_next_inplace_internal(CKKSCiphertext &ct) = 0;
        virtual void relinearize_inplace_internal(CKKSCiphertext &ct) = 0;

        CKKSEvaluator() = default;

        ContextDataPtr getContextData(const CKKSCiphertext &ct);

        mutable std::shared_mutex mutex_;
    };
}  // namespace hit
