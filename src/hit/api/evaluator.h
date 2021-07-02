// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <future>
#include <shared_mutex>

#include "ciphertext.h"

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
 *    See the examples/example_1_ckks for details.
 * Each homomorphic operation accepts ciphertexts with some subset of these properties, which
 * we denote using the terms above.
 */

namespace hit {

    class CKKSEvaluator {
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

        // Encrypt a (full-dimensional) vector of coefficients. If an encryption level (integer >= 0) is not specified,
        // the ciphertext will be encrypted at the highest level allowed by the parameters.
        virtual CKKSCiphertext encrypt(const std::vector<double> &coeffs) = 0;
        virtual CKKSCiphertext encrypt(const std::vector<double> &coeffs, int level) = 0;

        // Decrypt a ciphertext to (approximately) recover the plaintext coefficients.
        // This function will log a message if you try to decrypt a ciphertext which
        // is not at level 0. Sometimes it is expected for a ciphertext to be at a higher
        // level, so you can suppress the warning by setting `suppress_warnings` to true.
        virtual std::vector<double> decrypt(const CKKSCiphertext &ct);
        virtual std::vector<double> decrypt(const CKKSCiphertext &ct, bool suppress_warnings);

        // Get the number of plaintext slots expected by this evaluator
        virtual int num_slots() const = 0;

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

        /* Add a list of encrypted objects together, component-wise.
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

        /* Negate each plaintext coefficient.
         * Input: An arbitrary ciphertext (any degree and any scale)
         * Output (Inplace): A ciphertext with the same properties as the input.
         */
        void negate_inplace(CKKSCiphertext &ct);

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
         * NOTE: This operation throws an exception if the result is a constant
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
         * NOTE: This operation throws an exception if the result is a constant
         *       ciphertext, since this results in a "transparent ciphertext" which does not
         *       require the secret key to decrypt. One way this can happen is if one ciphertext
         *       is a scalar shift of the other. In this case, the ciphertexts only differ in
         *       their constant coefficient, so any higher-order terms are cancelled out.
         */
        void sub_inplace(CKKSCiphertext &ct1, const CKKSCiphertext &ct2);

        /* Multiply each plaintext slot by a scalar.
         * Input: A linear or quadratic ciphertext with nominal scale.
         * Output: A ciphertext with the same ciphertext degree as the input, but with squared scale.
         * NOTE: The scalar zero produces a transparent ciphertext since all ciphertext polynomial coefficients
         *       are zero. Rather than throw an exception, this implementation returns a fresh encryption of a
         *       all-zero plaintext.
         */
        CKKSCiphertext multiply_plain(const CKKSCiphertext &ct, double scalar);

        /* Multiply each plaintext slot by a scalar.
         * Input: A linear or quadratic ciphertext with nominal scale.
         * Output (Inplace): A ciphertext with the same ciphertext degree as the input, but with squared scale.
         * NOTE: The scalar zero produces a transparent ciphertext since all ciphertext polynomial coefficients
         *       are zero. Rather than throw an exception, this implementation returns a fresh encryption of a
         *       all-zero plaintext.
         */
        void multiply_plain_inplace(CKKSCiphertext &ct, double scalar);

        /* Multiply the encrypted plaintext and the public plaintext component-wise.
         * Input: A linear or quadratic ciphertext with nominal scale.
         * Output: A ciphertext with the same ciphertext degree as the input,
         *         but with squared scale.
         */
        CKKSCiphertext multiply_plain(const CKKSCiphertext &ct, const std::vector<double> &plain);

        /* Multiply the encrypted plaintext and the public plaintext component-wise.
         * Input: A linear or quadratic ciphertext with nominal scale.
         * Output (Inplace): A ciphertext with the same ciphertext degree as the input,
         *                   but with squared scale.
         */
        void multiply_plain_inplace(CKKSCiphertext &ct, const std::vector<double> &plain);

        /* Multiply two encrypted plaintexts, component-wise.
         * Input: Two linear ciphertexts at the same level, with nominal scales.
         * Output: A quadratic ciphertext whose level is the same as the inputs,
         *         and whose scale is squared.
         */
        CKKSCiphertext multiply(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2);

        /* Multiply two encrypted plaintexts, component-wise.
         * Input: Two linear ciphertexts at the same level, with nominal scales.
         * Output (Inplace): A quadratic ciphertext whose level is the same as the inputs,
         *                   and whose scale is squared.
         */
        void multiply_inplace(CKKSCiphertext &ct1, const CKKSCiphertext &ct2);

        /* Square each plaintext coefficient.
         * Input: A linear ciphertext with nominal scale.
         * Output: A quadratic ciphertext whose level is the same as the input,
         *         and whose scale is squared.
         */
        CKKSCiphertext square(const CKKSCiphertext &ct);

        /* Square each plaintext coefficient.
         * Input: A linear ciphertext with nominal scale.
         * Output (Inplace): A quadratic ciphertext whose level is the same as the input,
         *                   and whose scale is squared.
         */
        void square_inplace(CKKSCiphertext &ct);

        /* Reduce the HE level of `ct` to the level of the `target`.
         * Input: A linear ciphertext with nominal scale and level i,
         *        and an arbitrary ciphertext at level j <= i.
         * Output: A linear ciphertext with nominal scale and level j, encrypting
         *         the same plaintext as `ct`.
         * NOTE: It is an error if the target level is higher than the level of `ct`.
         */
        CKKSCiphertext reduce_level_to(const CKKSCiphertext &ct, const CKKSCiphertext &target);

        /* Reduce the HE level of `ct` to the level of the `target`.
         * Input: A linear ciphertext with nominal scale and level i,
         *        and an arbitrary ciphertext at level j <= i.
         * Output (Inplace): A linear ciphertext with nominal scale and level j, encrypting
         *                   the same plaintext as `ct`.
         * NOTE: It is an error if the target level is higher than the level of `ct`.
         */
        void reduce_level_to_inplace(CKKSCiphertext &ct, const CKKSCiphertext &target);

        /* Reduce the HE level of both inputs to the lower of the two levels.
         * This operation modifies at most one of the inputs.
         * Input: Two ciphertexts where the ciphertext at the higher level is
         *        linear with nominal scale.
         * Output (Inplace): The ciphertext at the higher level is modified
         *                   so that it is a linear ciphertext with nominal scale
         *                   at the level of the other input.
         * NOTE: If both inputs are at the same level, neither ciphertext is changed.
         */
        void reduce_level_to_min_inplace(CKKSCiphertext &ct1, CKKSCiphertext &ct2);

        /* Reduce the HE level of `ct` to a lower level
         * Input: A linear ciphertext with nominal scale and level i, and a target level
         *        0 <= j <= i.
         * Output: A linear ciphertext with nominal scale and level j, encrypting
         *         the same plaintext as `ct`.
         */
        CKKSCiphertext reduce_level_to(const CKKSCiphertext &ct, int level);

        /* Reduce the HE level of `ct` to a lower level
         * Input: A linear ciphertext with nominal scale and level i, and a target level
         *        0 <= j <= i.
         * Output (Inplace): A linear ciphertext with nominal scale and level j, encrypting
         *                   the same plaintext as `ct`.
         */
        void reduce_level_to_inplace(CKKSCiphertext &ct, int level);

        /* Remove a prime from the modulus (i.e. go down one level) and scale
         * down the plaintext by that prime.
         * Input: A linear or quadratic ciphertext with squared scale and level i>0.
         * Output: A ciphertext with the same degree as the input
         *         with nominal scale and level i-1.
         */
        CKKSCiphertext rescale_to_next(const CKKSCiphertext &ct);

        /* Remove a prime from the modulus (i.e. go down one level) and scale
         * down the plaintext by that prime.
         * Input: A linear or quadratic ciphertext with squared scale and level i>0.
         * Output (Inplace): A ciphertext with the same degree as the input
         *                   with nominal scale and level i-1.
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
         * to convert this quadratic ciphertext back into a linear ciphertext
         * that encrypts the same plaintext.
         *
         * Relinearize the ciphertext.
         * Input: A quadratic ciphertext with nominal or squared scale.
         * Output (Inplace): A linear ciphertext with the same scale and level as the input.
         * NOTE: Inputs which are linear ciphertexts to begin with are unchanged by this function.
         */
        void relinearize_inplace(CKKSCiphertext &ct);

        /* TODO
         */
        CKKSCiphertext bootstrap(const CKKSCiphertext &ct, bool rescale_for_bootstrapping = true);

       protected:
        virtual void rotate_right_inplace_internal(CKKSCiphertext &ct, int steps);
        virtual void rotate_left_inplace_internal(CKKSCiphertext &ct, int steps);
        virtual void negate_inplace_internal(CKKSCiphertext &ct);
        virtual void add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2);
        virtual void add_plain_inplace_internal(CKKSCiphertext &ct, double scalar);
        virtual void add_plain_inplace_internal(CKKSCiphertext &ct, const std::vector<double> &plain);
        virtual void sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2);
        virtual void sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar);
        virtual void sub_plain_inplace_internal(CKKSCiphertext &ct, const std::vector<double> &plain);
        virtual void multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2);
        virtual void multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar);
        virtual void multiply_plain_inplace_internal(CKKSCiphertext &ct, const std::vector<double> &plain);
        virtual void square_inplace_internal(CKKSCiphertext &ct);
        virtual void reduce_level_to_inplace_internal(CKKSCiphertext &ct, int level);
        virtual void rescale_to_next_inplace_internal(CKKSCiphertext &ct);
        virtual void relinearize_inplace_internal(CKKSCiphertext &ct);
        virtual void print_stats(const CKKSCiphertext &ct);
        virtual uint64_t get_last_prime_internal(const CKKSCiphertext &ct) const;
        virtual CKKSCiphertext bootstrap_internal(const CKKSCiphertext &ct, bool rescale_for_bootstrapping);

        void reduce_metadata_to_level(CKKSCiphertext &ct, int level);
        void rescale_metata_to_next(CKKSCiphertext &ct);

        CKKSEvaluator() = default;

        mutable std::shared_mutex mutex_;
    };
}  // namespace hit
