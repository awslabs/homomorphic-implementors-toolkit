// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../ciphertext.h"
#include "../evaluator.h"
#include "hit/protobuf/encoding_unit.pb.h"
#include "hit/protobuf/encrypted_col_vector.pb.h"
#include "hit/protobuf/encrypted_matrix.pb.h"
#include "hit/protobuf/encrypted_row_vector.pb.h"
#include "encodingunit.h"
#include "encryptedmatrix.h"
#include "encryptedrowvector.h"
#include "encryptedcolvector.h"
#include "../../common.h"
#include <glog/logging.h>

/* The LinearAlgebra API lifts the Evaluator API to linear algebra objects like row/column vectors and matrices.
 * It provides a simple API for performing many common linear algebra tasks, and automatic encoding and decoding
 * of plaintext objects to a (series of) ciphertexts.
 *
 * A fundamental concept is the `EncodingUnit`, which is a two-dimensional tile used for encoding objects. To encode
 * a matrix, we tile encoding units over the matrix, and pad the edges with 0s. Encoding vectors is similar, except
 * we have a list of encoding units which encode a vector, rather than a grid of encoding units. See the paper for
 * more details.
 */

namespace hit {

    // Evaluation and Encryption API for Linear Algebra objects
    class LinearAlgebra {
       public:
        /* Wraps a CKKSInstance to create a high-level API for linear algebra encoding, encryption, and operations
         */
        explicit LinearAlgebra(CKKSEvaluator &eval);

        /* Creates a valid encoding unit for this instance, i.e., one which holds exactly as many
         * coefficients as there are plaintext slots.
         * Inputs: Height of the encoding unit (must be a power of two)
         * Output: An encoding unit which has height `encoding_height` and width `num_slots()/encoding_height`
         */
        EncodingUnit make_unit(int encoding_height) const;

        /* Encrypt a matrix after encoding it with the provided encoding unit.
         * Matrix is encrypted at the specified level, or at the highest level allowed by the
         * encryption parameters if no level is specified. We encode the matrix
         * as described in encryptedmatrix.h.
         */
        EncryptedMatrix encrypt_matrix(const Matrix &mat, const EncodingUnit &unit, int level = -1);

        /* Decrypt a matrix with any ciphertext degree and any scale.
         * This function will log a message if you try to decrypt a ciphertext which
         * is not at level 0. Sometimes it is expected for a ciphertext to be at a higher
         * level, so you can suppress the warning by explicitly setting `suppress_warnings` to true.
         */
        Matrix decrypt(const EncryptedMatrix &enc_mat, bool suppress_warnings = false) const;

        /* Uniform encryption API, identical to encrypt_matrix
         */
        EncryptedMatrix encrypt(const Matrix &mat, const EncodingUnit &unit, int level = -1) {
            return encrypt_matrix(mat, unit, level);
        }

        /* Uniform encryption API, defined for T=EncryptedRowVector and T=EncryptedColVector,
         * exactly corresponding to `encrypt_row_vector` and `encrypt_col_vector`, respectively.
         * Template parameter must be explicitly specified.
         */
        template <typename T>
        T encrypt(const Vector &, const EncodingUnit &, int level = -1);

        /* Encrypt a vector representing a linear algebra row vector.
         * We first encode the vector as a matrix
         * where each column is `vec`; see encryptedrowvector.h for details.
         */
        EncryptedRowVector encrypt_row_vector(const Vector &vec, const EncodingUnit &unit, int level = -1);

        /* Decrypt a row vector with any ciphertext degree and any scale.
         * This function will log a message if you try to decrypt a ciphertext which
         * is not at level 0. Sometimes it is expected for a ciphertext to be at a higher
         * level, so you can suppress the warning by explicitly setting `suppress_warnings` to true.
         */
        Vector decrypt(const EncryptedRowVector &enc_vec, bool suppress_warnings = false) const;

        /* Encrypt a vector representing a linear algebra column vector.
         * We first encode the vector as a matrix
         * where each row is `vec`; see encryptedcolvector.h for details.
         */
        EncryptedColVector encrypt_col_vector(const Vector &vec, const EncodingUnit &unit, int level = -1);

        /* Decrypt a column vector with any ciphertext degree and any scale.
         * This function will log a message if you try to decrypt a ciphertext which
         * is not at level 0. Sometimes it is expected for a ciphertext to be at a higher
         * level, so you can suppress the warning by explicitly setting `suppress_warnings` to true.
         */
        Vector decrypt(const EncryptedColVector &enc_vec, bool suppress_warnings = false) const;


        /**************************************
         * Standard Linear Algebra Operations *
         **************************************/


        /* Add two encrypted linear algebra objects, component-wise.
         * Template Instantiations:
         *   - EncryptedMatrix add(const EncryptedMatrix&, const EncryptedMatrix&)
         *   - EncryptedRowVector add(const EncryptedRowVector&, const EncryptedRowVector&)
         *   - EncryptedColVector add(const EncryptedColVector&, const EncryptedColVector&)
         * Input Linear Algebra Constraints:
         *       Both inputs must have matching dimensions and be encoded with the same unit.
         * Input Ciphertext Constraints:
         *       Inputs must be at the same level and have matching scales.
         *       Note that ciphertext degrees do not need to match.
         * Output Linear Algebra Properties:
         *       Same as inputs.
         * Output Ciphertext Properties:
         *       A ciphertext whose level and scale is the same as the inputs, and whose
         *       degree is the maximum of the two input degrees.
         */
        template <typename T>
        T add(const T &arg1, const T &arg2) {
            T temp = arg1;
            add_inplace(temp, arg2);
            return temp;
        }


        /* Add two encrypted linear algebra objects, component-wise.
         * Template Instantiations:
         *   - void add_inplace(const EncryptedMatrix&, const EncryptedMatrix&)
         *   - void add_inplace(const EncryptedRowVector&, const EncryptedRowVector&)
         *   - void add_inplace(const EncryptedColVector&, const EncryptedColVector&)
         * Input Linear Algebra Constraints:
         *       Both inputs must have matching dimensions and be encoded with the same unit.
         * Input Ciphertext Constraints:
         *       Inputs must be at the same level and have matching scales.
         *       Note that ciphertext degrees do not need to match.
         * Output Linear Algebra Properties:
         *       Same as input.
         * Output Ciphertext Properties:
         *       A ciphertext whose level and scale is the same as the inputs,
         *       and whose degree is the maximum of the two input degrees.
         */
        template <typename T>
        void add_inplace(T &arg1, const T &arg2) {
            if (!arg1.initialized() || !arg2.initialized()) {
                LOG_AND_THROW_STREAM("Inputs to add_inplace are not initialized");
            }
            if (!arg1.same_size(arg2)) {
                LOG_AND_THROW_STREAM("Inputs to add_inplace do not have the same dimensions: "
                           << dim_string(arg1) << " vs " << dim_string(arg2));
            }
            if (arg1.he_level() != arg2.he_level()) {
                LOG_AND_THROW_STREAM("Inputs to add_inplace do not have the same level: "
                           << arg1.he_level() << "!=" << arg2.he_level());
            }
            if (arg1.scale() != arg2.scale()) {
                LOG_AND_THROW_STREAM("Inputs to add_inplace do not have the same scale: "
                           << log2(arg1.scale()) << "bits !=" << log2(arg2.scale()) << " bits");
            }
            for (size_t i = 0; i < arg1.num_cts(); i++) {
                eval.add_inplace(arg1[i], arg2[i]);
            }
        }


        /* Add a public plaintext component-wise to an encrypted plaintext.
         * Template Instantiations:
         *   - EncryptedMatrix add_plain(const EncryptedMatrix&, const Matrix&)
         *   - EncryptedRowVector add_plain(const EncryptedRowVector&, const Vector&)
         *   - EncryptedColVector add_plain(const EncryptedColVector&, const Vector&)
         * Input Linear Algebra Constraints:
         *       Both inputs must have matching dimensions.
         * Input Ciphertext Constraints: None
         * Output Linear Algebra Properties:
         *       Same as input.
         * Output Ciphertext Properties:
         *       A encrypted object with the same ciphertext properties as the encrypted input.
         */
        template <typename T1, typename T2>
        T1 add_plain(const T1 &arg1, const T2 &arg2) {
            T1 temp = arg1;
            add_plain_inplace(temp, arg2);
            return temp;
        }


        /* Add a public matrix component-wise to an encrypted matrix.
         * Input Linear Algebra Constraints:
         *       Both inputs must have matching dimensions.
         * Input Ciphertext Constraints: None
         * Output Linear Algebra Properties:
         *       Same as input.
         * Output Ciphertext Properties:
         *       An encrypted matrix with the same ciphertext properties as the encrypted input.
         */
        void add_plain_inplace(EncryptedMatrix &enc_mat1, const Matrix &mat2);


        /* Add a public row vector component-wise to an encrypted row vector.
         * Input Linear Algebra Constraints:
         *       Both inputs must have matching dimensions.
         * Input Ciphertext Constraints: None
         * Output (Inplace): An encrypted row vector with the same ciphertext
         *                   properties as the encrypted input.
         */
        void add_plain_inplace(EncryptedRowVector &enc_vec1, const Vector &vec2);


        /* Add a public column vector component-wise to an encrypted column vector.
         * Input Linear Algebra Constraints:
         *       Both inputs must have matching dimensions.
         * Input Ciphertext Constraints: None
         * Output Linear Algebra Properties:
         *       Same as input.
         * Output Ciphertext Properties:
         *       An encrypted column vector with the same ciphertext
         *       properties as the encrypted input.
         */
        void add_plain_inplace(EncryptedColVector &enc_vec1, const Vector &vec2);


        /* Add a list of encrypted objects together, component-wise.
         * Template Instantiations:
         *   - EncryptedMatrix add_many(const vector<EncryptedMatrix>&)
         *   - EncryptedRowVector add_many(const vector<EncryptedRowVector>&)
         *   - EncryptedColVector add_many(const vector<EncryptedColVector>&)
         * Input Linear Algebra Constraints:
         *       All elements of the list must have the same dimensions and be
         *       encoded with the same unit.
         * Input Ciphertext Constraints:
         *       The inputs must be at the same level, and their scales must be equal.
         *       Note that ciphertext degrees do not need to match.
         * Other Input Constraints: The list must be non-empty.
         * Output Linear Algebra Properties:
         *       Same as input units.
         * Output Ciphertext Properties:
         *       A ciphertext whose level and scale is the same as the inputs,
         *       and whose degree is the maximum of the input degrees.
         */
        template <typename T>
        T add_many(const std::vector<T> &args) {
            if (args.empty()) {
                LOG_AND_THROW_STREAM("Vector of summands to add_many cannot be empty.");
            }
            // no further validation needed since we call a LinearAlgebra function
            T temp = args[0];
            for (size_t i = 1; i < args.size(); i++) {
                add_inplace(temp, args[i]);
            }
            return temp;
        }


        /* Subtract one encrypted linear algebra object from another, component-wise.
         * Template Instantiations:
         *   - EncryptedMatrix sub(const EncryptedMatrix&, const EncryptedMatrix&)
         *   - EncryptedRowVector sub(const EncryptedRowVector&, const EncryptedRowVector&)
         *   - EncryptedColVector sub(const EncryptedColVector&, const EncryptedColVector&)
         * Input Linear Algebra Constraints:
         *       Both inputs must have matching dimensions and be encoded with the same unit.
         * Input Ciphertext Constraints:
         *       Inputs must be at the same level and have matching scales.
         *       Note that ciphertext degrees do not need to match.
         * Output Linear Algebra Properties:
         *       Same as inputs.
         * Output Ciphertext Properties:
         *       A ciphertext whose level and scale is the same as the inputs, and whose
         *       degree is the maximum of the two input degrees.
         */
        template <typename T>
        T sub(const T &arg1, const T &arg2) {
            T temp = arg1;
            sub_inplace(temp, arg2);
            return temp;
        }


        /* Subtract one encrypted linear algebra object from another, component-wise.
         * Template Instantiations:
         *   - void sub_inplace(const EncryptedMatrix&, const EncryptedMatrix&)
         *   - void sub_inplace(const EncryptedRowVector&, const EncryptedRowVector&)
         *   - void sub_inplace(const EncryptedColVector&, const EncryptedColVector&)
         * Input Linear Algebra Constraints:
         *       Both inputs must have matching dimensions and be encoded with the same unit.
         * Input Ciphertext Constraints:
         *       Inputs must be at the same level and have matching scales.
         *       Note that ciphertext degrees do not need to match.
         * Output Linear Algebra Properties:
         *       Same as input.
         * Output Ciphertext Properties:
         *       A ciphertext whose level and scale is the same as the inputs,
         *       and whose degree is the maximum of the two input degrees.
         */
        template <typename T>
        void sub_inplace(T &arg1, const T &arg2) {
            if (!arg1.initialized() || !arg2.initialized()) {
                LOG_AND_THROW_STREAM("Inputs to sub_inplace are not initialized");
            }
            if (!arg1.same_size(arg2)) {
                LOG_AND_THROW_STREAM("Inputs to sub_inplace do not have the same dimensions: "
                           << dim_string(arg1) << " vs " << dim_string(arg2));
            }
            if (arg1.he_level() != arg2.he_level()) {
                LOG_AND_THROW_STREAM("Inputs to sub_inplace do not have the same level: "
                           << arg1.he_level() << "!=" << arg2.he_level());
            }
            if (arg1.scale() != arg2.scale()) {
                LOG_AND_THROW_STREAM("Inputs to sub_inplace do not have the same scale: "
                           << log2(arg1.scale()) << "bits !=" << log2(arg2.scale()) << " bits");
            }
            for (size_t i = 0; i < arg1.num_cts(); i++) {
                eval.sub_inplace(arg1[i], arg2[i]);
            }
        }


        /* Subtract a public plaintext from an encrypted linear algebra object, component-wise.
         * Template Instantiations:
         *   - EncryptedMatrix sub_plain(const EncryptedMatrix&, const Matrix&)
         *   - EncryptedRowVector sub_plain(const EncryptedRowVector&, const Vector&)
         *   - EncryptedColVector sub_plain(const EncryptedColVector&, const Vector&)
         * Input Linear Algebra Constraints:
         *       Both inputs must have matching dimensions.
         * Input Ciphertext Constraints: None
         * Output Linear Algebra Properties:
         *       Same as input.
         * Output Ciphertext Properties:
         *       A encrypted object with the same ciphertext properties as the encrypted input.
         */
        template <typename T1, typename T2>
        T1 sub_plain(const T1 &arg1, const T2 &arg2) {
            T1 temp = arg1;
            sub_plain_inplace(temp, arg2);
            return temp;
        }


        /* Subtract a public matrix from an encrypted matrix, component-wise.
         * Input Linear Algebra Constraints:
         *       Both inputs must have matching dimensions.
         * Input Ciphertext Constraints: None
         * Output Linear Algebra Properties:
         *       Same as input.
         * Output Ciphertext Properties:
         *       An encrypted matrix with the same ciphertext properties as the encrypted input.
         */
        void sub_plain_inplace(EncryptedMatrix &enc_mat1, const Matrix &mat2);


        /* Subtract a public row vector from an encrypted row vector, component-wise.
         * Input Linear Algebra Constraints:
         *       Both inputs must have matching dimensions.
         * Input Ciphertext Constraints: None
         * Output (Inplace): An encrypted row vector with the same ciphertext
         *                   properties as the encrypted input.
         */
        void sub_plain_inplace(EncryptedRowVector &enc_vec1, const Vector &vec2);


        /* Subtract a public column vector from an encrypted column vector, component-wise.
         * Input Linear Algebra Constraints:
         *       Both inputs must have matching dimensions.
         * Input Ciphertext Constraints: None
         * Output Linear Algebra Properties:
         *       Same as input.
         * Output Ciphertext Properties:
         *       An encrypted column vector with the same ciphertext properties as the encrypted input.
         */
        void sub_plain_inplace(EncryptedColVector &enc_vec1, const Vector &vec2);


        /* Negate an encrypted linear algebra object.
         * Template Instantiations:
         *   - EncryptedMatrix negate(const EncryptedMatrix&)
         *   - EncryptedRowVector negate(const EncryptedRowVector&)
         *   - EncryptedColVector negate(const EncryptedColVector&)
         * Input Linear Algebra Constraints: None
         * Input Ciphertext Constraints: None
         * Output Linear Algebra Properties:
         *      Same encoding unit as input.
         * Output Ciphertext Properties:
         *      Same properties as the input.
         */
        template <typename T>
        T negate(const T &arg) {
            T temp = arg;
            negate_inplace(temp);
            return temp;
        }


        /* Negate an encrypted linear algebra object.
         * Template Instantiations:
         *   - void negate_inplace(const EncryptedMatrix&)
         *   - void negate_inplace(const EncryptedRowVector&)
         *   - void negate_inplace(const EncryptedColVector&)
         * Input Linear Algebra Constraints: None
         * Input Ciphertext Constraints: None
         * Output Linear Algebra Properties:
         *      Same encoding unit as input.
         * Output Ciphertext Properties:
         *      Same properties as the input.
         */
        template <typename T>
        void negate_inplace(T &arg) {
            if (!arg.initialized()) {
                LOG_AND_THROW_STREAM("Encrypted input to sub_plain is not initialized.");
            }
            for (size_t i = 0; i < arg.num_cts(); i++) {
                eval.negate_inplace(arg[i]);
            }
        }


        /* Scale an encrypted object by a constant.
         * Template Instantiations:
         *   - EncryptedMatrix multiply_plain(const EncryptedMatrix&, double scalar)
         *   - EncryptedRowVector multiply_plain(const EncryptedRowVector&, double scalar)
         *   - EncryptedColVector multiply_plain(const EncryptedColVector&, double scalar)
         * Input Linear Algebra Constraints: None
         * Input Ciphertext Constraints:
                 First argument must be a linear or quadratic ciphertext with nominal scale.
         * Output Linear Algebra Properties:
         *       Same as input.
         * Output Ciphertext Properties:
         *       A ciphertext with the same ciphertext degree as the input, but with squared scale.
         * NOTE: The scalar zero produces a transparent ciphertext since all ciphertext polynomial coefficients
         *       are zero. Rather than throw an exception, this implementation returns a fresh encryption of a
         *       all-zero plaintext.
         */
        template <typename T>
        T multiply_plain(const T &arg1, double scalar) {
            T temp = arg1;
            multiply_plain_inplace(temp, scalar);
            return temp;
        }


        /* Scale an encrypted object by a constant.
         * Template Instantiations:
         *   - void multiply_plain_inplace(const EncryptedMatrix&, double scalar)
         *   - void multiply_plain_inplace(const EncryptedRowVector&, double scalar)
         *   - void multiply_plain_inplace(const EncryptedColVector&, double scalar)
         * Input Linear Algebra Constraints: None
         * Input Ciphertext Constraints:
                 First argument must be a linear or quadratic ciphertext with nominal scale.
         * Output Linear Algebra Properties:
         *       Same as input.
         * Output Ciphertext Properties:
         *       A ciphertext with the same ciphertext degree as the input, but with squared scale.
         * NOTE: The scalar zero produces a transparent ciphertext since all ciphertext polynomial coefficients
         *       are zero. Rather than throw an exception, this implementation returns a fresh encryption of a
         *       all-zero plaintext.
         */
        template <typename T>
        void multiply_plain_inplace(T &arg, double scalar) {
            if (!arg.initialized()) {
                LOG_AND_THROW_STREAM("Encrypted input to multiply_plain is not initialized.");
            }
            if(arg.needs_rescale()) {
                LOG_AND_THROW_STREAM("Encrypted input to multiply_plain must have nominal scale.");
            }
            for (size_t i = 0; i < arg.num_cts(); i++) {
                eval.multiply_plain_inplace(arg[i], scalar);
            }
        }


        /* Computes a standard (scaled) matrix/matrix product scalar*A*B, except that the inputs
         * are A^T and B. Note that this operation has constant depth, but involves 3*g (parallel)
         * multiplications.
         * Input Linear Algebra Constraints:
         *       Both arguments must be encoded with the same unit. `enc_mat_a_trans` is a g-by-f matrix,
         *       and `enc_mat_b` is a g-by-h matrix.
         * Input Ciphertext Constraints:
         *       Both inputs must be linear ciphertexts with nominal scale. `enc_mat_a_trans` must be
         *       at level i >= 3, and `enc_mat_b` must be at level i-1.
         * Other Input Constraints:
         *       Optional scalar defaults to 1.
         * Output Linear Algebra Properties:
         *       An f-by-h matrix scalar*A*B encoded with the same unit as the input.
         * Output Ciphertext Properties:
         *       A linear ciphertext with a squared scale at level i-2.
         */
        EncryptedMatrix multiply(const EncryptedMatrix &enc_mat_a_trans, const EncryptedMatrix &enc_mat_b,
                                 double scalar = 1);


        /* Computes a standard row vector/matrix product, except that the output is transposed.
         * Input Linear Algebra Constraints:
         *       Both arguments must be encoded with the same unit. `enc_vec` is a f-dimensional vector,
         *       and `enc_mat` is a f-by-g matrix.
         * Input Ciphertext Constraints:
         *       Both inputs must be linear ciphertexts with nominal scale at level i >= 1.
         * Output Linear Algebra Properties:
         *       An g-dimensional column vector matrix encoded with the same unit as the input.
         * Output Ciphertext Properties:
         *       A linear ciphertext with a squared scale at level i.
         */
        EncryptedColVector multiply(const EncryptedRowVector &enc_vec, const EncryptedMatrix &enc_mat);


        /* Computes a standard matrix/column vector product, except that the output is transposed.
         * Input Linear Algebra Constraints:
         *       Both arguments must be encoded with the same unit. `enc_mat` is a f-by-g matrix
         *       and `enc_vec` is a g-dimensional vector.
         * Input Ciphertext Constraints:
         *       Both inputs must be linear ciphertexts with nominal scale at level i >= 2.
         * Output Linear Algebra Properties:
         *       An f-dimensional row vector matrix encoded with the same unit as the input.
         * Output Ciphertext Properties:
         *       A linear ciphertext with a squared scale at level i-1.
         */
        EncryptedRowVector multiply(const EncryptedMatrix &enc_mat, const EncryptedColVector &enc_vec,
                                    double scalar = 1);


        /******************************************
         * Non-standard Linear Algebra Operations *
         ******************************************/


        /* Add a scalar to each coefficient of the encrypted value.
         * Template Instantiations:
         *   - EncryptedMatrix add_plain(const EncryptedMatrix&, double scalar)
         *   - EncryptedRowVector add_plain(const EncryptedRowVector&, double scalar)
         *   - EncryptedColVector add_plain(const EncryptedColVector&, double scalar)
         * Input Linear Algebra Constraints: None
         * Input Ciphertext Constraints: None
         * Output Linear Algebra Properties:
         *      Same encoding unit as input.
         * Output Ciphertext Properties:
         *      Same properties as the input.
         */
        template <typename T>
        T add_plain(const T &arg1, double scalar) {
            T temp = arg1;
            add_plain_inplace(temp, scalar);
            return temp;
        }


        /* Add a scalar to each coefficient of the encrypted value.
         * Template Instantiations:
         *   - void add_plain_inplace(const EncryptedMatrix&, double scalar)
         *   - void add_plain_inplace(const EncryptedRowVector&, double scalar)
         *   - void add_plain_inplace(const EncryptedColVector&, double scalar)
         * Input Linear Algebra Constraints: None
         * Input Ciphertext Constraints: None
         * Output Linear Algebra Properties:
         *      Same encoding unit as input.
         * Output Ciphertext Properties:
         *      Same properties as the input.
         */
        template <typename T>
        void add_plain_inplace(T &arg, double scalar) {
            if (!arg.initialized()) {
                LOG_AND_THROW_STREAM("Encrypted input to add_plain is not initialized.");
            }
            for (size_t i = 0; i < arg.num_cts(); i++) {
                eval.add_plain_inplace(arg[i], scalar);
            }
        }


        /* Subtract a scalar from each coefficient of the encrypted value.
         * Template Instantiations:
         *   - EncryptedMatrix sub_plain(const EncryptedMatrix&, double scalar)
         *   - EncryptedRowVector sub_plain(const EncryptedRowVector&, double scalar)
         *   - EncryptedColVector sub_plain(const EncryptedColVector&, double scalar)
         * Input Linear Algebra Constraints: None
         * Input Ciphertext Constraints: None
         * Output Linear Algebra Properties:
         *      Same encoding unit as input.
         * Output Ciphertext Properties:
         *      Same properties as the input.
         */
        template <typename T>
        T sub_plain(const T &arg1, double scalar) {
            T temp = arg1;
            sub_plain_inplace(temp, scalar);
            return temp;
        }


        /* Subtract a scalar from each coefficient of the encrypted value.
         * Template Instantiations:
         *   - void sub_plain_inplace(const EncryptedMatrix&, double scalar)
         *   - void sub_plain_inplace(const EncryptedRowVector&, double scalar)
         *   - void sub_plain_inplace(const EncryptedColVector&, double scalar)
         * Input Linear Algebra Constraints: None
         * Input Ciphertext Constraints: None
         * Output Linear Algebra Properties:
         *      Same encoding unit as input.
         * Output Ciphertext Properties:
         *      Same properties as the input.
         */
        template <typename T>
        void sub_plain_inplace(T &arg, double scalar) {
            if (!arg.initialized()) {
                LOG(ERROR) << "Encrypted input to sub_plain is not initialized.";
                throw std::invalid_argument("An error occurred. See the log for details.");
            }
            for (size_t i = 0; i < arg.num_cts(); i++) {
                eval.sub_plain_inplace(arg[i], scalar);
            }
        }


        /* Coefficient-wise (Hadamard) product of two objects.
         * Template Instantiations:
         *   - EncryptedMatrix hadamard_multiply(const EncryptedMatrix&, const EncryptedMatrix&)
         *   - EncryptedRowVector hadamard_multiply(const EncryptedRowVector&, const EncryptedRowVector&)
         *   - EncryptedColVector hadamard_multiply(const EncryptedColVector&, const EncryptedColVector&)
         * Input Linear Algebra Constraints:
         *      Inputs must have the same dimensions and encoding units.
         * Input Ciphertext Constraints:
         *      Inputs must be linear ciphertexts with nominal scales.
         * Output Linear Algebra Properties:
         *      Same encoding unit as inputs.
         * Output Ciphertext Properties:
         *      A quadratic ciphertext whose level is the same as the inputs,
         *      and whose scale is squared.
         */
        template <typename T>
        T hadamard_multiply(const T &arg1, const T &arg2) {
            T temp = arg1;
            hadamard_multiply_inplace(temp, arg2);
            return temp;
        }


        /* Coefficient-wise (Hadamard) product of two objects.
         * Template Instantiations:
         *   - void hadamard_multiply_inplace(const EncryptedMatrix&, const EncryptedMatrix&)
         *   - void hadamard_multiply_inplace(const EncryptedRowVector&, const EncryptedRowVector&)
         *   - void hadamard_multiply_inplace(const EncryptedColVector&, const EncryptedColVector&)
         * Input Linear Algebra Constraints:
         *      Inputs must have the same dimensions and encoding units.
         * Input Ciphertext Constraints:
         *      Inputs must be linear ciphertexts with nominal scales.
         * Output Linear Algebra Properties:
         *      Same encoding unit as inputs.
         * Output Ciphertext Properties:
         *      A quadratic ciphertext whose level is the same as the inputs,
         *      and whose scale is squared.
         */
        template <typename T>
        void hadamard_multiply_inplace(T &arg1, const T &arg2) {
            if (!arg2.initialized() || !arg1.initialized()) {
                LOG_AND_THROW_STREAM("Inputs to hadamard_multiply are not initialized.");
            }
            if (arg1.encoding_unit() != arg2.encoding_unit()) {
                LOG_AND_THROW_STREAM("Inputs to hadamard_multiply must have the same units: "
                           << dim_string(arg1.encoding_unit()) << "!="
                           << dim_string(arg2.encoding_unit()));
            }
            if (!arg1.same_size(arg2)) {
                LOG_AND_THROW_STREAM("Dimension mismatch in hadamard_multiply: " + dim_string(arg1)
                           << " vs " + dim_string(arg2));
            }
            if (arg1.he_level() != arg2.he_level()) {
                LOG_AND_THROW_STREAM("Inputs to hadamard_multiply must have the same level: "
                           << arg1.he_level() << "!=" << arg2.he_level());
            }
            if (arg1.scale() != arg2.scale()) {
                LOG_AND_THROW_STREAM("Inputs to hadamard_multiply must have the same scale: "
                           << log2(arg1.scale()) << "bits != " << log2(arg2.scale()) << " bits");
            }
            if (arg1.needs_rescale() || arg2.needs_rescale()) {
                LOG_AND_THROW_STREAM("Inputs to hadamard_multiply must have nominal scale: "
                           << "Vector: " << arg1.needs_rescale()
                           << ", Matrix: " << arg2.needs_rescale());
            }
            if (arg1.needs_relin() || arg2.needs_relin()) {
                LOG_AND_THROW_STREAM("Inputs to hadamard_multiply must be linear ciphertexts: "
                           << "Vector: " << arg1.needs_relin()
                           << ", Matrix: " << arg2.needs_relin());
            }

            for (size_t i = 0; i < arg1.num_cts(); i++) {
                eval.multiply_inplace(arg1[i], arg2[i]);
            }
        }


        /* Square each coefficient of an object.
         * Template Instantiations:
         *   - EncryptedMatrix hadamard_square(const EncryptedMatrix&)
         *   - EncryptedRowVector hadamard_square(const EncryptedRowVector&)
         *   - EncryptedColVector hadamard_square(const EncryptedColVector&)
         * Input Linear Algebra Constraints: None
         * Input Ciphertext Constraints:
         *      Input must be a linear ciphertext with nominal scale.
         * Output Linear Algebra Properties:
         *      Same encoding unit as input.
         * Output Ciphertext Properties:
         *      A quadratic ciphertext whose level is the same as the input,
         *      and whose scale is squared.
         */
        template <typename T>
        T hadamard_square(const T &arg) {
            T temp = arg;
            hadamard_square_inplace(temp);
            return temp;
        }


        /* Square each coefficient of an object.
         * Template Instantiations:
         *   - void hadamard_square_inplace(const EncryptedMatrix&)
         *   - void hadamard_square_inplace(const EncryptedRowVector&)
         *   - void hadamard_square_inplace(const EncryptedColVector&)
         * Input Linear Algebra Constraints: None
         * Input Ciphertext Constraints:
         *      Input must be a linear ciphertext with nominal scale.
         * Output Linear Algebra Properties:
         *      Same encoding unit as input.
         * Output Ciphertext Properties:
         *      A quadratic ciphertext whose level is the same as the input,
         *      and whose scale is squared.
         */
        template <typename T>
        void hadamard_square_inplace(T &arg) {
            if (!arg.initialized()) {
                LOG_AND_THROW_STREAM("Input to hadamard_square is not initialized");
            }
            if(arg.needs_relin()) {
                LOG_AND_THROW_STREAM("Input to hadamard_square must be a linear ciphertext");
            }
            if(arg.needs_rescale()) {
                LOG_AND_THROW_STREAM("Input to hadamard_square must have nominal scale");
            }

            for (size_t i = 0; i < arg.num_cts(); i++) {
                eval.square_inplace(arg[i]);
            }
        }


        /* Hadamard product of a row vector with each column of a matrix.
         * Input Linear Algebra Constraints:
         *      Input dimensions must be compatibile for standard row-vector/matrix
         *      product, i.e., the length of the vector must be the same as the
         *      height of the matrix. Inputs must be encoded with respect to the
         *      same encoding unit.
         * Input Ciphertext Constraints:
         *      Input must both be linear ciphertexts at the same HE level and with nominal scale.
         * Output Linear Algebra Properties:
         *      Same encoding unit as inputs.
         * Output Ciphertext Properties:
         *      A quadratic ciphertext whose level is the same as the input,
         *      and whose scale is squared.
         */
        EncryptedMatrix hadamard_multiply(const EncryptedRowVector &enc_vec, const EncryptedMatrix &enc_mat);


        /* Hadamard product of a column vector with each row of a matrix.
         * Input Linear Algebra Constraints:
         *      Input dimensions must be compatibile for standard matrix/column-vector product,
         *      i.e., the length of the vector must be the same as the width of the matrix.
         *      Inputs must be encoded with respect to the same encoding unit.
         * Input Ciphertext Constraints:
         *      Input must both be linear ciphertexts at the same HE level and with nominal scale.
         * Output Linear Algebra Properties:
         *      Same encoding unit as inputs.
         * Output Ciphertext Properties:
         *      A quadratic ciphertext whose level is the same as the input,
         *      and whose scale is squared.
         */
        EncryptedMatrix hadamard_multiply(const EncryptedMatrix &enc_mat, const EncryptedColVector &enc_vec);


        /* Sum the columns of a matrix, and encode the result as a row vector.
         * This is a key algorithm for (standard) matrix/column-vector multiplication,
         * which is achieved by performing a hadamard product between the matrix and column
         * vector (see hadamard_multiply()), and then summing the columns of the result.
         * This algorithm can optionally scale the result by a constant.
         * Input Linear Algebra Constraints: None
         * Input Ciphertext Constraints:
         *      Input must be a linear ciphertext with nominal scale.
         * Other Input Constraints:
         *      Optional scalar is 1 if not specified.
         * Output Linear Algebra Properties:
         *      A row vector which is the (transposed) sum of the columns of the input matrix,
         *      encoded with the same unit as the input.
         * Output Ciphertext Properties:
         *      A linear ciphertext at the same level as the input, but with squared scale.
         * NOTE: This function is a linear map:
         *            sum_cols(mat1, c) + sum_cols(mat2, c) = sum_cols(mat1 + mat2, c)
         *       It's fairly expensive to evaluate, so taking advantage of this map
         *       is recommended; see `sum_cols_many()` for more information.
         */
        EncryptedRowVector sum_cols(const EncryptedMatrix &enc_mat, double scalar = 1);


        /* Sum the rows of a matrix, and encode the result as a column vector.
         * This is a key algorithm for (standard) row-vector/matrix multiplication,
         * which is achieved by performing a hadamard product between the row vector and matrix
         * (see hadamard_multiply()), and then summing the rows of the result.
         * Input Linear Algebra Constraints: None
         * Input Ciphertext Constraints:
         *      Input must be a linear ciphertext (no scale constraint).
         * Output Linear Algebra Properties:
         *      A column vector which is the (transposed) sum of the rows of the input matrix,
         *      encoded with the same unit as the input.
         * Output Ciphertext Properties:
         *      A linear ciphertext with the same scale and level as the input.
         * NOTE: This function is a linear map:
         *            sum_rows(mat1) + sum_rows(mat2) = sum_rows(mat1 + mat2)
         *       It's fairly expensive to evaluate, so taking advantage of this map
         *       is recommended; see `sum_rows_many()` for more information.
         */
        EncryptedColVector sum_rows(const EncryptedMatrix &enc_mat);


        /* This function enables the use of the sum_cols linear map across matrices of incompatibile dimensions.
         * If A is f-by-g1 and B is f-by-g2, then sum_cols(A, scalar) + sum_cols(B, scalar) is a f-dimensional row
         * vector. This function returns the same result, but without invoking sum_cols multiple times.
         * Input Linear Algebra Constraints:
         *      Each matrix in the input must be encoded with the same unit and have the same height `f`.
         * Input Ciphertext Constraints:
         *      Each ciphertext must be linear, and all ciphertexts must be at the same level
         *      and have nominal scale.
         * Other Input Constraints:
         *      The input vector must be non-empty.
         * Output Linear Algebra Properties:
         *      An f-dimensional row vector which is \sum_i{sum_cols(enc_mats[i], scalar)} (but more efficient),
         *      encoded with the same unit as the inputs.
         * Output Ciphertext Properties:
         *      A linear ciphertext with squared scale and same level as the input.
         */
        EncryptedRowVector sum_cols_many(const std::vector<EncryptedMatrix> &enc_mats, double scalar = 1);


        /* This function enables the use of the sum_rows linear map across matrices of incompatibile dimensions.
         * If A is f1-by-g and B is f2-by-g, then sum_rows(A) + sum_rows(B) is a g-dimensional column vector.
         * This function returns the same result, but without invoking sum_rows multiple times.
         * Input Linear Algebra Constraints:
         *      Each matrix in the input must be encoded with the same unit and have the same width `g`.
         * Input Ciphertext Constraints:
         *      Each ciphertext must be linear, and all ciphertexts must be at the same level
         *      and have the same scale (can be nominal or squared).
         * Other Input Constraints:
         *      The input vector must be non-empty.
         * Output Linear Algebra Properties:
         *      An g-dimensional column vector which is \sum_i{sum_rows(enc_mats[i])} (but more efficient),
         *      encoded with the same unit as the inputs.
         * Output Ciphertext Properties:
         *      A linear ciphertext with the same scale and level as the inputs.
         */
        EncryptedColVector sum_rows_many(const std::vector<EncryptedMatrix> &enc_mats);


        /*************************************
         * Ciphertext Maintenance Operations *
         *************************************/
        // These operations do not affect encoding unit or other linear algebra properties.


        /* Reduce the HE level of `ct` to the level of the `target`.
         * Input: The first argument must be a linear encrypted linear algebra object
         *        with nominal scale and level i, and the second argument must be a
         *        (possibly different) encrypted linear algebra type at level j <= i.
         * Output: A linear ciphertext with nominal scale and level j, encrypting
         *         the same plaintext as the input.
         * NOTE: It is an error if the level of `arg2` is higher than the level of `arg1`.
         */
        template <typename T1, typename T2>
        T1 reduce_level_to(const T1 &arg1, const T2 &arg2) {
            return reduce_level_to(arg1, arg2.he_level());
        }


        /* Reduce the HE level of `ct` to the level of the `target`.
         * Input: The first argument must be a linear encrypted linear algebra object
         *        with nominal scale and level i, and the second argument must be a
         *        (possibly different) encrypted linear algebra type at level j <= i.
         * Output (Inplace): A linear ciphertext with nominal scale and level j, encrypting
         *                   the same plaintext as the input.
         * NOTE: It is an error if the level of `arg2` is higher than the level of `arg1`.
         */
        template <typename T1, typename T2>
        void reduce_level_to_inplace(T1 &arg1, const T2 &arg2) {
            reduce_level_to_inplace(arg1, arg2.he_level());
        }


        /* Reduce the HE level of both inputs to the lower of the two levels.
         * This operation modifies at most one of the inputs.
         * Input: Two encrypted linear algebra objects (not necessarily of the same type)
         *        where the ciphertext at the higher level is linear with nominal scale.
         * Output (Inplace): The ciphertext at the higher level is modified
         *                   so that it is a linear ciphertext with nominal scale
         *                   at the level of the other input.
         * NOTE: If both inputs are at the same level, neither ciphertext is changed.
         */
        template <typename T1, typename T2>
        void reduce_level_to_min_inplace(T1 &arg1, T2 &arg2) {
            if (!arg1.initialized() || !arg2.initialized()) {
                LOG_AND_THROW_STREAM("Inputs to reduce_level_to_min_inplace are not initialized");
            }

            for (size_t i = 0; i < arg1.num_cts(); i++) {
                eval.reduce_level_to_min_inplace(arg1[i], arg2[i]);
            }
        }


        /* Reduce the HE level of the first argument to the target level.
         * Inputs: A linear EncryptedMatrix, EncryptedRowVector, or EncryptedColVector
         *         with nominal scale and level i, and a target level 0 <= j <= i.
         * Output : A linear ciphertext with nominal scale and level j, encrypting
         *          the same plaintext as the input.
         */
        template <typename T>
        T reduce_level_to(const T &arg, int level) {
            T temp = arg;
            reduce_level_to_inplace(temp, level);
            return temp;
        }


        /* Reduce the HE level of the first argument to the target level.
         * Inputs: A linear EncryptedMatrix, EncryptedRowVector, or EncryptedColVector
         *         with nominal scale and level i, and a target level 0 <= j <= i.
         * Output (Inplace): A linear ciphertext with nominal scale and level j, encrypting
         *                   the same plaintext as the input.
         */
        template <typename T>
        void reduce_level_to_inplace(T &arg, int level) {
            if (!arg.initialized()) {
                LOG_AND_THROW_STREAM("Input to reduce_level_to is not initialized");
            }

            for (size_t i = 0; i < arg.num_cts(); i++) {
                eval.reduce_level_to_inplace(arg[i], level);
            }
        }


        /* Remove a prime from the modulus (i.e. go down one level) and scale
         * down the plaintext by that prime.
         * Inputs: A linear or quadratic EncryptedMatrix, EncryptedRowVector, or EncryptedColVector
         *         at level i > 0.
         * Output: A ciphertext with the same degree as the input with nominal scale and level i-1.
         */
        template <typename T>
        T rescale_to_next(const T &arg) {
            T temp = arg;
            rescale_to_next_inplace(temp);
            return temp;
        }


        /* Remove a prime from the modulus (i.e. go down one level) and scale
         * down the plaintext by that prime.
         * Inputs: A linear or quadratic EncryptedMatrix, EncryptedRowVector, or EncryptedColVector
         *         at level i > 0.
         * Output (Inplace): A ciphertext with the same degree as the input with nominal scale and level i-1.
         */
        template <typename T>
        void rescale_to_next_inplace(T &arg) {
            if (!arg.initialized()) {
                LOG_AND_THROW_STREAM("Inputs to rescale_to_next is not initialized");
            }

            for (size_t i = 0; i < arg.num_cts(); i++) {
                eval.rescale_to_next_inplace(arg[i]);
            }
        }


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
         * Relinearize the encrypted object.
         * Input: A quadratic EncryptedMatrix, EncryptedRowVector, or EncryptedColVector
         *        with nominal or squared scale.
         * Output (Inplace): A linear ciphertext with the same scale and level as the input.
         * NOTE: Inputs which are linear ciphertexts to begin with are unchanged by this function.
         */
        template <typename T>
        void relinearize_inplace(T &arg) {
            if (!arg.initialized()) {
                LOG_AND_THROW_STREAM("Inputs to relinearize is not initialized");
            }

            for (size_t i = 0; i < arg.num_cts(); i++) {
                eval.relinearize_inplace(arg[i]);
            }
        }

        CKKSEvaluator &eval;

       private:
        template <typename T>
        std::string dim_string(const T &arg);

        /* Algorithm 3 in HHCP'18; see the paper for details.
         * sum the columns of a matrix packed into a single ciphertext
         * The plaintext is a vector representing the row-major format of a matrix with `width` columns.
         * All operations (like the left shift) occur on the vectorized form of the matrix.
         *
         * ASSUMPTIONS:
         *  - c is a linear ciphertext
         *  - c encodes a matrix
         *  - c.width is a power of 2
         *
         * CONSUMES ONE HE LEVEL
         *
         * NOTE: This function could be modified to work for any integer width,
         *       given the complete factorization of the width, though there is some
         *       computational overhead for widths which are not a power of 2.
         *       Specifically, the cost for width p^e is (p-1)*e rotations and (p-1)*e
         *       additions. Viewing each row as a tensor, this can naturally be
         *       extended to work for an arbitrary width, as in LPR'13.
         * The output needs to be rescaled!
         */
        CKKSCiphertext sum_cols_core(const CKKSCiphertext &ct, const EncodingUnit &unit, double scalar);

        /* Algorithm 2 in HHCP'18; see the paper for details.
         * sum the rows of a matrix packed into a single ciphertext
         * All operations (like the left shift) occur on the vectorized form of the matrix.
         *
         * ASSUMPTIONS:
         *  - c is a linear ciphertext
         *  - c encodes a matrix
         *  - c.height is a power of 2
         *  - c.width*c.height = dimension of ciphertext space
         *
         * CONSUMES ZERO HE LEVELS
         *
         * NOTE: This function only works when the plaintext is full-dimensional.
         *       This prevents the need for masking and a second round of shifting
         *       as in colSum, at the cost of flexibility
         * The output needs to be rescaled!
         */
        CKKSCiphertext sum_rows_core(const EncryptedMatrix &enc_mat, int j);

        // helper function for sum_rows and sum_cols which repeatedly shifts by increasing powers of two, adding the
        // results
        void rot(CKKSCiphertext &t1, int max, int stride, bool rotate_left);

        // inner loop for matrix/row vector hadamard multiplication
        std::vector<CKKSCiphertext> matrix_rowvec_hadamard_mul_loop(const EncryptedRowVector &enc_vec,
                                                                    const EncryptedMatrix &enc_mat, int j);

        // inner loop for matrix/column vector hadamard multiplication
        std::vector<CKKSCiphertext> matrix_colvec_hadamard_mul_loop(const EncryptedMatrix &enc_mat,
                                                                    const EncryptedColVector &enc_vec, int i);

        // inner loop for matrix/matrix multiplication
        EncryptedColVector matrix_matrix_mul_loop(const EncryptedMatrix &enc_mat_a_trans,
                                                  const EncryptedMatrix &enc_mat_b, double scalar, int k,
                                                  bool transpose_unit);

        // common core for matrix/matrix multiplication; used by both multiply and multiply_unit_transpose
        std::vector<EncryptedColVector> multiply_common(const EncryptedMatrix &enc_mat_a_trans,
                                                        const EncryptedMatrix &enc_mat_b, double scalar,
                                                        bool transpose_unit);

        // helper function for matrix/matrix multiplication which extracts a single row of A (given the encoding of A^T)
        EncryptedRowVector extract_row(const EncryptedMatrix &enc_mat_a_trans, int row);
    };

}  // namespace hit
