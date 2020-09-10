// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../CKKSInstance.h"
#include "ciphertext.h"
#include "evaluator.h"

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

    struct EncodingUnit {
       public:
        // use `makeUnit` in `LinearAlgebra` to construct an encoding unit
        EncodingUnit() = default;
        friend bool operator==(const EncodingUnit &lhs, const EncodingUnit &rhs);
        friend bool operator!=(const EncodingUnit &lhs, const EncodingUnit &rhs);
        int encoding_height() const;  // height of this encoding unit
        int encoding_width() const;   // width of this encoding unit
       private:
        EncodingUnit(int encoding_height, int encoding_width);
        int encoding_height_ = 0;  // height of the encoding unit
        int encoding_width_ = 0;   // width of the encoding unit
        bool initialized() const;

        friend class LinearAlgebra;
        friend struct EncryptedMatrix;
        friend struct EncryptedRowVector;
        friend struct EncryptedColVector;
    };

    struct EncryptedMatrix : CiphertextMetadata<Matrix> {
       public:
        // use `encrypt_matrix` in `LinearAlgebra` to construct an encrypted matrix
        EncryptedMatrix() = default;

        int height() const;                  // height of the encrypted matrix
        int width() const;                   // width of the encrypted matrix
        int num_vertical_units() const;      // number of encoding units tiled vertically to encode this matrix
        int num_horizontal_units() const;    // number of encoding units tiled horizontally to encode this matrix
        EncodingUnit encoding_unit() const;  // encoding unit used to encode this matrix

        // number of plaintext slots in the CKKS parameters
        int num_slots() const override;
        // encryption level of this matrix
        int he_level() const override;
        // CKKS scale of this matrix
        double scale() const override;
        // Underlying plaintext matrix. This is only available with the Plaintext, Debug, and ScaleEstimator evaluators
        Matrix plaintext() const override;

       private:
        EncryptedMatrix(int height, int width, const EncodingUnit &unit, std::vector<std::vector<CKKSCiphertext>> &cts);

        bool initialized() const;

        int height_ = 0;    // height of the encoded matrix
        int width_ = 0;     // width of the encoded matrix
        EncodingUnit unit;  // encoding unit
        // two-dimensional grid of encoding units composing this encrypted matrix
        // First index is the row, second index is the column
        std::vector<std::vector<CKKSCiphertext>> cts;

        // simple iterator
        size_t num_cts() const;
        CKKSCiphertext &operator[](size_t idx);
        const CKKSCiphertext &operator[](size_t idx) const;

        // compare this matrix to another matrix to determine if they have the same size (dimensions and encoding unit)
        bool same_size(const EncryptedMatrix &mat) const;

        friend class LinearAlgebra;
    };

    struct EncryptedRowVector : CiphertextMetadata<Vector> {
       public:
        // use `encrypt_row_vector` in `LinearAlgebra` to construct an encrypted row vector
        EncryptedRowVector() = default;

        int width() const;
        int num_units() const;
        EncodingUnit encoding_unit() const;

        // number of plaintext slots in the CKKS parameters
        int num_slots() const override;
        // encryption level of this vector
        int he_level() const override;
        // CKKS scale of this vector
        double scale() const override;
        // Underlying plaintext vector. This is only available with the Plaintext, Debug, and ScaleEstimator evaluators
        Vector plaintext() const override;

       private:
        EncryptedRowVector(int width, const EncodingUnit &unit, std::vector<CKKSCiphertext> &cts);

        bool initialized() const;

        int width_ = 0;                   // width of the encoded matrix
        EncodingUnit unit;                // encoding unit
        std::vector<CKKSCiphertext> cts;  // ciphertexts composing this encrypted matrix

        // simple iterator
        size_t num_cts() const;
        CKKSCiphertext &operator[](size_t idx);
        const CKKSCiphertext &operator[](size_t idx) const;

        // compare this row vector to another to determine if they have the same size (dimension and encoding unit)
        bool same_size(const EncryptedRowVector &vec) const;

        friend class LinearAlgebra;
    };

    struct EncryptedColVector : CiphertextMetadata<Vector> {
       public:
        // use `encrypt_row_vector` in `LinearAlgebra` to construct an encrypted row vector
        EncryptedColVector() = default;

        int height() const;
        int num_units() const;
        EncodingUnit encoding_unit() const;

        // number of plaintext slots in the CKKS parameters
        int num_slots() const override;
        // encryption level of this vector
        int he_level() const override;
        // CKKS scale of this vector
        double scale() const override;
        // Underlying plaintext vector. This is only available with the Plaintext, Debug, and ScaleEstimator evaluators
        Vector plaintext() const override;

       private:
        EncryptedColVector(int height, const EncodingUnit &unit, std::vector<CKKSCiphertext> &cts);

        bool initialized() const;

        int height_ = 0;                  // height of the encoded vector
        EncodingUnit unit;                // encoding unit
        std::vector<CKKSCiphertext> cts;  // ciphertexts composing this encrypted matrix

        // simple iterator
        size_t num_cts() const;
        CKKSCiphertext &operator[](size_t idx);
        const CKKSCiphertext &operator[](size_t idx) const;

        // compare this column vector to another to determine if they have the same size (dimension and encoding unit)
        bool same_size(const EncryptedColVector &vec) const;

        friend class LinearAlgebra;
    };

    // Evaluation and Encryption API for Linear Algebra objects
    class LinearAlgebra {
       public:
        /* Wraps a CKKSInstance to create a high-level API for linear algebra encoding, encryption, and operations
         */
        explicit LinearAlgebra(CKKSInstance &inst);

        /* Creates a valid encoding unit for this instance, i.e., one which holds exactly as many
         * coefficients as there are plaintext slots.
         * Inputs: None
         * Output: An encoding unit which has height `encoding_height` and width `num_slots()/encoding_height`
         */
        EncodingUnit make_unit(int encoding_height) const;

        /* Encrypt a matrix after encoding it with the provided encoding unit.
         * Matrix is encrypted at the specified level, or at the highest level allowed by the
         * encryption parameters if no level is specified.
         */
        EncryptedMatrix encrypt_matrix(const Matrix &mat, const EncodingUnit &unit, int level = -1);

        /* Decrypt a matrix.
         */
        Matrix decrypt(const EncryptedMatrix &mat) const;

        /* Encrypt a vector representing a linear algebra row vector.
         * We first encode the vector as a matrix
         * where each column is `vec`; see the paper for details.
         */
        EncryptedRowVector encrypt_row_vector(const Vector &vec, const EncodingUnit &unit, int level = -1);

        /* Decrypt a row vector.
         */
        Vector decrypt(const EncryptedRowVector &vec) const;

        /* Encrypt a vector representing a linear algebra column vector.
         * We first encode the vector as a matrix
         * where each row is `vec`; see the paper for details.
         */
        EncryptedColVector encrypt_col_vector(const Vector &vec, const EncodingUnit &unit, int level = -1);

        /* Decrypt a column vector.
         */
        Vector decrypt(const EncryptedColVector &vec) const;

        /* Computes the sum of two linear algebra objects.
         * Inputs: One of the following options
         *   - EncryptedMatrix, EncryptedMatrix
         *   - EncryptedMatrix, Matrix
         *   - EncryptedRowVector, EncryptedRowVector
         *   - EncryptedRowVector, Vector
         *   - EncryptedColVector, EncryptedColVector
         *   - EncryptedColVector, Vector
         *   where the dimensions of both arguments must be the same.
         * Output: The (encrypted) sum of the two objects
         *
         * Notes: This function has multiplicative depth zero and returns a linear ciphertext.
         */
        template <typename T1, typename T2>
        T1 add(const T1 &arg1, const T2 &arg2) {
            T1 temp = arg1;
            add_inplace(temp, arg2);
            return temp;
        }

        /* Computes the sum of two linear algebra objects, putting the result in the first argument.
         * Inputs: One of the following options
         *   - EncryptedMatrix, EncryptedMatrix
         *   - EncryptedRowVector, EncryptedRowVector
         *   - EncryptedColVector, EncryptedColVector
         *   where the dimensions of both arguments must be the same.
         * Output: None
         *
         * Notes: This function has multiplicative depth zero and returns a linear ciphertext.
         */
        template <typename T>
        void add_inplace(T &arg1, const T &arg2) {
            if (!arg1.initialized() || !arg2.initialized() || arg1.same_size(arg2)) {
                throw std::invalid_argument("Arguments to LinearAlgebra::add_inplace do not have the same dimensions");
            }
            for (size_t i = 0; i < arg1.num_cts(); i++) {
                eval.add_inplace(arg1[i], arg2[i]);
            }
        }

        /* Computes the sum of an encrypted matrix and a public matrix, where the result is stored in the first
         * argument. Inputs: An encrypted matrix and a public matrix, both with the same dimensions. Output: None
         *
         * Notes: This function has multiplicative depth zero and returns a linear ciphertext.
         */
        void add_inplace(EncryptedMatrix &mat1, const Matrix &mat2);

        /* Computes the sum of an encrypted row vector and a public vector, where the result is stored in the first
         * argument. Inputs: An encrypted vector and a public vector, both with the same dimensions. Output: None
         *
         * Notes: This function has multiplicative depth zero and returns a linear ciphertext.
         */
        void add_inplace(EncryptedRowVector &vec1, const Vector &vec2);

        /* Computes the sum of an encrypted column vector and a public vector, where the result is stored in the first
         * argument. Inputs: An encrypted vector and a public vector, both with the same dimensions. Output: None
         *
         * Notes: This function has multiplicative depth zero and returns a linear ciphertext.
         */
        void add_inplace(EncryptedColVector &vec1, const Vector &vec2);

        /* Add a constant to each coefficient of the encrypted plaintext, putting the result in the first argument.
         * Inputs: One of the following options
         *   - EncryptedMatrix, double
         *   - EncryptedRowVector, double
         *   - EncryptedColVector, double
         * Output: None
         *
         * Notes: This function has multiplicative depth zero and returns a linear ciphertext.
         */
        template <typename T>
        void add_inplace(T &arg, double scalar) {
            if (!arg.initialized()) {
                throw std::invalid_argument("LinearAlgebra::add_inplace: argument not initialized.");
            }
            for (size_t i = 0; i < arg.num_cts(); i++) {
                eval.add_plain_inplace(arg[i], scalar);
            }
        }

        /* Add a constant to each coefficient of the encrypted plaintext.
         * Inputs: One of the following options
         *   - EncryptedMatrix, double
         *   - EncryptedRowVector, double
         *   - EncryptedColVector, double
         * Output: An encrypted object where each coefficient is shifted by the scalar.
         *
         * Notes: This function has multiplicative depth zero and returns a linear ciphertext.
         */
        template <typename T>
        T add(const T &arg1, double scalar) {
            T temp = arg1;
            add_inplace(temp, scalar);
            return temp;
        }

        /* Add a list of encrypted objects together.
         * Inputs: One of the following options
         *   - vector<EncryptedMatrix>
         *   - vector<EncryptedRowVector>
         *   - vector<EncryptedColVector>
         * Output: An encrypted object containing the sum of the inputs.
         *
         * Notes: This function has multiplicative depth zero and returns a linear ciphertext.
         * The input vector may not be empty.
         */
        template <typename T>
        T add(const std::vector<T> &args) {
            if (args.empty()) {
                throw std::invalid_argument("Vector of summands to LinearAlgebra::add cannot be empty.");
            }
            // no further validation needed since we call a LinearAlgebra function
            T temp = args[0];
            for (size_t i = 1; i < args.size(); i++) {
                add_inplace(temp, args[i]);
            }
            return temp;
        }

        /* Coefficient-wise (Hadamard) product of two objects.
         * Inputs: One of the following options
         *   - EncryptedMatrix, EncryptedMatrix
         *   - EncryptedRowVector, EncryptedRowVector
         *   - EncryptedColVector, EncryptedColVector
         * Output: An encrypted object containing the hadamard product of the inputs.
         *
         * Notes: This function has multiplicative depth one and returns a quadratic ciphertext
         * at the same level as the input, so it needs to be relinearized and rescaled.
         */
        template <typename T>
        T hadamard_multiply(const T &arg1, const T &arg2) {
            T temp = arg1;
            hadamard_multiply_inplace(temp, arg2);
            return temp;
        }

        /* Coefficient-wise (Hadamard) product of two objects, storing result in first argument.
         * Inputs: One of the following options
         *   - EncryptedMatrix, EncryptedMatrix
         *   - EncryptedRowVector, EncryptedRowVector
         *   - EncryptedColVector, EncryptedColVector
         * Output: None
         *
         * Notes: This function has multiplicative depth one and returns a quadratic ciphertext
         * at the same level as the input, so it needs to be relinearized and rescaled.
         */
        template <typename T>
        void hadamard_multiply_inplace(T &arg1, const T &arg2) {
            if (!arg1.initialized() || !arg2.initialized() || !arg1.same_size(arg2)) {
                throw std::invalid_argument("LinearAlgebra::hadamard_multiply: arguments not initialized.");
            }

            for (size_t i = 0; i < arg1.num_cts(); i++) {
                eval.multiply_inplace(arg1[i], arg2[i]);
            }
        }

        /* Squares each coefficient of an object.
         * Inputs: One of the following options
         *   - EncryptedMatrix
         *   - EncryptedRowVector
         *   - EncryptedColVector
         * Output: An encrypted object where each coefficient is the square of the corresponding
         * coefficient of the input.
         *
         * Notes: This function has multiplicative depth one and returns a quadratic ciphertext
         * at the same level as the input, so it needs to be relinearized and rescaled.
         */
        template <typename T>
        T hadamard_square(const T &arg) {
            T temp = arg;
            hadamard_square_inplace(temp);
            return temp;
        }

        /* Squares each coefficient of an object, inplace.
         * Inputs: One of the following options
         *   - EncryptedMatrix
         *   - EncryptedRowVector
         *   - EncryptedColVector
         * Output: None
         *
         * Notes: This function has multiplicative depth one and returns a quadratic ciphertext
         * at the same level as the input, so it needs to be relinearized and rescaled.
         */
        template <typename T>
        void hadamard_square_inplace(T &arg) {
            if (!arg.initialized()) {
                throw std::invalid_argument("LinearAlgebra::hadamard_square: argument not initialized.");
            }

            for (size_t i = 0; i < arg.num_cts(); i++) {
                eval.square_inplace(arg[i]);
            }
        }

        /* Hadamard product of a row vector with each column of a matrix.
         * Inputs: A row vector and a matrix, both at the same HE level and encoded with respect to the same encoding
         * unit. Input dimensions must be compatibile for standard row-vector/matrix product, i.e., the length of the
         *         vector must be the same as the height of the matrix.
         * Output: An encrypted matrix where each column is the hadamard product of the (encoded) row vector
         *         and the corresponding column of the input matrix.
         *
         * Notes: This function has multiplicative depth one and returns a quadratic ciphertext
         * at the same level as the input, so it needs to be relinearized and rescaled.
         */
        EncryptedMatrix hadamard_multiply(const EncryptedRowVector &vec, const EncryptedMatrix &mat);

        /* Hadamard product of a column vector with each row of a matrix.
         * Inputs: A column vector and a matrix, both at the same HE level and encoded with respect to the same encoding
         * unit. Input dimensions must be compatibile for standard matrix/column-vector product, i.e., the length of the
         *         vector must be the same as the width of the matrix.
         * Output: An encrypted matrix where each row is the hadamard product of the (encoded) column vector
         *         and the corresponding row of the input matrix.
         *
         * Notes: This function has multiplicative depth one and returns a quadratic ciphertext
         * at the same level as the input, so it needs to be relinearized and rescaled.
         */
        EncryptedMatrix hadamard_multiply(const EncryptedMatrix &mat, const EncryptedColVector &vec);

        /* Scale an encrypted object by a constant.
         * Inputs: One of the following options
         *   - EncryptedMatrix, double
         *   - EncryptedRowVector, double
         *   - EncryptedColVector, double
         * Output: An encrypted object where each coefficient is scaled by the scalar.
         *
         * Notes: This function has multiplicative depth one and returns a linear ciphertext at
         * the same level as the input, so it needs to be rescaled but *not* relinearized.
         */
        template <typename T>
        T multiply(const T &arg1, double scalar) {
            T temp = arg1;
            multiply_inplace(temp, scalar);
            return temp;
        }

        /* Scale an encrypted object by a constant and stores the result in the first argument.
         * Inputs: One of the following options
         *   - EncryptedMatrix, double
         *   - EncryptedRowVector, double
         *   - EncryptedColVector, double
         * Output: None
         *
         * Notes: This function has multiplicative depth one and returns a linear ciphertext at
         * the same level as the input, so it needs to be rescaled but *not* relinearized.
         */
        template <typename T>
        void multiply_inplace(T &arg, double scalar) {
            if (!arg.initialized()) {
                throw std::invalid_argument("LinearAlgebra::multiply_inplace: argument not initialized.");
            }

            for (size_t i = 0; i < arg.num_cts(); i++) {
                eval.multiply_plain_inplace(arg[i], scalar);
            }
        }

        /* Computes a standard matrix product.
         * Inputs: A^T and B, both encoded with the same unit, optional scalar which defaults to 1
         * Output: scalar*A*B, encoded with the same unit
         *
         * Notes: This function has multiplicative depth three, meaning A^T must be at least level 3.
         * The matrix B must be encrypted at at least level 2. The output is two levels below the level of A^T,
         * but is a linear ciphertext with squared scale, so it needs to be rescaled but *not* relinearized.
         */
        EncryptedMatrix multiply(const EncryptedMatrix &matrix_aTrans, const EncryptedMatrix &matrix_b,
                                 double scalar = 1);

        /* Special case of a standard matrix product.
         * Inputs: A t-by-s matrix A^T and t-by-u matrix B, both encoded with the same n-times-m unit,
         *         where t,m <= n and s,u <= m. An optional scalar which defaults to 1.
         * Output: scalar*A*B, encoded with a *transposed* (i.e., m-by-n) unit
         *
         * Notes: This function has multiplicative depth three, meaning A^T must be at least level 3.
         * The matrix B must be encrypted at at least level 2. The output is two levels below the level of A^T,
         * but is a linear ciphertext with squared scale, so it needs to be rescaled but *not* relinearized.
         */
        EncryptedMatrix multiply_unit_transpose(const EncryptedMatrix &matrix_aTrans, const EncryptedMatrix &matrix_b,
                                                double scalar = 1);

        /* Computes a standard row vector/matrix product.
         * Inputs: Row vector and Matrix, both encoded with the same unit
         * Output: (vec*mat)^T, a column vector encoded with the same unit
         *
         * Notes: This function has multiplicative depth one, meaning both inputs must be at least level 1.
         * The output is at the same level of the input and is linear ciphertext with squared scale,
         * so it needs to be rescaled but *not* relinearized.
         */
        EncryptedColVector multiply(const EncryptedRowVector &vec, const EncryptedMatrix &mat);

        /* Computes a standard matrix/column vector product.
         * Inputs: Matrix and Column vector, both encoded with the same unit
         * Output: (mat*vec)^T, a row vector encoded with the same unit
         *
         * Notes: This function has multiplicative depth two, meaning both inputs must be at least level 2.
         * The output is one level below the inputs and is linear ciphertext with squared scale,
         * so it needs to be rescaled but *not* relinearized.
         */
        EncryptedRowVector multiply(const EncryptedMatrix &mat, const EncryptedColVector &vec, double scalar = 1);

        /* Reduce the HE level of both inputs to the lower of the two levels. This can modify at most one of the inputs.
         * Inputs: One of the following options
         *   - EncryptedMatrix, EncryptedMatrix
         *   - EncryptedRowVector, EncryptedRowVector
         *   - EncryptedColVector, EncryptedColVector
         * Inputs must be linear and not in need of a rescale.
         * Output: None
         *
         * Notes: This function repeatedly multiplies by the constant 1 and then rescales. The modified argument is
         * a linear ciphertext which does not need to be rescaled.
         */
        template <typename T>
        void mod_down_to_min_inplace(T &arg1, T &arg2) {
            if (!arg1.initialized() || !arg2.initialized()) {
                throw std::invalid_argument("LinearAlgebra::mod_down_to_min: arguments not initialized.");
            }

            for (size_t i = 0; i < arg1.num_cts(); i++) {
                eval.mod_down_to_min_inplace(arg1[i], arg2[i]);
            }
        }

        /* Reduce the HE level of the first argument to the target level.
         * Inputs: One of the following options
         *   - EncryptedMatrix, int
         *   - EncryptedRowVector, int
         *   - EncryptedColVector, int
         * Inputs must be linear and not in need of a rescale. `level` must be >= 0.
         * Output: A ciphertext encrypting the same value as the input, but at the target level.
         *
         * Notes: This function repeatedly multiplies by the constant 1 and then rescales. The output is
         * a linear ciphertext which does not need to be rescaled.
         */
        template <typename T>
        T mod_down_to_level(const T &arg, int level) {
            T temp = arg;
            mod_down_to_level_inplace(temp, level);
            return temp;
        }

        /* Reduce the HE level of the first argument to the target level, inplace.
         * Inputs: One of the following options
         *   - EncryptedMatrix, int
         *   - EncryptedRowVector, int
         *   - EncryptedColVector, int
         * Inputs must be linear and not in need of a rescale. `level` must be >= 0.
         * Output: None
         *
         * Notes: This function repeatedly multiplies by the constant 1 and then rescales. The output is
         * a linear ciphertext which does not need to be rescaled.
         */
        template <typename T>
        void mod_down_to_level_inplace(T &arg, int level) {
            if (!arg.initialized()) {
                throw std::invalid_argument("LinearAlgebra::mod_down_to_level: argument not initialized.");
            }

            for (size_t i = 0; i < arg.num_cts(); i++) {
                eval.mod_down_to_level_inplace(arg[i], level);
            }
        }

        /* Remove a prime from the modulus (i.e. go down one level) and scale down the plaintext by that prime.
         * Inputs: One of the following options
         *   - EncryptedMatrix
         *   - EncryptedRowVector
         *   - EncryptedColVector
         * Inputs must be linear and in need of a rescale. Encryption level must be >= 0.
         * Output: A ciphertext which encrypts the same plaintext as the input, but whose
         * encryption level is one lower, ane whose scale is reduced by the outer-most prime in the ciphertext modulus.
         *
         * Notes: The output is a linear ciphertext which does not need to be rescaled.
         */
        template <typename T>
        T rescale_to_next(const T &arg) {
            T temp = arg;
            rescale_to_next_inplace(temp);
            return temp;
        }

        /* Remove a prime from the modulus (i.e. go down one level) and scale down the plaintext by that prime, inplace
         * Inputs: One of the following options
         *   - EncryptedMatrix
         *   - EncryptedRowVector
         *   - EncryptedColVector
         * Inputs must be linear and in need of a rescale. Encryption level must be >= 0.
         * Output: None
         *
         * Notes: The output is a linear ciphertext which does not need to be rescaled.
         */
        template <typename T>
        void rescale_to_next_inplace(T &arg) {
            if (!arg.initialized()) {
                throw std::invalid_argument("LinearAlgebra::mod_down_to_level: argument not initialized.");
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
         * (`relin_keys`) to convert this quadratic ciphertext back into a linear
         * ciphertext that encrypts the same plaintext.
         *
         * Inputs: One of the following options
         *   - EncryptedMatrix
         *   - EncryptedRowVector
         *   - EncryptedColVector
         * Input must be a quadratic ciphertext.
         * Output: None
         *
         * Notes: The output is a linear ciphertext which does not need to be rescaled.
         */
        template <typename T>
        void relinearize_inplace(T &arg) {
            if (!arg.initialized()) {
                throw std::invalid_argument("LinearAlgebra::mod_down_to_level: argument not initialized.");
            }

            for (size_t i = 0; i < arg.num_cts(); i++) {
                eval.relinearize_inplace(arg[i]);
            }
        }

        /* Sum the columns of a matrix, and encode the result as a row vector.
         * This is a key algorithm for (standard) matrix/column-vector multiplication,
         * which is achieved by performing a hadamard product between the matrix and column
         * vector (see hadamard_multiply()), and then summing the columns of the result.
         * This algorithm can optionally scale the result by a constant.
         * Inputs: An encrypted matrix and an optional scalar, which is 1 if not specified.
         * Output: A row vector which is the (transposed) sum of the columns of the input matrix,
         * scaled by a constant.
         *
         * Notes: This function is an additive homomorphism:
         * sum_cols(mat1, c) + sum_cols(mat2, c) = sum_cols(mat1 + mat2, c)
         * It's fairly expensive to evaluate, so taking advantage of this homomorphism is recommended.
         *
         * This function has multiplicative depth one and outputs a linear ciphertext at the same level
         * as the input, so it needs to be rescaled but not relinearized.
         */
        EncryptedRowVector sum_cols(const EncryptedMatrix &mat, double scalar = 1);

        /* Sum the rows of a matrix, and encode the result as a column vector.
         * This is a key algorithm for (standard) row-vector/matrix multiplication,
         * which is achieved by performing a hadamard product between the row vector and matrix
         * (see hadamard_multiply()), and then summing the rows of the result.
         * Inputs: An encrypted matrix.
         * Output: A column vector which is the (transposed) sum of the rows of the input matrix.
         *
         * Notes: This function is an additive homomorphism:
         * sum_rows(mat1) + sum_rows(mat2) = sum_rows(mat1 + mat2)
         * It's fairly expensive to evaluate, so taking advantage of this homomorphism is recommended.
         *
         * This function has multiplicative depth zero and outputs a linear ciphertext at the same level
         * as the input, so it does not need to be rescaled or relinearized.
         */
        EncryptedColVector sum_rows(const EncryptedMatrix &mat);

       private:
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
        CKKSCiphertext sum_rows_core(const CKKSCiphertext &ct, const EncodingUnit &unit);

        // helper function for sum_rows and sum_cols which repeatedly shifts by increasing powers of two, adding the
        // results
        void rot(CKKSCiphertext &t1, int max, int stride, bool rotateLeft);

        // inner loop for matrix/row vector hadamard multiplication
        std::vector<CKKSCiphertext> matrix_rowvec_hadamard_mul_loop(const EncryptedRowVector &vec,
                                                                    const EncryptedMatrix &mat, int j);

        // inner loop for matrix/column vector hadamard multiplication
        std::vector<CKKSCiphertext> matrix_colvec_hadamard_mul_loop(const EncryptedMatrix &mat,
                                                                    const EncryptedColVector &vec, int i);

        // inner loop for sum_rows
        CKKSCiphertext sum_rows_loop(const EncryptedMatrix &mat, int j);

        // inner loop for matrix/matrix multiplication
        EncryptedColVector matrix_matrix_mul_loop(const EncryptedMatrix &matrix_aTrans, const EncryptedMatrix &matrix_b,
                                                  double scalar, int k, bool transpose_unit);

        // common core for matrix/matrix multiplication; used by both multiply and multiply_unit_transpose
        std::vector<EncryptedColVector> multiply_common(const EncryptedMatrix &matrix_aTrans,
                                                        const EncryptedMatrix &matrix_b, double scalar,
                                                        bool transpose_unit);

        // helper function for matrix/matrix multiplication which extracts a single row of A (given the encoding of A^T)
        EncryptedRowVector extractRow(const EncryptedMatrix &aTrans, int row);

        CKKSInstance &inst;
        CKKSEvaluator &eval;
    };

    // Encode a matrix as a sequence of plaintext matrices which encode the matrix
    std::vector<std::vector<Matrix>> encode_matrix(const Matrix &mat, const EncodingUnit &unit);

    // Encode a row vector as a sequence of plaintext matrices which encode the vector
    std::vector<Matrix> encode_row_vector(const Vector &vec, const EncodingUnit &unit);

    // Encode a column vector as a sequence of plaintext matrices which encode the vector
    std::vector<Matrix> encode_col_vector(const Vector &vec, const EncodingUnit &unit);

    // Decode a matrix given its encoding as a sequence of encoding units
    Matrix decode_matrix(const std::vector<std::vector<Matrix>> &mats, int trim_height = -1, int trim_width = -1);

    // Decode a row vector given its encoding as a sequence of encoding units
    Vector decode_row_vector(const std::vector<Matrix> &mats, int trim_length = -1);

    // Decode a column vector given its encoding as a sequence of encoding units
    Vector decode_col_vector(const std::vector<Matrix> &mats, int trim_length = -1);
}  // namespace hit
