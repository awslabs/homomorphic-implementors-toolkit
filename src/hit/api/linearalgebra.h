// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "ciphertext.h"
#include "evaluator.h"
#include "../CKKSInstance.h"

namespace hit {

    struct EncodingUnit {
        EncodingUnit(int encoding_height, int encoding_width);
        friend bool operator== (const EncodingUnit & lhs, const EncodingUnit & rhs);
        friend bool operator!= (const EncodingUnit & lhs, const EncodingUnit & rhs);
        const int encoding_height;  // height of the encoding unit
        const int encoding_width;   // width of the encoding unit
    };

    struct EncryptedMatrix {
        EncryptedMatrix(int height, int width, const EncodingUnit &unit, std::vector<std::vector<CKKSCiphertext>> &cts);
        int num_vertical_units() const;
        int num_horizontal_units() const;

        int height;         // height of the encoded matrix
        int width;          // width of the encoded matrix
        EncodingUnit unit;  // encoding unit
        // two-dimensional grid of encoding units composing this encrypted matrix
        // First index is the row, second index is the column
        std::vector<std::vector<CKKSCiphertext>> cts;
    };

    struct EncryptedRowVector {
        EncryptedRowVector(int width, const EncodingUnit &unit, std::vector<CKKSCiphertext> &cts);
        int num_units() const;

        int width;                   // width of the encoded matrix
        EncodingUnit unit;           // encoding unit
        std::vector<CKKSCiphertext> cts;  // ciphertexts composing this encrypted matrix
    };

    struct EncryptedColVector {
        EncryptedColVector(int height, const EncodingUnit &unit, std::vector<CKKSCiphertext> &cts);
        int num_units() const;

        int height;                  // height of the encoded vector
        EncodingUnit unit;           // encoding unit
        std::vector<CKKSCiphertext> cts;  // ciphertexts composing this encrypted matrix
    };

    class LinearAlgebra {
        LinearAlgebra(CKKSInstance &inst);

        EncryptedMatrix encrypt_matrix(const Matrix &mat, const EncodingUnit &unit, int level = -1);
        Matrix decrypt(const EncryptedMatrix &mat) const;

        /* Encrypt a C++ vector representing a linear algebra column vector.
         * We first encode the vector as a matrix
         * where each row is `plain`; see pplr.cpp for details.
         * This requires the target matrix height as a parameter.
         */
        EncryptedRowVector encrypt_col_vec(const Vector &vec, const EncodingUnit &unit, int level = -1);
        Vector decrypt(const EncryptedRowVector &vec) const;

        /* Encrypt a C++ vector representing a linear algebra row vector.
         * We first encode the vector as a matrix
         * where each column is `plain`; see pplr.cpp for details.
         * This requires the target matrix width as a parameter.
         */
        EncryptedColVector encrypt_row_vec(const Vector &vec, const EncodingUnit &unit, int level = -1);
        Vector decrypt(const EncryptedColVector &vec) const;

        void add_inplace(EncryptedMatrix &mat1, const EncryptedMatrix &mat2);
        void add_inplace(EncryptedRowVector &vec1, const EncryptedRowVector &vec2);
        void add_inplace(EncryptedColVector &vec1, const EncryptedColVector &vec2);
        void add_inplace(EncryptedMatrix &mat1, const Matrix &mat2);
        void add_inplace(EncryptedRowVector &vec1, const Vector &vec2);
        void add_inplace(EncryptedColVector &vec1, const Vector &vec2);
        void add_inplace(EncryptedMatrix &mat, double c);
        void add_inplace(EncryptedRowVector &vec, double c);
        void add_inplace(EncryptedColVector &vec, double c);

        EncryptedMatrix add(const EncryptedMatrix &mat1, const EncryptedMatrix &mat2);
        EncryptedRowVector add(const EncryptedRowVector &vec1, const EncryptedRowVector &vec2);
        EncryptedColVector add(const EncryptedColVector &vec1, const EncryptedColVector &vec2);
        EncryptedMatrix add(const EncryptedMatrix &mat1, const Matrix &mat2);
        EncryptedRowVector add(const EncryptedRowVector &vec1, const Vector &vec2);
        EncryptedColVector add(const EncryptedColVector &vec1, const Vector &vec2);
        EncryptedMatrix add(const EncryptedMatrix &mat1, double c);
        EncryptedRowVector add(const EncryptedRowVector &mat1, double c);
        EncryptedColVector add(const EncryptedColVector &mat1, double c);

        EncryptedMatrix add(const std::vector<EncryptedMatrix> &mats);

        // not providing inplace versions of these since they change the object and/or dimension
        EncryptedMatrix multiply(const EncryptedMatrix &aTrans, const EncryptedMatrix &bTrans, double c = 1);
        EncryptedColVector multiply(const EncryptedRowVector &vec, const EncryptedMatrix &mat);
        EncryptedRowVector multiply(const EncryptedMatrix &mat, const EncryptedColVector &vec, double c = 1);

        EncryptedMatrix multiply(const EncryptedMatrix &mat, double c);
        EncryptedRowVector multiply(const EncryptedRowVector &vec, double c);
        EncryptedColVector multiply(const EncryptedColVector &vec, double c);

        void multiply_inplace(EncryptedMatrix &mat, double c);
        void multiply_inplace(EncryptedRowVector &vec, double c);
        void multiply_inplace(EncryptedColVector &vec, double c);

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
         */
        CKKSCiphertext sumCols(const CKKSCiphertext &ct, const EncodingUnit &unit, double c = 1);

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
         */
        CKKSCiphertext sumRows(const CKKSCiphertext &ct, const EncodingUnit &unit);












    private:

        void rot(CKKSCiphertext &t1, int max, int stride, bool rotateLeft);
        CKKSCiphertext matrix_rowvec_mul_loop(const EncryptedMatrix &mat, const EncryptedRowVector &vec, int j);
        CKKSCiphertext matrix_colvec_mul_loop(const EncryptedMatrix &mat, const EncryptedColVector &vec, double c, int i);
        std::vector<CKKSCiphertext> matrix_matrix_mul_loop(const EncryptedMatrix &aTrans, const EncryptedMatrix &bTrans, double c, int k);
        EncryptedRowVector extractRow(const EncryptedMatrix &aTrans, int row);
        std::vector<std::vector<Matrix>> encode_matrix(const Matrix &mat, const EncodingUnit &unit);
        std::vector<Matrix> encodeRowVector(const Vector &vec, const EncodingUnit &unit);
        std::vector<Matrix> encodeColVector(const Vector &vec, const EncodingUnit &unit);

        CKKSInstance &inst;
        CKKSEvaluator &eval;
    };

    Matrix decode_matrix(const std::vector<std::vector<Matrix>> &mats, int trim_height = -1, int trim_width = -1);

    // Matrix ctPlaintextToMatrix(const CKKSCiphertext &ct);
    // Matrix ctDecryptedToMatrix(CKKSInstance &inst, const CKKSCiphertext &ct);

    // Matrix ctPlaintextToMatrix(const std::vector<CKKSCiphertext> &cts);
    // Vector ctPlaintextToVector(const std::vector<CKKSCiphertext> &cts);
    // Matrix ctDecryptedToMatrix(CKKSInstance &inst, const std::vector<CKKSCiphertext> &cts);
    // Vector ctDecryptedToVector(CKKSInstance &inst, const std::vector<CKKSCiphertext> &cts);

}  // namespace hit
