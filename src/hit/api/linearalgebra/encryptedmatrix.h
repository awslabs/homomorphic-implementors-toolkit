// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "encodingunit.h"
#include "../ciphertext.h"
#include "hit/protobuf/encrypted_matrix.pb.h"

namespace hit {

    /* One or more ciphertexts which encrypts a plaintext matrix.
     * Matrices are divided into plaintexts by tiling the matrix with the encoding unit.
     * If the matrix dimensions do not exactly divide into encoding units, extra space is
     * padded with zeros. For example, consider the plaintext matrix A where
     *
     * A = [ a b c d e ]
     *     [ f g h i j ]
     *     [ k l m n o ]
     *     [ p q r s t ]
     *
     * We can tile A with a 2x4 unit to get four plaintext units, and
     * therefore four ciphertexts:
     *
     *   cts[0][0]    cts[0][1]
     *  [ a b c d ]  [ e 0 0 0 ]
     *  [ f g h i ]  [ j 0 0 0 ]
     *
     *   cts[1][0]    cts[1][1]
     *  [ k l m n ]  [ o 0 0 0 ]
     *  [ p q r s ]  [ t 0 0 0 ]
     *
     * If we instead use a 4x2 unit, we divide A into three plaintext units,
     * and therefore three ciphertexts:
     *
     *  cts[0][0]  cts[0][1]  cts[0][2]
     *  [ a b ]    [ c d ]    [ e 0 ]
     *  [ f g ]    [ h i ]    [ j 0 ]
     *  [ k l ]    [ m n ]    [ k 0 ]
     *  [ p q ]    [ r s ]    [ t 0 ]
     *
     * The encoding unit can affect the efficiency of homomorphic operations,
     * but does not affect their multiplicative depth.
     */
    struct EncryptedMatrix : CiphertextMetadata<Matrix> {
       public:
        // use `encrypt_matrix` in `LinearAlgebra` to construct an encrypted matrix
        EncryptedMatrix() = default;
        // Returns a EncryptedMatrix, which is deserialized from protobuf::EncryptedMatrix.
        EncryptedMatrix(const std::shared_ptr<seal::SEALContext> &context,
                        const protobuf::EncryptedMatrix &encrypted_matrix);
        // Returns a protobuf::EncryptedMatrix, which is serialized from EncryptedMatrix.
        protobuf::EncryptedMatrix *serialize() const;
        // height of the encrypted matrix
        int height() const;
        // width of the encrypted matrix
        int width() const;
        // number of encoding units tiled vertically to encode this matrix
        int num_vertical_units() const;
        // number of encoding units tiled horizontally to encode this matrix
        int num_horizontal_units() const;
        // encoding unit used to encode this matrix
        EncodingUnit encoding_unit() const;
        // number of plaintext slots in the CKKS parameters
        int num_slots() const override;
        // encryption level of this matrix
        int he_level() const override;
        // CKKS scale of this matrix
        double scale() const override;
        // Underlying plaintext matrix. This is only available with the Plaintext, Debug, and ScaleEstimator evaluators
        Matrix plaintext() const override;

       private:
        EncryptedMatrix(int height, int width, const EncodingUnit &unit,
                        const std::vector<std::vector<CKKSCiphertext>> &cts);

        bool initialized() const;
        void validateInit() const;

        // height of the encoded matrix
        int height_ = 0;
        // width of the encoded matrix
        int width_ = 0;
        // encoding unit
        EncodingUnit unit;
        // two-dimensional grid of encoding units composing this encrypted matrix
        // First index is the row, second index is the column
        std::vector<std::vector<CKKSCiphertext>> cts;

        // simple iterator
        size_t num_cts() const;
        CKKSCiphertext &operator[](size_t idx);
        const CKKSCiphertext &operator[](size_t idx) const;

        // compare this matrix to another matrix to determine if they have the same size (dimensions and encoding unit)
        bool same_size(const EncryptedMatrix &enc_mat) const;

        friend class LinearAlgebra;
    };

    // Encode a matrix as a sequence of plaintext matrices which encode the matrix
    std::vector<std::vector<Matrix>> encode_matrix(const Matrix &mat, const EncodingUnit &unit);

    // Decode a matrix given its encoding as a sequence of encoding units
    Matrix decode_matrix(const std::vector<std::vector<Matrix>> &mats, int trim_height = -1, int trim_width = -1);

} // namespace hit
