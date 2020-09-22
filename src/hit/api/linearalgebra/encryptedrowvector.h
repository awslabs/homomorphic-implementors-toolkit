// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "encodingunit.h"
#include "../ciphertext.h"
#include "hit/protobuf/encrypted_row_vector.pb.h"

namespace hit {

    /* One or more ciphertexts which encrypts a plaintext row vector.
     * Row vectors are encoded as the *columns* of an encoding unit,
     * where each column is identical.
     * If the vector dimensions do not exactly divide the height of the encoding unit,
     * extra space is padded with zeros. For example,
     * consider the plaintext row vector v where
     *
     * v = [ a b c d e ]
     *
     * We can tile v with a 2x4 unit to get three plaintext units, and
     * therefore three ciphertexts:
     *
     *     cts[0]
     *  [ a a a a ]
     *  [ b b b b ]
     *
     *     cts[1]
     *  [ c c c c ]
     *  [ d d d d ]
     *
     *     cts[2]
     *  [ e e e e ]
     *  [ 0 0 0 0 ]
     *
     * If we instead use a 4x2 unit, we divide v into two plaintext units,
     * and therefore two ciphertexts:
     *
     *   cts[0]
     *  [ a a ]
     *  [ b b ]
     *  [ c c ]
     *  [ d d ]
     *
     *   cts[1]
     *  [ e e ]
     *  [ 0 0 ]
     *  [ 0 0 ]
     *  [ 0 0 ]
     *
     * The encoding unit can affect the efficiency of homomorphic operations,
     * but does not affect their multiplicative depth.
     */
    struct EncryptedRowVector : CiphertextMetadata<Vector> {
       public:
        // use `encrypt_row_vector` in `LinearAlgebra` to construct an encrypted row vector
        EncryptedRowVector() = default;

        // Returns a EncryptedRowVector, which is deserialized from protobuf::EncryptedRowVector.
        EncryptedRowVector(const std::shared_ptr<seal::SEALContext> &context,
                           const protobuf::EncryptedRowVector &encrypted_row_vector);
        // Returns a protobuf::EncryptedRowVector, which is serialized from EncryptedRowVector.
        protobuf::EncryptedRowVector *serialize() const;

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
        void validate_init() const;

        // width of the encoded matrix
        int width_ = 0;
        // encoding unit
        EncodingUnit unit;
        // ciphertexts composing this encrypted matrix
        std::vector<CKKSCiphertext> cts;

        // simple iterator
        size_t num_cts() const;
        CKKSCiphertext &operator[](size_t idx);
        const CKKSCiphertext &operator[](size_t idx) const;

        // compare this row vector to another to determine if they have the same size (dimension and encoding unit)
        bool same_size(const EncryptedRowVector &enc_vec) const;

        friend class LinearAlgebra;
    };

    // Encode a row vector as a sequence of plaintext matrices which encode the vector
    std::vector<Matrix> encode_row_vector(const Vector &vec, const EncodingUnit &unit);

    // Decode a row vector given its encoding as a sequence of encoding units
    Vector decode_row_vector(const std::vector<Matrix> &mats, int trim_length = -1);

} // namespace hit
