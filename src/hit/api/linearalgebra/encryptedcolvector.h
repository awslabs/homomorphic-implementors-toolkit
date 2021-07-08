// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../../common.h"
#include "../ciphertext.h"
#include "encodingunit.h"
#include "hit/protobuf/encrypted_col_vector.pb.h"

namespace hit {

    /* One or more ciphertexts which encrypts a plaintext column vector.
     * Column vectors are encoded as the *rows* of an encoding unit,
     * where each row is identical.
     * If the vector dimensions do not exactly divide the width of the encoding unit,
     * extra space is padded with zeros. For example,
     * consider the plaintext column vector v where
     *
     *     [ a ]
     *     [ b ]
     * v = [ c ]
     *     [ d ]
     *     [ e ]
     *
     * We can tile v with a 2x4 unit to get two plaintext units, and
     * therefore two ciphertexts:
     *
     *     cts[0]       cts[1]
     *  [ a b c d ]  [ e 0 0 0 ]
     *  [ a b c d ]  [ e 0 0 0 ]
     *
     * If we instead use a 4x2 unit, we divide v into three plaintext units,
     * and therefore three ciphertexts:
     *
     *   cts[0]     cts[1]     cts[2]
     *  [ a b ]    [ c d ]    [ e 0 ]
     *  [ a b ]    [ c d ]    [ e 0 ]
     *  [ a b ]    [ c d ]    [ e 0 ]
     *  [ a b ]    [ c d ]    [ e 0 ]
     *
     * The encoding unit can affect the efficiency of homomorphic operations,
     * but does not affect their multiplicative depth.
     */
    struct EncryptedColVector : CiphertextMetadata<Vector> {
       public:
        // use `encrypt_row_vector` in `LinearAlgebra` to construct an encrypted row vector
        EncryptedColVector() = default;
        // Returns a EncryptedColVector, which is deserialized from protobuf::EncryptedColVector.
        EncryptedColVector(const std::shared_ptr<HEContext> &context,
                           const protobuf::EncryptedColVector &encrypted_col_vector);
        // Returns a EncryptedColVector, which is deserialized from a stream containing a protobuf::EncryptedColVector.
        EncryptedColVector(const std::shared_ptr<HEContext> &context, std::istream &stream);
        // Returns a protobuf::EncryptedColVector, which is serialized from EncryptedColVector.
        protobuf::EncryptedColVector *serialize() const;
        // Serialize an EncryptedColVector as a protobuf object to a stream.
        void save(std::ostream &stream) const;

        int height() const;
        int num_units() const;
        EncodingUnit encoding_unit() const;

        // number of plaintext slots in the CKKS parameters
        int num_slots() const override;
        // encryption level of this vector
        int he_level() const override;
        // CKKS scale of this vector
        double scale() const override;
        // Output true if the ciphertext has squared scale and is
        // therefore in need of a rescale, false otherwise.
        bool needs_rescale() const override;
        // Output true if the ciphertext is quadratic and is
        // therefore in need of relinearization, false otherwise.
        bool needs_relin() const override;
        // Underlying plaintext vector. This is only available with the Plaintext, Debug, and ScaleEstimator evaluators
        Vector plaintext() const override;

       private:
        void read_from_proto(const std::shared_ptr<HEContext> &context,
                             const protobuf::EncryptedColVector &encrypted_col_vector);

        EncryptedColVector(int height, const EncodingUnit &unit, std::vector<CKKSCiphertext> &cts);

        void validate() const;

        // height of the encoded vector
        int height_ = 0;
        // encoding unit
        EncodingUnit unit;
        // ciphertexts composing this encrypted matrix
        std::vector<CKKSCiphertext> cts;

        // simple iterator
        size_t num_cts() const;
        CKKSCiphertext &operator[](size_t idx);
        const CKKSCiphertext &operator[](size_t idx) const;

        // compare this column vector to another to determine if they have the same size (dimension and encoding unit)
        bool same_size(const EncryptedColVector &enc_vec) const;

        friend class LinearAlgebra;
    };

    // Encode a column vector as a sequence of plaintext matrices which encode the vector
    std::vector<Matrix> encode_col_vector(const Vector &vec, const EncodingUnit &unit);

    // Decode a column vector given its encoding as a sequence of encoding units
    Vector decode_col_vector(const std::vector<Matrix> &mats, int trim_length = -1);

}  // namespace hit
