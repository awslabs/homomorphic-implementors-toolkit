// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "hit/protobuf/encoding_unit.pb.h"

namespace hit {

    /* An EncodingUnit determines how linear algebra objects are encoded as one or more CKKS plaintexts.
     * Recall that a CKKS plaintext is a list of real numbers, where the length of the list is exactly
     * the number of slots determined by the CKKS parameters.
     * You can view an encoding unit as a rectangular "tile" with which we cover the linear algebra object.
     * Any extra space after tiling is filled with zeros. For fixed CKKS paramters, there are many possible valid
     * tiles, but any valid tile must satisfy tile_height*tile_width = num_CKKS_slots. In particular, this means
     * that encoding units are always powers of two in both dimensions. After dividing a plaintext object into
     * one or more encoding units, we encode each tile in row-major order to get a CKKS plaintext; see the example
     * below.
     *
     * Assume CKKS parameters have eight slots. The the encoding unit
     * [ 1 2 3 4 ]
     * [ 5 6 7 8 ]
     * becomes the CKKS plaintext [1 2 3 4 5 6 7 8].
     *
     * As the programmer, you don't have to worry about think about how the encoding works, but carefully choosing
     * an encoding unit can affect the efficiency of the implementation. See the comments above EncryptedMatrix,
     * EncryptedColVector, and EncryptedRowVector for details on how these objects are encoded.
     */
    struct EncodingUnit {
       public:
        // Returns a EncodingUnit, which is deserialized from protobuf::EncodingUnit.
        explicit EncodingUnit(const protobuf::EncodingUnit &encoding_unit);
        // Returns a EncodingUnit, which is deserialized from a stream containing a protobuf::EncodingUnit.
        explicit EncodingUnit(std::istream &stream);
        // Returns a protobuf::EncodingUnit, which is serialized from EncodingUnit.
        // This function is typically used in protobuf serialization code for objects which
        // contain a protobuf::EncodingUnit. When used directly, you are responsible for
        // calling `delete` on the pointer. When passed as an argument to a protocol buffer
        // `add_allocated` function, ownership is transferred to the protocol buffer object,
        // which is responsible for releasing the memory allocated here.
        protobuf::EncodingUnit *serialize() const;
        // Serialize an Encoding unit as a protobuf object to a stream.
        void save(std::ostream &stream) const;
        friend bool operator==(const EncodingUnit &lhs, const EncodingUnit &rhs);
        friend bool operator!=(const EncodingUnit &lhs, const EncodingUnit &rhs);
        // height of this encoding unit
        int encoding_height() const;
        // width of this encoding unit
        int encoding_width() const;
        // transpose of this unit
        EncodingUnit transpose() const;

       private:
        void read_from_proto(const protobuf::EncodingUnit &encoding_unit);
        // use `make_unit` in `LinearAlgebra` to construct an encoding unit
        EncodingUnit() = default;
        EncodingUnit(int encoding_height, int encoding_width);
        // height of the encoding unit
        int encoding_height_ = 0;
        // width of the encoding unit
        int encoding_width_ = 0;
        void validate() const;

        friend class LinearAlgebra;
        friend struct EncryptedMatrix;
        friend struct EncryptedRowVector;
        friend struct EncryptedColVector;
    };

}  // namespace hit
