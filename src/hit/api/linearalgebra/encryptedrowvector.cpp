// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "encryptedrowvector.h"

#include <algorithm>
#include <execution>
#include <glog/logging.h>

#include "common.h"

using namespace std;
using namespace seal;

namespace hit {
    EncryptedRowVector::EncryptedRowVector(int width, const EncodingUnit &unit, vector<CKKSCiphertext> &cts)
        : width_(width), unit(unit), cts(cts) {
        validate_init();
    }

    void EncryptedRowVector::read_from_proto(const shared_ptr<SEALContext> &context,
                                             const protobuf::EncryptedRowVector &encrypted_row_vector) {
        width_ = encrypted_row_vector.width();
        if (width_ < 0) {
            LOG_AND_THROW_STREAM("Error deserializing EncryptedRowVector: width must be non-negative, got " << width_);
        }
        unit = EncodingUnit(encrypted_row_vector.unit());
        cts.reserve(encrypted_row_vector.cts().cts_size());
        deserialize_vector(context, encrypted_row_vector.cts(), cts);
        validate_init();
    }

    EncryptedRowVector::EncryptedRowVector(const shared_ptr<SEALContext> &context,
                                           const protobuf::EncryptedRowVector &encrypted_row_vector) {
        read_from_proto(context, encrypted_row_vector);
    }

    EncryptedRowVector::EncryptedRowVector(const shared_ptr<SEALContext> &context,
                                           istream &stream) {
        protobuf::EncryptedRowVector proto_vec;
        proto_vec.ParseFromIstream(&stream);
        read_from_proto(context, proto_vec);
    }

    protobuf::EncryptedRowVector *EncryptedRowVector::serialize() const {
        auto *encrypted_row_vector = new protobuf::EncryptedRowVector();
        encrypted_row_vector->set_width(width_);
        encrypted_row_vector->set_allocated_unit(unit.serialize());
        encrypted_row_vector->set_allocated_cts(serialize_vector(cts));
        return encrypted_row_vector;
    }

    void EncryptedRowVector::save(ostream &stream) const {
        protobuf::EncryptedRowVector *proto_vec = serialize();
        proto_vec->SerializeToOstream(&stream);
        delete proto_vec;
    }

    int EncryptedRowVector::width() const {
        return width_;
    }

    int EncryptedRowVector::num_units() const {
        return cts.size();
    }

    int EncryptedRowVector::num_slots() const {
        return cts[0].num_slots();
    }

    int EncryptedRowVector::he_level() const {
        // assumes that cts is non-empty and that we enforce all cts must have the same level
        return cts[0].he_level();
    }

    bool EncryptedRowVector::needs_rescale() const {
        return cts[0].needs_rescale();
    }

    bool EncryptedRowVector::needs_relin() const {
        return cts[0].needs_relin();
    }

    Vector EncryptedRowVector::plaintext() const {
        vector<Matrix> plaintext_pieces(cts.size());

        for (int i = 0; i < cts.size(); i++) {
            // The CKKSCiphertext plaintext is just a list of coefficients.
            // We know that it has additional meaning here: it's really a matrix
            // with the dimensions of the encoding unit.
            // To decode and recover the underlying plaintext matrix, we must first
            // add this additional context.
            Vector raw_plaintext = cts[i].plaintext();
            if (raw_plaintext.size() != unit.encoding_height() * unit.encoding_width()) {
                LOG_AND_THROW_STREAM("Internal error: plaintext has " << raw_plaintext.size()
                           << " coefficients, expected " << unit.encoding_height() * unit.encoding_width());
            }
            Matrix formatted_plaintext = Matrix(unit.encoding_height(), unit.encoding_width(), raw_plaintext.data());
            plaintext_pieces[i] = formatted_plaintext;
        }

        return decode_row_vector(plaintext_pieces, width_);
    }

    EncodingUnit EncryptedRowVector::encoding_unit() const {
        return unit;
    }

    double EncryptedRowVector::scale() const {
        // assumes that cts is non-empty and that we enforce all cts must have the same scale
        return cts[0].scale();
    }

    bool EncryptedRowVector::initialized() const {
        if (cts.empty()) {
            return false;
        }

        if (cts.size() != ceil(width_ / static_cast<double>(unit.encoding_height()))) {
            return false;
        }

        for (int i = 1; i < cts.size(); i++) {
            if (cts[i].scale() != cts[0].scale() || cts[i].he_level() != cts[0].he_level()) {
                return false;
            }
        }
        /* If we got to this point:
         *   - cts is non-empty
         *   - all cts have the same scale
         *   - all cts hav ethe same he_level
         */
        return unit.initialized() && num_units() == cts.size();
    }

    void EncryptedRowVector::validate_init() const {
        if (!initialized()) {
            LOG_AND_THROW_STREAM("Invalid ciphertexts in EncryptedRowVector: "
                       << "Expected " << ceil(width_ / static_cast<double>(unit.encoding_height()))
                       << " ciphertexts, found " << cts.size() << ". "
                       << "Each ciphertext must have the same scale and level.");
        }
    }

    size_t EncryptedRowVector::num_cts() const {
        return cts.size();
    }

    CKKSCiphertext &EncryptedRowVector::operator[](size_t idx) {
        return cts[idx];
    }

    const CKKSCiphertext &EncryptedRowVector::operator[](size_t idx) const {
        return cts[idx];
    }

    bool EncryptedRowVector::same_size(const EncryptedRowVector &enc_vec) const {
        return width_ == enc_vec.width() && unit == enc_vec.encoding_unit();
    }

    /*********   CKKS Basics   *********
     * The basic form of a CKKS plaintext is an 'array' of real or complex values
     * (distinguished from a 'vector', which will refer to linear algebra vectors
     * below). All plaintext arrays must first be *encoded* into a CKKS Plaintext
     * type. This encoding is done implicitly in the high-level API.
     * Plaintexts can then be encrypted to obtain a Ciphertext.
     *
     *********   Vector Encoding   *********
     * It might seem obvious that we should encode vectors directly as arrays.
     * However, it turns out to be more convenient to first encode a linear algebra
     * vector \vec{x} as a *matrix* X. There are two different encodings: either as
     * rows or columns. We would encode a *column* vector as *rows* of a matrix,
     * and a *row* vector as *columns* of a matrix. The intuition for this is that
     * for an  matrix A, we can compute A*x for a column vector x as A(*)X,
     * where (*) is the Hadamard (component-wise) product and X is the m x n
     * row-encoding of \vec{x}. (This accomplishes the multiplication in a
     * single step; the 'sum' portion of the dot product is another step.)
     * Similarly, for a row-vector x, we can
     * compute x*A easily if we use the column-encoding for X and compute X(*)A.
     * The vector encoding is always relative to a matrix A, and the dimension of
     * the the encoded matrix X is the same as the dimension of the transpose of A.
     *                                                 [ x y ]
     *                                   |x|             ...
     * The row encoding turns the vector |y| to matrix [ x y ], while the column
     *                                         [ x ... x ]
     * encoding of | x y | produces the matrix [ y ... y ].
     */
    vector<Matrix> encode_row_vector(const Vector &vec, const EncodingUnit &unit) {
        int width = vec.size();

        // We encode row vectors as *columns*, which is why the row vector's width is used to
        // calculated the number of vertical units.
        size_t num_units = ceil(vec.size() / static_cast<double>(unit.encoding_height()));
        vector<Matrix> cts(num_units);
        for (size_t i = 0; i < num_units; i++) {
            vector<double> unit_i;
            for (int k = 0; k < unit.encoding_height(); k++) {
                for (int l = 0; l < unit.encoding_width(); l++) {
                    size_t col = unit.encoding_height() * i + k;
                    if (col < width) {
                        unit_i.emplace_back(vec[col]);
                    } else {
                        unit_i.emplace_back(0);
                    }
                }
            }
            cts[i] = Matrix(unit.encoding_height(), unit.encoding_width(), unit_i);
        }
        return cts;
    }

    Vector decode_row_vector(const vector<Matrix> &mats, int trim_length) {
        if (mats.empty()) {
            LOG_AND_THROW_STREAM("Internal error: input to decode_row_vector cannot be empty");
        }

        if (trim_length < 0) {
            trim_length = static_cast<int>(mats.size() * mats[0].size1());
        }

        // row vectors are encoded as columns of a matrix.
        // return the first column of each matrix, concatenated together
        vector<double> v;
        v.reserve(trim_length);
        for (int i = 0; i < mats.size(); i++) {
            for (int j = 0; j < mats[0].size1() && i * mats[0].size1() + j < trim_length; j++) {
                v.emplace_back(mats[i](j, 0));
            }
        }

        return Vector(v);
    }
}  // namespace hit
