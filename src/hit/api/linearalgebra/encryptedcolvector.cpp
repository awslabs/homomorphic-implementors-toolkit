// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "encryptedcolvector.h"

#include <algorithm>
#include <execution>

using namespace std;

namespace hit {
    EncryptedColVector::EncryptedColVector(int height, const EncodingUnit &unit, std::vector<CKKSCiphertext> &cts)
        : height_(height), unit(unit), cts(cts) {
        validate_init();
    }

    EncryptedColVector::EncryptedColVector(const std::shared_ptr<seal::SEALContext> &context,
                                           const protobuf::EncryptedColVector &encrypted_col_vector)
        : height_(encrypted_col_vector.height()), unit(encrypted_col_vector.unit()) {
        cts.reserve(encrypted_col_vector.cts().cts_size());
        deserialize_vector(context, encrypted_col_vector.cts(), cts);
        validate_init();
    }

    protobuf::EncryptedColVector *EncryptedColVector::serialize() const {
        auto *encrypted_col_vector = new protobuf::EncryptedColVector();
        encrypted_col_vector->set_height(height_);
        encrypted_col_vector->set_allocated_unit(unit.serialize());
        encrypted_col_vector->set_allocated_cts(serialize_vector(cts));
        return encrypted_col_vector;
    }

    EncodingUnit EncryptedColVector::encoding_unit() const {
        return unit;
    }

    int EncryptedColVector::height() const {
        return height_;
    }

    int EncryptedColVector::num_units() const {
        return cts.size();
    }

    int EncryptedColVector::num_slots() const {
        return cts[0].num_slots();
    }

    int EncryptedColVector::he_level() const {
        // assumes that cts is non-empty and that we enforce all cts must have the same level
        return cts[0].he_level();
    }

    double EncryptedColVector::scale() const {
        // assumes that cts is non-empty and that we enforce all cts must have the same scale
        return cts[0].scale();
    }

    Vector EncryptedColVector::plaintext() const {
        vector<Matrix> plaintext_pieces(cts.size());

        for (int i = 0; i < cts.size(); i++) {
            // The CKKSCiphertext plaintext is just a list of coefficients.
            // We know that it has additional meaning here: it's really a matrix
            // with the dimensions of the encoding unit.
            // To decode and recover the underlying plaintext matrix, we must first
            // add this additional context.
            Vector raw_plaintext = cts[i].plaintext();
            if (raw_plaintext.size() != unit.encoding_height() * unit.encoding_width()) {
                throw invalid_argument("Plaintext has the wrong number of coefficients.");
            }
            Matrix formatted_plaintext = Matrix(unit.encoding_height(), unit.encoding_width(), raw_plaintext.data());
            plaintext_pieces[i] = formatted_plaintext;
        }

        return decode_col_vector(plaintext_pieces, height_);
    }

    bool EncryptedColVector::initialized() const {
        if (cts.empty()) {
            return false;
        }

        if (cts.size() != ceil(height_ / static_cast<double>(unit.encoding_width()))) {
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

    void EncryptedColVector::validate_init() const {
        if (!initialized()) {
            throw invalid_argument("Invalid cts to EncryptedColVector.");
        }
    }

    size_t EncryptedColVector::num_cts() const {
        return cts.size();
    }

    CKKSCiphertext &EncryptedColVector::operator[](size_t idx) {
        return cts[idx];
    }

    const CKKSCiphertext &EncryptedColVector::operator[](size_t idx) const {
        return cts[idx];
    }

    bool EncryptedColVector::same_size(const EncryptedColVector &enc_vec) const {
        return height_ == enc_vec.height() && unit == enc_vec.encoding_unit();
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
    vector<Matrix> encode_col_vector(const Vector &vec, const EncodingUnit &unit) {
        int height = vec.size();

        // We encode column vectors as *rows*, which is why the row vector's width is used to
        // calculated the number of vertical units.
        size_t num_units = ceil(vec.size() / static_cast<double>(unit.encoding_width()));
        vector<Matrix> cts(num_units);
        for (size_t i = 0; i < num_units; i++) {
            vector<double> unit_i;
            for (int k = 0; k < unit.encoding_height(); k++) {
                for (int l = 0; l < unit.encoding_width(); l++) {
                    size_t row = i * unit.encoding_width() + l;
                    if (row < height) {
                        unit_i.emplace_back(vec[row]);
                    } else {
                        unit_i.emplace_back(0);
                    }
                }
            }
            cts[i] = Matrix(unit.encoding_height(), unit.encoding_width(), unit_i);
        }
        return cts;
    }

    Vector decode_col_vector(const vector<Matrix> &mats, int trim_length) {
        if (mats.empty()) {
            throw invalid_argument("decode_col_vector: input cannot be empty");
        }

        if (trim_length < 0) {
            trim_length = static_cast<int>(mats.size() * mats[0].size2());
        }

        // col vectors are encoded as rows of a matrix.
        // return the first row of each matrix, concatenated together
        vector<double> v;
        v.reserve(trim_length);
        for (int i = 0; i < mats.size(); i++) {
            for (int j = 0; j < mats[0].size2() && i * mats[0].size2() + j < trim_length; j++) {
                v.emplace_back(mats[i](0, j));
            }
        }

        return Vector(v);
    }
}  // namespace hit
