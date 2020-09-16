// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "linearalgebra.h"

#include <algorithm>
#include <execution>

#include "common.h"

using namespace std;

namespace hit {
    EncodingUnit::EncodingUnit(int encoding_height, int encoding_width)
        : encoding_height_(encoding_height), encoding_width_(encoding_width) {
        if (!initialized()) {
            throw invalid_argument("Encoding unit dimensions must be a power of two.");
        }
    }

    bool operator==(const EncodingUnit &lhs, const EncodingUnit &rhs) {
        return lhs.encoding_width() == rhs.encoding_width() && lhs.encoding_height() == rhs.encoding_height();
    }

    bool operator!=(const EncodingUnit &lhs, const EncodingUnit &rhs) {
        return !(lhs == rhs);
    }

    int EncodingUnit::encoding_height() const {
        return encoding_height_;
    }

    int EncodingUnit::encoding_width() const {
        return encoding_width_;
    }

    bool EncodingUnit::initialized() const {
        return encoding_height_ > 0 && encoding_width_ > 0 && isPow2(encoding_height_) && isPow2(encoding_width_);
    }

    EncodingUnit EncodingUnit::transpose() const {
        return EncodingUnit(encoding_width_, encoding_height_);
    }

    EncryptedMatrix::EncryptedMatrix(int height, int width, const EncodingUnit &unit,
                                     const vector<vector<CKKSCiphertext>> &cts)
        : height_(height), width_(width), unit(unit), cts(move(cts)) {
        if (!initialized()) {
            throw invalid_argument("Invalid cts to EncryptedMatrix.");
        }
    }

    EncodingUnit EncryptedMatrix::encoding_unit() const {
        return unit;
    }

    int EncryptedMatrix::height() const {
        return height_;
    }

    int EncryptedMatrix::width() const {
        return width_;
    }

    int EncryptedMatrix::num_vertical_units() const {
        return ceil(height_ / static_cast<double>(unit.encoding_height()));
    }

    int EncryptedMatrix::num_horizontal_units() const {
        return ceil(width_ / static_cast<double>(unit.encoding_width()));
    }

    int EncryptedMatrix::num_slots() const {
        return cts[0][0].num_slots();
    }

    int EncryptedMatrix::he_level() const {
        // assumes that cts is non-empty and that we enforce all cts must have the same level
        return cts[0][0].he_level();
    }

    double EncryptedMatrix::scale() const {
        // assumes that cts is non-empty and that we enforce all cts must have the same scale
        return cts[0][0].scale();
    }

    Matrix EncryptedMatrix::plaintext() const {
        vector<vector<Matrix>> plaintext_pieces(cts.size());

        for (int i = 0; i < cts.size(); i++) {
            vector<Matrix> plaintext_row(cts[0].size());
            for (int j = 0; j < cts[0].size(); j++) {
                // The CKKSCiphertext plaintext is just a list of coefficients.
                // We know that it has additional meaning here: it's really a matrix
                // with the dimensions of the encoding unit.
                // To decode and recover the underlying plaintext matrix, we must first
                // add this additional context.
                Vector raw_plaintext = cts[i][j].plaintext();
                Matrix formatted_plaintext =
                    Matrix(unit.encoding_height(), unit.encoding_width(), raw_plaintext.data());
                plaintext_row[j] = formatted_plaintext;
            }
            plaintext_pieces[i] = plaintext_row;
        }

        return decode_matrix(plaintext_pieces, height_, width_);
    }

    bool EncryptedMatrix::initialized() const {
        return unit.initialized() && !cts.empty() && num_vertical_units() == cts.size() && !cts[0].empty() &&
               num_horizontal_units() == cts[0].size();
    }

    size_t EncryptedMatrix::num_cts() const {
        return cts.size() * cts[0].size();
    }

    CKKSCiphertext &EncryptedMatrix::operator[](size_t idx) {
        size_t num_cols = cts[0].size();
        size_t row = idx / num_cols;
        size_t col = idx % num_cols;
        return cts[row][col];
    }

    const CKKSCiphertext &EncryptedMatrix::operator[](size_t idx) const {
        size_t num_cols = cts[0].size();
        size_t row = idx / num_cols;
        size_t col = idx % num_cols;
        return cts[row][col];
    }

    bool EncryptedMatrix::same_size(const EncryptedMatrix &mat) const {
        return height_ == mat.height() && width_ == mat.width() && unit == mat.encoding_unit();
    }

    template <>
    EncryptedRowVector LinearAlgebra::encrypt(const Vector &vec, const EncodingUnit &unit, int level) {
        return encrypt_row_vector(vec, unit, level);
    }

    template <>
    EncryptedColVector LinearAlgebra::encrypt(const Vector &vec, const EncodingUnit &unit, int level) {
        return encrypt_col_vector(vec, unit, level);
    }

    EncryptedMatrix LinearAlgebra::encrypt_matrix(const Matrix &mat, const EncodingUnit &unit, int level) {
        vector<vector<Matrix>> mat_pieces = encode_matrix(mat, unit);
        vector<vector<CKKSCiphertext>> mat_cts(mat_pieces.size());
        for (int i = 0; i < mat_pieces.size(); i++) {
            vector<CKKSCiphertext> row_cts(mat_pieces[0].size());
            for (int j = 0; j < mat_pieces[0].size(); j++) {
                row_cts[j] = inst.encrypt(mat_pieces[i][j].data(), level);
            }
            mat_cts[i] = row_cts;
        }
        return EncryptedMatrix(mat.size1(), mat.size2(), unit, mat_cts);
    }

    Matrix LinearAlgebra::decrypt(const EncryptedMatrix &mat) const {
        if (!mat.initialized()) {
            throw invalid_argument("Cannot decrypt uninitialized matrix");
        }

        vector<vector<Matrix>> mat_pieces(mat.cts.size());
        for (int i = 0; i < mat.cts.size(); i++) {
            vector<Matrix> row_pieces(mat.cts[0].size());
            for (int j = 0; j < mat.cts[0].size(); j++) {
                row_pieces[j] = Matrix(mat.encoding_unit().encoding_height(), mat.encoding_unit().encoding_width(),
                                       inst.decrypt(mat.cts[i][j]));
            }
            mat_pieces[i] = row_pieces;
        }
        return decode_matrix(mat_pieces, mat.height(), mat.width());
    }

    EncryptedRowVector::EncryptedRowVector(int width, const EncodingUnit &unit, std::vector<CKKSCiphertext> &cts)
        : width_(width), unit(unit), cts(cts) {
        if (!initialized()) {
            throw invalid_argument("Invalid cts to EncryptedRowVector.");
        }
    }

    int EncryptedRowVector::width() const {
        return width_;
    }

    int EncryptedRowVector::num_units() const {
        return ceil(width_ / static_cast<double>(unit.encoding_height()));
    }

    int EncryptedRowVector::num_slots() const {
        return cts[0].num_slots();
    }

    int EncryptedRowVector::he_level() const {
        // assumes that cts is non-empty and that we enforce all cts must have the same level
        return cts[0].he_level();
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
        return unit.initialized() && !cts.empty() && num_units() == cts.size();
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

    bool EncryptedRowVector::same_size(const EncryptedRowVector &vec) const {
        return width_ == vec.width() && unit == vec.encoding_unit();
    }

    EncryptedRowVector LinearAlgebra::encrypt_row_vector(const Vector &vec, const EncodingUnit &unit, int level) {
        vector<Matrix> mat_pieces = encode_row_vector(vec, unit);
        vector<CKKSCiphertext> mat_cts(mat_pieces.size());
        for (int i = 0; i < mat_pieces.size(); i++) {
            mat_cts[i] = inst.encrypt(mat_pieces[i].data(), level);
        }
        return EncryptedRowVector(vec.size(), unit, mat_cts);
    }

    Vector LinearAlgebra::decrypt(const EncryptedRowVector &vec) const {
        if (!vec.initialized()) {
            throw invalid_argument("Cannot decrypt uninitialized row vector");
        }

        vector<Matrix> mat_pieces(vec.cts.size());
        for (int i = 0; i < vec.cts.size(); i++) {
            mat_pieces[i] = Matrix(vec.encoding_unit().encoding_height(), vec.encoding_unit().encoding_width(),
                                   inst.decrypt(vec.cts[i]));
        }
        return decode_row_vector(mat_pieces, vec.width());
    }

    EncryptedColVector::EncryptedColVector(int height, const EncodingUnit &unit, std::vector<CKKSCiphertext> &cts)
        : height_(height), unit(unit), cts(cts) {
        if (!initialized()) {
            throw invalid_argument("Invalid cts to EncryptedColVector.");
        }
    }

    EncodingUnit EncryptedColVector::encoding_unit() const {
        return unit;
    }

    int EncryptedColVector::height() const {
        return height_;
    }

    int EncryptedColVector::num_units() const {
        return ceil(height_ / static_cast<double>(unit.encoding_width()));
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
            Matrix formatted_plaintext = Matrix(unit.encoding_height(), unit.encoding_width(), raw_plaintext.data());
            plaintext_pieces[i] = formatted_plaintext;
        }

        return decode_col_vector(plaintext_pieces, height_);
    }

    bool EncryptedColVector::initialized() const {
        return unit.initialized() && !cts.empty() && num_units() == cts.size();
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

    bool EncryptedColVector::same_size(const EncryptedColVector &vec) const {
        return height_ == vec.height() && unit == vec.encoding_unit();
    }

    EncryptedColVector LinearAlgebra::encrypt_col_vector(const Vector &vec, const EncodingUnit &unit, int level) {
        vector<Matrix> mat_pieces = encode_col_vector(vec, unit);
        vector<CKKSCiphertext> mat_cts(mat_pieces.size());
        for (int i = 0; i < mat_pieces.size(); i++) {
            mat_cts[i] = inst.encrypt(mat_pieces[i].data(), level);
        }
        return EncryptedColVector(vec.size(), unit, mat_cts);
    }

    EncodingUnit LinearAlgebra::make_unit(int encoding_height) const {
        return EncodingUnit(encoding_height, inst.plaintext_dim() / encoding_height);
    }

    Vector LinearAlgebra::decrypt(const EncryptedColVector &vec) const {
        if (!vec.initialized()) {
            throw invalid_argument("Cannot decrypt uninitialized column vector");
        }

        vector<Matrix> mat_pieces(vec.cts.size());
        for (int i = 0; i < vec.cts.size(); i++) {
            mat_pieces[i] = Matrix(vec.encoding_unit().encoding_height(), vec.encoding_unit().encoding_width(),
                                   inst.decrypt(vec.cts[i]));
        }
        return decode_col_vector(mat_pieces, vec.height());
    }

    LinearAlgebra::LinearAlgebra(CKKSInstance &inst) : eval(*(inst.evaluator)), inst(inst) {
    }

    // explicit template instantiation
    template EncryptedMatrix LinearAlgebra::add(const EncryptedMatrix &, const EncryptedMatrix &);
    template void LinearAlgebra::add_inplace(EncryptedMatrix &, const EncryptedMatrix &);
    template EncryptedMatrix LinearAlgebra::add(const vector<EncryptedMatrix> &);
    template EncryptedMatrix LinearAlgebra::add(const EncryptedMatrix &, const Matrix &);
    template EncryptedMatrix LinearAlgebra::add(const EncryptedMatrix &, double);
    template void LinearAlgebra::add_inplace(EncryptedMatrix &mat, double scalar);
    template EncryptedMatrix LinearAlgebra::multiply(const EncryptedMatrix &, double);
    template void LinearAlgebra::mod_down_to_min_inplace(EncryptedMatrix &, EncryptedMatrix &);
    template EncryptedMatrix LinearAlgebra::mod_down_to_level(const EncryptedMatrix &, int);
    template void LinearAlgebra::mod_down_to_level_inplace(EncryptedMatrix &, int);
    template void LinearAlgebra::rescale_to_next_inplace(EncryptedMatrix &);
    template EncryptedMatrix LinearAlgebra::rescale_to_next(const EncryptedMatrix &);
    template void LinearAlgebra::relinearize_inplace(EncryptedMatrix &);
    template void LinearAlgebra::hadamard_square_inplace(EncryptedMatrix &);
    template EncryptedMatrix LinearAlgebra::hadamard_square(const EncryptedMatrix &);
    template EncryptedMatrix LinearAlgebra::hadamard_multiply(const EncryptedMatrix &, const EncryptedMatrix &);
    template void LinearAlgebra::hadamard_multiply_inplace(EncryptedMatrix &, const EncryptedMatrix &);
    template EncryptedMatrix LinearAlgebra::mod_down_to(const EncryptedMatrix &, const EncryptedMatrix &);
    template EncryptedMatrix LinearAlgebra::mod_down_to(const EncryptedMatrix &, const EncryptedRowVector &);
    template EncryptedMatrix LinearAlgebra::mod_down_to(const EncryptedMatrix &, const EncryptedColVector &);
    template void LinearAlgebra::mod_down_to_inplace(EncryptedMatrix &, const EncryptedMatrix &);
    template void LinearAlgebra::mod_down_to_inplace(EncryptedMatrix &, const EncryptedRowVector &);
    template void LinearAlgebra::mod_down_to_inplace(EncryptedMatrix &, const EncryptedColVector &);

    // explicit template instantiation
    template EncryptedRowVector LinearAlgebra::add(const EncryptedRowVector &, const EncryptedRowVector &);
    template void LinearAlgebra::add_inplace(EncryptedRowVector &, const EncryptedRowVector &);
    template EncryptedRowVector LinearAlgebra::add(const vector<EncryptedRowVector> &);
    template EncryptedRowVector LinearAlgebra::add(const EncryptedRowVector &, const Vector &);
    template EncryptedRowVector LinearAlgebra::add(const EncryptedRowVector &, double);
    template void LinearAlgebra::add_inplace(EncryptedRowVector &mat, double scalar);
    template EncryptedRowVector LinearAlgebra::multiply(const EncryptedRowVector &, double);
    template void LinearAlgebra::mod_down_to_min_inplace(EncryptedRowVector &, EncryptedRowVector &);
    template EncryptedRowVector LinearAlgebra::mod_down_to_level(const EncryptedRowVector &, int);
    template void LinearAlgebra::mod_down_to_level_inplace(EncryptedRowVector &, int);
    template void LinearAlgebra::rescale_to_next_inplace(EncryptedRowVector &);
    template EncryptedRowVector LinearAlgebra::rescale_to_next(const EncryptedRowVector &);
    template void LinearAlgebra::relinearize_inplace(EncryptedRowVector &);
    template void LinearAlgebra::hadamard_square_inplace(EncryptedRowVector &);
    template EncryptedRowVector LinearAlgebra::hadamard_square(const EncryptedRowVector &);
    template EncryptedRowVector LinearAlgebra::hadamard_multiply(const EncryptedRowVector &,
                                                                 const EncryptedRowVector &);
    template void LinearAlgebra::hadamard_multiply_inplace(EncryptedRowVector &, const EncryptedRowVector &);
    template EncryptedRowVector LinearAlgebra::mod_down_to(const EncryptedRowVector &, const EncryptedMatrix &);
    template EncryptedRowVector LinearAlgebra::mod_down_to(const EncryptedRowVector &, const EncryptedRowVector &);
    template EncryptedRowVector LinearAlgebra::mod_down_to(const EncryptedRowVector &, const EncryptedColVector &);
    template void LinearAlgebra::mod_down_to_inplace(EncryptedRowVector &, const EncryptedMatrix &);
    template void LinearAlgebra::mod_down_to_inplace(EncryptedRowVector &, const EncryptedRowVector &);
    template void LinearAlgebra::mod_down_to_inplace(EncryptedRowVector &, const EncryptedColVector &);

    // explicit template instantiation
    template EncryptedColVector LinearAlgebra::add(const EncryptedColVector &, const EncryptedColVector &);
    template void LinearAlgebra::add_inplace(EncryptedColVector &, const EncryptedColVector &);
    template EncryptedColVector LinearAlgebra::add(const vector<EncryptedColVector> &);
    template EncryptedColVector LinearAlgebra::add(const EncryptedColVector &, const Vector &);
    template EncryptedColVector LinearAlgebra::add(const EncryptedColVector &, double);
    template void LinearAlgebra::add_inplace(EncryptedColVector &mat, double scalar);
    template EncryptedColVector LinearAlgebra::multiply(const EncryptedColVector &, double);
    template void LinearAlgebra::mod_down_to_min_inplace(EncryptedColVector &, EncryptedColVector &);
    template EncryptedColVector LinearAlgebra::mod_down_to_level(const EncryptedColVector &, int);
    template void LinearAlgebra::mod_down_to_level_inplace(EncryptedColVector &, int);
    template void LinearAlgebra::rescale_to_next_inplace(EncryptedColVector &);
    template EncryptedColVector LinearAlgebra::rescale_to_next(const EncryptedColVector &);
    template void LinearAlgebra::relinearize_inplace(EncryptedColVector &);
    template void LinearAlgebra::hadamard_square_inplace(EncryptedColVector &);
    template EncryptedColVector LinearAlgebra::hadamard_square(const EncryptedColVector &);
    template EncryptedColVector LinearAlgebra::hadamard_multiply(const EncryptedColVector &,
                                                                 const EncryptedColVector &);
    template void LinearAlgebra::hadamard_multiply_inplace(EncryptedColVector &, const EncryptedColVector &);
    template EncryptedColVector LinearAlgebra::mod_down_to(const EncryptedColVector &, const EncryptedMatrix &);
    template EncryptedColVector LinearAlgebra::mod_down_to(const EncryptedColVector &, const EncryptedRowVector &);
    template EncryptedColVector LinearAlgebra::mod_down_to(const EncryptedColVector &, const EncryptedColVector &);
    template void LinearAlgebra::mod_down_to_inplace(EncryptedColVector &, const EncryptedMatrix &);
    template void LinearAlgebra::mod_down_to_inplace(EncryptedColVector &, const EncryptedRowVector &);
    template void LinearAlgebra::mod_down_to_inplace(EncryptedColVector &, const EncryptedColVector &);

    void LinearAlgebra::add_inplace(EncryptedMatrix &mat1, const Matrix &mat2) {
        if (!mat1.initialized() || mat1.height() != mat2.size1() || mat1.width() != mat2.size2()) {
            throw invalid_argument("Arguments to LinearAlgebra::add_inplace do not have the same dimensions.");
        }
        vector<vector<Matrix>> encoded_matrix = encode_matrix(mat2, mat1.encoding_unit());

        for (int i = 0; i < mat1.cts.size(); i++) {
            vector<CKKSCiphertext> row;
            for (int j = 0; j < mat1.cts[0].size(); j++) {
                eval.add_plain_inplace(mat1.cts[i][j], encoded_matrix[i][j].data());
            }
        }
    }

    void LinearAlgebra::add_inplace(EncryptedRowVector &vec1, const Vector &vec2) {
        if (!vec1.initialized() || vec1.width() != vec2.size()) {
            throw invalid_argument("Arguments to LinearAlgebra::add_inplace do not have the same dimensions.");
        }
        vector<Matrix> encoded_vector = encode_row_vector(vec2, vec1.encoding_unit());

        for (int i = 0; i < vec1.cts.size(); i++) {
            eval.add_plain_inplace(vec1.cts[i], encoded_vector[i].data());
        }
    }

    void LinearAlgebra::add_inplace(EncryptedColVector &vec1, const Vector &vec2) {
        if (!vec1.initialized() || vec1.height() != vec2.size()) {
            throw invalid_argument("Arguments to LinearAlgebra::add_inplace do not have the same dimensions.");
        }
        vector<Matrix> encoded_vector = encode_col_vector(vec2, vec1.encoding_unit());

        for (int i = 0; i < vec1.cts.size(); i++) {
            eval.add_plain_inplace(vec1.cts[i], encoded_vector[i].data());
        }
    }

    vector<CKKSCiphertext> LinearAlgebra::matrix_rowvec_hadamard_mul_loop(const EncryptedRowVector &vec,
                                                                          const EncryptedMatrix &mat, int j) {
        vector<CKKSCiphertext> col_prods(mat.num_vertical_units());
        for (int i = 0; i < mat.num_vertical_units(); i++) {
            col_prods[i] = eval.multiply(mat.cts[i][j], vec.cts[i]);
            // rotation requires a linear ciphertext, but does not require rescaling
            eval.relinearize_inplace(col_prods[i]);
        }
        return col_prods;
    }

    EncryptedMatrix LinearAlgebra::hadamard_multiply(const EncryptedRowVector &vec, const EncryptedMatrix &mat) {
        if (!vec.initialized() || !mat.initialized() || mat.height() != vec.width() ||
            mat.encoding_unit() != vec.encoding_unit()) {
            throw invalid_argument("Dimension mismatch in LinearAlgebra::multiply.");
        }

        vector<vector<CKKSCiphertext>> cts_transpose(mat.num_horizontal_units());

        vector<int> iterIdxs(mat.num_horizontal_units());
        for (int i = 0; i < mat.num_horizontal_units(); i++) {
            iterIdxs[i] = i;
        }

        if (eval.evalPolicy == launch::deferred) {
            std::for_each(execution::seq, begin(iterIdxs), end(iterIdxs),
                          [&](int j) { cts_transpose[j] = matrix_rowvec_hadamard_mul_loop(vec, mat, j); });
        } else {
            std::for_each(execution::par, begin(iterIdxs), end(iterIdxs),
                          [&](int j) { cts_transpose[j] = matrix_rowvec_hadamard_mul_loop(vec, mat, j); });
        }

        // Because we iterate over the *columns* of the encoding, the encoding units are transposed
        // We un-transpose them here.
        vector<vector<CKKSCiphertext>> cts(mat.num_vertical_units());

        for (int i = 0; i < mat.num_vertical_units(); i++) {
            vector<CKKSCiphertext> mat_row(mat.num_horizontal_units());
            for (int j = 0; j < mat.num_horizontal_units(); j++) {
                mat_row[j] = cts_transpose[j][i];
            }
            cts[i] = mat_row;
        }

        return EncryptedMatrix(mat.height(), mat.width(), mat.encoding_unit(), cts);
    }

    vector<CKKSCiphertext> LinearAlgebra::matrix_colvec_hadamard_mul_loop(const EncryptedMatrix &mat,
                                                                          const EncryptedColVector &vec, int i) {
        vector<CKKSCiphertext> row_prods(mat.num_horizontal_units());
        for (int j = 0; j < mat.num_horizontal_units(); j++) {
            row_prods[j] = eval.multiply(mat.cts[i][j], vec.cts[j]);
            eval.relinearize_inplace(row_prods[j]);
            eval.rescale_to_next_inplace(row_prods[j]);
        }
        return row_prods;
    }

    EncryptedMatrix LinearAlgebra::hadamard_multiply(const EncryptedMatrix &mat, const EncryptedColVector &vec) {
        if (!vec.initialized() || !mat.initialized() || mat.width() != vec.height() ||
            mat.encoding_unit() != vec.encoding_unit()) {
            throw invalid_argument("Dimension mismatch in LinearAlgebra::multiply.");
        }

        vector<vector<CKKSCiphertext>> cts(mat.num_vertical_units());

        vector<int> iterIdxs(mat.num_vertical_units());
        for (int i = 0; i < mat.num_vertical_units(); i++) {
            iterIdxs[i] = i;
        }

        if (eval.evalPolicy == launch::deferred) {
            std::for_each(execution::seq, begin(iterIdxs), end(iterIdxs),
                          [&](int i) { cts[i] = matrix_colvec_hadamard_mul_loop(mat, vec, i); });
        } else {
            std::for_each(execution::par, begin(iterIdxs), end(iterIdxs),
                          [&](int i) { cts[i] = matrix_colvec_hadamard_mul_loop(mat, vec, i); });
        }

        return EncryptedMatrix(mat.height(), mat.width(), mat.encoding_unit(), cts);
    }

    EncryptedColVector LinearAlgebra::multiply(const EncryptedRowVector &vec, const EncryptedMatrix &mat) {
        EncryptedMatrix hadmard_prod = hadamard_multiply(vec, mat);
        return sum_rows(hadmard_prod);
    }

    EncryptedRowVector LinearAlgebra::multiply(const EncryptedMatrix &mat, const EncryptedColVector &vec,
                                               double scalar) {
        EncryptedMatrix hadmard_prod = hadamard_multiply(mat, vec);
        return sum_cols(hadmard_prod, scalar);
    }

    EncryptedMatrix LinearAlgebra::unit_transpose(  // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
        const EncryptedMatrix &mat) {
        if (!mat.initialized()) {
            throw invalid_argument("unit_transpose: matrix is not initialized");
        }
        // if (mat.unit.encoding_height() > mat.unit.encoding_width()) {
        //     throw invalid_argument("You can only transpose a matrix whose unit is wider than it is tall.");
        // }
        // if (mat.height > mat.unit.encoding_height() || mat.width > mat.unit.encoding_height()) {
        //     throw invalid_argument("You can only transpose a matrix which is smaller than mxm for a mxn encoding
        //     unit.");
        // }

        // TODO(Eric): Add additional safety measures

        if (  // landscape unit
            mat.unit.encoding_height() <= mat.unit.encoding_width() &&
            // sub-square matrix in a single unit
            mat.height_ <= mat.unit.encoding_height() && mat.width_ <= mat.unit.encoding_height()) {
            return EncryptedMatrix(mat.unit.encoding_width(), mat.width_, mat.unit.transpose(), mat.cts);
        }

        if (  // portrait unit
            mat.unit.encoding_height() >= mat.unit.encoding_width() &&
            // matrix fits in one unit
            mat.height_ <= mat.unit.encoding_height() && mat.width_ <= mat.unit.encoding_width()) {
            return EncryptedMatrix(mat.width_, mat.height_, mat.unit.transpose(), mat.cts);
        }

        throw invalid_argument("Invalid arguments to unit_transpose");
    }

    /* Computes (the encoding of) the k^th row of A, given A^T */
    EncryptedRowVector LinearAlgebra::extractRow(const EncryptedMatrix &aTrans, int row) {
        int num_slots = aTrans.encoding_unit().encoding_width() * aTrans.encoding_unit().encoding_height();

        // create a mask for the k^th column of A^T, which is the k^th row of A
        vector<double> col_mask(num_slots);

        // compute which unit column the desired row is in
        int unit_col = row / aTrans.encoding_unit().encoding_width();
        // col_in_unit is the column within the encoding unit that contains the masked column
        int col_in_unit = row % aTrans.encoding_unit().encoding_width();

        for (size_t i = 0; i < num_slots; i++) {
            if (i % aTrans.encoding_unit().encoding_width() == col_in_unit) {
                col_mask[i] = 1;
            } else {
                col_mask[i] = 0;
            }
        }

        vector<CKKSCiphertext> isolated_col_cts(aTrans.num_vertical_units());
        for (int i = 0; i < aTrans.num_vertical_units(); i++) {
            isolated_col_cts[i] = eval.multiply_plain(aTrans.cts[i][unit_col], col_mask);
            eval.rescale_to_next_inplace(isolated_col_cts[i]);
            // we now have isolated the k^th column of A^T. To get an encoding of the k^th row of A
            // we need to replicate this column across all columns of the encoding unit

            // first step is to shift the column to the left
            if (col_in_unit != 0) {
                eval.rotate_left_inplace(isolated_col_cts[i], col_in_unit);
            }

            // now replicate this column to all other columns of the unit
            rot(isolated_col_cts[i], aTrans.encoding_unit().encoding_width(), 1, false);
        }
        return EncryptedRowVector(aTrans.height(), aTrans.encoding_unit(), isolated_col_cts);
    }

    /* Computes the k^th row of c*A*B^T given A^T and B, but NOT encoded as a vector.
     * First, mask out the k^th column of A^T, which is the k^th row of A.
     * The goal is to replicate this column to get the encoding of the k^th row of A (as columns)
     */
    EncryptedColVector LinearAlgebra::matrix_matrix_mul_loop(const EncryptedMatrix &matrix_aTrans,
                                                             const EncryptedMatrix &matrix_b, const double scalar,
                                                             int k, bool transpose_unit) {
        EncryptedRowVector kth_row_A = extractRow(matrix_aTrans, k);
        EncryptedColVector kth_row_A_times_BT = multiply(kth_row_A, matrix_b);
        rescale_to_next_inplace(kth_row_A_times_BT);

        // kth_row_A_times_BT is a column vector encoded as rows.
        // we need to mask out the desired row (but NOT replicate it; we will add it to the other rows later)

        int num_slots =
            matrix_aTrans.encoding_unit().encoding_width() * matrix_aTrans.encoding_unit().encoding_height();

        // Currently, each row of kth_row_A_times_BT is identical. We want to mask out one
        // so that we can add it to another row later to get our matrix product.
        // Create a mask for the k^th row of kth_row_A_times_BT.
        // This mask is scaled by c so that we get a constant multiplication for free.
        vector<double> row_mask(num_slots);

        if (transpose_unit) {
            // create a mask for the k^th row in a *transposed* encoding unit
            for (int i = 0; i < matrix_aTrans.encoding_unit().encoding_width(); i++) {
                for (int j = 0; j < matrix_aTrans.encoding_unit().encoding_height(); j++) {
                    if (i == k && j < matrix_b.width()) {
                        row_mask[i * matrix_aTrans.encoding_unit().encoding_height() + j] = scalar;
                    } else {
                        row_mask[i * matrix_aTrans.encoding_unit().encoding_height() + j] = 0;
                    }
                }
            }
        } else {
            // row_in_unit is the row within the encoding unit that should contain the masked row
            int row_in_unit = k % matrix_aTrans.encoding_unit().encoding_height();

            for (int i = 0; i < matrix_aTrans.encoding_unit().encoding_height(); i++) {
                for (int j = 0; j < matrix_aTrans.encoding_unit().encoding_width(); j++) {
                    if (i == row_in_unit) {
                        row_mask[i * matrix_aTrans.encoding_unit().encoding_width() + j] = scalar;
                    } else {
                        row_mask[i * matrix_aTrans.encoding_unit().encoding_width() + j] = 0;
                    }
                }
            }
        }

        // iterate over all the (horizontally adjacent) units of this column vector to mask out the kth row
        for (auto &ct : kth_row_A_times_BT.cts) {
            eval.multiply_plain_inplace(ct, row_mask);
        }

        return kth_row_A_times_BT;
    }

    vector<EncryptedColVector> LinearAlgebra::multiply_common(const EncryptedMatrix &matrix_aTrans,
                                                              const EncryptedMatrix &matrix_b, double scalar,
                                                              bool transpose_unit) {
        // This function requires b to be at one level below aTrans.
        // Ensure that's the case.
        EncryptedMatrix matrix_b_leveled = matrix_b;
        for (int i = 0; i < matrix_b.cts.size(); i++) {
            for (int j = 0; j < matrix_b.cts[0].size(); j++) {
                eval.mod_down_to_level_inplace(matrix_b_leveled.cts[i][j], matrix_aTrans.he_level() - 1);
            }
        }

        // we will iterate over all columns of A^T (rows of A)
        // and compute the k^th row of A times B^T
        // then combine the results for each row to get the matrix product
        vector<EncryptedColVector> row_results(matrix_aTrans.width());

        vector<int> iterIdxs(matrix_aTrans.width());
        for (int i = 0; i < matrix_aTrans.width(); i++) {
            iterIdxs[i] = i;
        }

        if (eval.evalPolicy == launch::deferred) {
            std::for_each(execution::seq, begin(iterIdxs), end(iterIdxs), [&](int k) {
                row_results[k] = matrix_matrix_mul_loop(matrix_aTrans, matrix_b_leveled, scalar, k, transpose_unit);
            });
        } else {
            std::for_each(execution::par, begin(iterIdxs), end(iterIdxs), [&](int k) {
                row_results[k] = matrix_matrix_mul_loop(matrix_aTrans, matrix_b_leveled, scalar, k, transpose_unit);
            });
        }
        return row_results;
    }

    EncryptedMatrix LinearAlgebra::multiply(const EncryptedMatrix &matrix_aTrans, const EncryptedMatrix &matrix_b,
                                            double scalar) {
        if (!matrix_aTrans.initialized() || !matrix_b.initialized() || matrix_aTrans.height() != matrix_b.height() ||
            matrix_aTrans.encoding_unit() != matrix_b.encoding_unit()) {
            throw invalid_argument("Arguments to LinearAlgebra::multiply do not have compatible dimensions.");
        }

        vector<EncryptedColVector> row_results = multiply_common(matrix_aTrans, matrix_b, scalar, false);

        // row_results[i] contains a *single* row (possibily distributed across several cts)
        // containing the i^th row of A times the matrix B
        // The next step is to add unit.encoding_height of these together to make a single unit
        int result_vertical_units =
            ceil(matrix_aTrans.width() / static_cast<double>(matrix_aTrans.encoding_unit().encoding_height()));
        vector<vector<CKKSCiphertext>> matrix_cts(result_vertical_units);

        for (int i = 0; i < result_vertical_units; i++) {
            // this is the ColVector containing the first row of this horizontal unit
            EncryptedColVector unit_row_i_cts = row_results[i * matrix_aTrans.encoding_unit().encoding_height()];
            for (int j = 1; j < matrix_aTrans.encoding_unit().encoding_height(); j++) {
                // there are exactly matrix_aTrans.width items in row_results, but this may not correspond
                // to the number of rows in the encoding units (because some rows at the end may be 0-padding)
                // thus, we need to break once we add all the ciphertexts in row_results
                // this will break out of the inner loop, but the outer loop will immediately exit because
                // the inner loop can only break when j = result_vertical_units-1
                if (i * matrix_aTrans.encoding_unit().encoding_height() + j >= matrix_aTrans.width()) {
                    break;
                }
                add_inplace(unit_row_i_cts, row_results[i * matrix_aTrans.encoding_unit().encoding_height() + j]);
            }
            matrix_cts[i] = unit_row_i_cts.cts;
        }

        return EncryptedMatrix(matrix_aTrans.width(), matrix_b.width(), matrix_aTrans.encoding_unit(), matrix_cts);
    }

    EncryptedMatrix LinearAlgebra::multiply_unit_transpose(const EncryptedMatrix &matrix_aTrans,
                                                           const EncryptedMatrix &matrix_b, double scalar) {
        /* Inputs: A t-by-s matrix A^T and t-by-u matrix B, both encoded with the same n-times-m unit,
         *         where t,m <= n and s,u <= m.
         * m -> matrix_b.unit.encoding_width
         * n -> matrix_b.unit.encoding_height
         * t -> matrix_b.height, matrix_aTrans.height
         * s -> matrix_aTrans.width
         * u -> matrix_b.width
         */
        if (!matrix_aTrans.initialized() || !matrix_b.initialized() || matrix_aTrans.height() != matrix_b.height() ||
            matrix_aTrans.encoding_unit() != matrix_b.encoding_unit() ||
            matrix_b.height() > matrix_b.encoding_unit().encoding_height() ||
            matrix_b.encoding_unit().encoding_width() > matrix_b.encoding_unit().encoding_height() ||
            matrix_aTrans.width() > matrix_b.encoding_unit().encoding_width() ||
            matrix_b.width() > matrix_b.encoding_unit().encoding_width()) {
            throw invalid_argument(
                "Arguments to LinearAlgebra::multiply_unit_transpose do not have compatible dimensions.");
        }

        vector<EncryptedColVector> row_results = multiply_common(matrix_aTrans, matrix_b, scalar, true);

        // row_results[i] contains a *single* row (inside a *single* encoding unit)
        // containing the i^th row of A times the matrix B
        // The next step is to add unit.encoding_height of these together to make a single unit
        // There will be exactly one ciphertext in the output matrix
        EncryptedColVector matrix_ct = row_results[0];

        for (int i = 1; i < matrix_aTrans.width(); i++) {
            add_inplace(matrix_ct, row_results[i]);
        }

        EncodingUnit tranposeUnit =
            EncodingUnit(matrix_b.encoding_unit().encoding_width(), matrix_b.encoding_unit().encoding_height());
        vector<vector<CKKSCiphertext>> matrix_cts{matrix_ct.cts};

        return EncryptedMatrix(matrix_aTrans.width(), matrix_b.width(), tranposeUnit, matrix_cts);
    }

    /* Generic helper for summing or replicating the rows or columns of an encoded matrix
     *
     * To sum columns, set `max` to the width of the matrix (must be a power of two), `stride` to 1, and rotateLeft=true
     * To sum rows, set `max` to the height of the matrix (must be a power of two), `stride` to the matrix width, and
     * rotateLeft=true To replicate columns, set `max` to the width of the matrix (must be a power of two), `stride` to
     * 1, and rotateLeft=false
     */
    void LinearAlgebra::rot(CKKSCiphertext &t1, int max, int stride, bool rotateLeft) {
        // serial implementation
        for (int i = 1; i < max; i <<= 1) {
            CKKSCiphertext t2;
            if (rotateLeft) {
                t2 = eval.rotate_left(t1, i * stride);
            } else {
                t2 = eval.rotate_right(t1, i * stride);
            }
            t1 = eval.add(t1, t2);
        }
    }

    /* Algorithm 3 in HHCP'18; see the paper for details.
     * sum the columns of a matrix packed into a single ciphertext
     * The plaintext is a vector representing the row-major format of a matrix with `width` columns.
     * All operations (like the left shift) occur on the vectorized form of the matrix.
     *
     * ASSUMPTIONS:
     *  - ct is a linear ciphertext
     *  - ct encodes a matrix
     *  - ct.width is a power of 2
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
    // Summing the columns of a matrix would typically produce a column vector.
    // Forget that.
    // This function returns the encoding of the *transpose* of that column vector,
    // which is a *row* vector.
    CKKSCiphertext LinearAlgebra::sum_cols_core(const CKKSCiphertext &ct, const EncodingUnit &unit, double scalar) {
        // if(!isPow2(ct.width)) {
        //   stringstream buffer;
        //   buffer << "sum_cols called with a non-power-2 width: " << ct.width;
        //   throw invalid_argument(buffer.str());
        // }
        // if(ct.encoding != COL_MAT) {
        //   throw invalid_argument("sum_cols argument must be a column matrix");
        // }
        CKKSCiphertext output = ct;

        // sum the columns, placing the result in the left-most column
        rot(output, unit.encoding_width(), 1, true);

        // At this point, the first column of the matrix represented by the plaintext holds the column sums
        // with the other columns hold garbage (i.e., the sum of some elements from row 1 and some from row 2)
        // We will zeroize everything but the first column by computing the Hadamard product with the matrix
        //     [ c 0 ... 0 ]
        // D = [ c 0 ... 0 ]
        //     [     ...   ]
        //     [ c 0 ... 0 ]

        vector<double> D;
        int matsize = ct.num_slots();
        D.reserve(matsize);

        // we assume that all slots outside of this matrix are already set to 0
        for (int i = 0; i < unit.encoding_height(); i++) {
            D.emplace_back(scalar);
            for (int j = 1; j < unit.encoding_width(); j++) {
                D.emplace_back(0);
            }
        }

        // mask out the first column
        output = eval.multiply_plain(output, D);

        // For now, I'm commenting this out so that all methods do as little rescaling as possible.
        // In theory, this allows more efficient circuits by allowing the developer to carefully place
        // rescales. However, rescaling here would make the rotation below more efficient, so it's not
        // clear which one is better. Preliminary benchmark results indicate that the rotation isn't
        // affected *too* much, so I'll leave this rescale up to the developer for now.
        // eval.rescale_to_next_inplace(output);

        // now the first column of the matrix holds the column sum; but we want to repeat the first column in each
        // column.
        rot(output, unit.encoding_width(), 1, false);

        return output;
    }

    // To sum the columns of a matrix, first sum all of the units in each row,
    // then call sum_cols_core on the result.
    // Repeat for each encoding unit row.
    EncryptedRowVector LinearAlgebra::sum_cols(const EncryptedMatrix &mat, double scalar) {
        vector<CKKSCiphertext> cts(mat.num_vertical_units());

        vector<int> iterIdxs(mat.num_vertical_units());
        for (int i = 0; i < mat.num_vertical_units(); i++) {
            iterIdxs[i] = i;
        }

        if (eval.evalPolicy == launch::deferred) {
            std::for_each(execution::seq, begin(iterIdxs), end(iterIdxs), [&](int i) {
                cts[i] = sum_cols_core(eval.add_many(mat.cts[i]), mat.encoding_unit(), scalar);
            });
        } else {
            std::for_each(execution::par, begin(iterIdxs), end(iterIdxs), [&](int i) {
                cts[i] = sum_cols_core(eval.add_many(mat.cts[i]), mat.encoding_unit(), scalar);
            });
        }

        return EncryptedRowVector(mat.height(), mat.encoding_unit(), cts);
    }

    /* Summing the rows of a matrix would typically produce a row vector.
     * Forget that.
     * This function returns the encoding of the *transpose* of that row vector,
     * which is a *column* vector.
     * Algorithm 2 in HHCP'18; see the paper for details.
     * sum the rows of a matrix packed into a single ciphertext
     * All operations (like the left shift) occur on the vectorized form of the matrix.
     *
     * ASSUMPTIONS:
     *  - ct is a linear ciphertext
     *  - ct encodes a matrix
     *  - ct.height is a power of 2
     *  - ct encodes a full-dimensional plaintext
     *
     * CONSUMES ZERO HE LEVELS
     *
     * NOTE: This function only works when the plaintext is full-dimensional.
     *       This prevents the need for masking and a second round of shifting
     *       as in colSum, at the cost of flexibility
     */
    CKKSCiphertext LinearAlgebra::sum_rows_core(const CKKSCiphertext &ct, const EncodingUnit &unit) {
        CKKSCiphertext output = ct;
        rot(output, unit.encoding_height(), unit.encoding_width(), true);
        return output;
    }

    CKKSCiphertext LinearAlgebra::sum_rows_loop(const EncryptedMatrix &mat, int j) {
        vector<CKKSCiphertext> col_prods(mat.num_vertical_units());
        // extract the j^th column of encoding units
        for (int i = 0; i < mat.num_vertical_units(); i++) {
            col_prods[i] = mat.cts[i][j];
        }
        return sum_rows_core(eval.add_many(col_prods), mat.encoding_unit());
    }

    // To sum the rows of a matrix, first sum all of the units in each column,
    // then call sum_rows_core on the result.
    // Repeat for each encoding unit column.
    EncryptedColVector LinearAlgebra::sum_rows(const EncryptedMatrix &mat) {
        vector<CKKSCiphertext> cts(mat.num_horizontal_units());

        vector<int> iterIdxs(mat.num_horizontal_units());
        for (int i = 0; i < mat.num_horizontal_units(); i++) {
            iterIdxs[i] = i;
        }

        if (eval.evalPolicy == launch::deferred) {
            std::for_each(execution::seq, begin(iterIdxs), end(iterIdxs),
                          [&](int j) { cts[j] = sum_rows_loop(mat, j); });
        } else {
            std::for_each(execution::par, begin(iterIdxs), end(iterIdxs),
                          [&](int j) { cts[j] = sum_rows_loop(mat, j); });
        }
        return EncryptedColVector(mat.width(), mat.encoding_unit(), cts);
    }

    /********* A Word on Encodings *********
     *
     *********   CKKS Basics   *********
     * The basic form of a CKKS plaintext is an 'array' of real or complex values
     * (distinguished from a 'vector', which will refer to linear algebra vectors
     * below). All plaintext arrays must first be *encoded* into a CKKS Plaintext
     * type. This encoding is done implicitly in the high-level API.
     * Plaintexts can then be encrypted to obtain a Ciphertext.
     *
     *********   HELR 101   *********
     * The algorithm implemented below is called 'mini-batch logistic regression
     * training'. The algorithm primarily utilizes linear algebra objects like
     * matrices and vectors. Recall that CKKS only knows how to handle arrays,
     * so we first need to encode these linear algebra objects as an array
     * before we can CKKS-encode them and encrypt them.
     *
     *********   Matrix Encoding   *********
     * A matrix is encoded as a single array (which is then encoded as a CKKS
     * plaintext, and then encrypted into a CKKS ciphertext) by concatenating the
     * rows of the matrix (i.e., row-major encoding). Any operations that refer to
     * matrices really is talking about inducing something on the underlying array
     * representation. (Note: It *really* induces an operation on the *padded* array.
     * CKKS encoding takes a plaintext array like < 1,2,3,4 > and first pads it with
     * 0s until it has length poly_modulus_degree/2.)
     * A good example is a rotation. Rotations don't operate
     * directly on rows of the matrix, they operate on the array as a whole, which
     * does not correspond to rotating the rows of the matrix. We have to do extra
     * work to build "matrix row rotation" out of "array rotation".
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

    vector<vector<Matrix>> encode_matrix(const Matrix &mat, const EncodingUnit &unit) {
        int height = mat.size1();
        int width = mat.size2();

        int num_vertical_units = ceil(height / static_cast<double>(unit.encoding_height()));
        int num_horizontal_units = ceil(width / static_cast<double>(unit.encoding_width()));

        vector<vector<Matrix>> cts(num_vertical_units);
        for (int i = 0; i < num_vertical_units; i++) {
            vector<Matrix> row_units(num_horizontal_units);
            for (int j = 0; j < num_horizontal_units; j++) {
                vector<double> unit_ij;
                unit_ij.reserve(unit.encoding_height() * unit.encoding_width());
                for (int k = 0; k < unit.encoding_height(); k++) {
                    for (int l = 0; l < unit.encoding_width(); l++) {
                        int row = unit.encoding_height() * i + k;
                        int col = unit.encoding_width() * j + l;
                        if (row < height && col < width) {
                            unit_ij.emplace_back(mat.data()[row * width + col]);
                        } else {
                            unit_ij.emplace_back(0);
                        }
                    }
                }
                row_units[j] = Matrix(unit.encoding_height(), unit.encoding_width(), unit_ij);
            }
            cts[i] = row_units;
        }
        return cts;
    }

    Matrix decode_matrix(const vector<vector<Matrix>> &mats, int trim_height, int trim_width) {
        if (mats.empty() || mats[0].empty()) {
            throw invalid_argument("decode_matrix: input cannot be empty");
        }

        int height = mats[0][0].size1();
        int width = mats[0][0].size2();

        if (trim_height < 0) {
            trim_height = static_cast<int>(mats.size() * height);
        }
        if (trim_width < 0) {
            trim_width = static_cast<int>(mats[0].size() * width);
        }

        vector<double> linear_matrix;
        linear_matrix.reserve(trim_height * trim_width);
        for (int i = 0; i < mats.size(); i++) {
            if (mats[i].size() != mats[0].size()) {
                throw invalid_argument("decode_matrix: all rows must have the same length");
            }
            // for each Matrix row
            for (int j = 0; j < height && i * height + j < trim_height; j++) {
                for (int k = 0; k < mats[0].size(); k++) {
                    if (mats[i][k].size1() != height || mats[i][k].size2() != width) {
                        throw invalid_argument("decode_matrix: all matrices must have the same dimension");
                    }
                    for (int l = 0; l < width && k * width + l < trim_width; l++) {
                        linear_matrix.emplace_back(mats[i][k].data()[j * width + l]);
                    }
                }
            }
        }
        return Matrix(trim_height, trim_width, linear_matrix);
    }

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
            throw invalid_argument("decode_row_vector: input cannot be empty");
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
