// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "linearalgebra.h"

#include <algorithm>
#include <execution>

using namespace std;

namespace hit {
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
                row_cts[j] = eval.encrypt(mat_pieces[i][j].data(), level);
            }
            mat_cts[i] = row_cts;
        }
        return EncryptedMatrix(mat.size1(), mat.size2(), unit, mat_cts);
    }

    Matrix LinearAlgebra::decrypt(const EncryptedMatrix &enc_mat, bool suppress_warnings) const {
        if (!enc_mat.initialized()) {
            throw invalid_argument("Cannot decrypt uninitialized enc_matrix");
        }

        if (!suppress_warnings) {
            decryption_warning(enc_mat.he_level());
        }

        vector<vector<Matrix>> mat_pieces(enc_mat.cts.size());
        for (int i = 0; i < enc_mat.cts.size(); i++) {
            vector<Matrix> row_pieces(enc_mat.cts[0].size());
            for (int j = 0; j < enc_mat.cts[0].size(); j++) {
                row_pieces[j] = Matrix(enc_mat.encoding_unit().encoding_height(),
                                       enc_mat.encoding_unit().encoding_width(), eval.decrypt(enc_mat.cts[i][j], true));
            }
            mat_pieces[i] = row_pieces;
        }
        return decode_matrix(mat_pieces, enc_mat.height(), enc_mat.width());
    }

    template <>
    string LinearAlgebra::dim_string(const EncodingUnit &arg) {
        return "unit " + to_string(arg.encoding_height()) + "x" + to_string(arg.encoding_width());
    }

    template <>
    string LinearAlgebra::dim_string(const EncryptedMatrix &arg) {
        return "matrix " + to_string(arg.height()) + "x" + to_string(arg.width()) + " (" + dim_string(arg.unit) + ")";
    }

    template <>
    string LinearAlgebra::dim_string(const EncryptedRowVector &arg) {
        return "row " + to_string(arg.width()) + " (" + dim_string(arg.unit) + ")";
    }

    EncryptedRowVector LinearAlgebra::encrypt_row_vector(const Vector &vec, const EncodingUnit &unit, int level) {
        vector<Matrix> mat_pieces = encode_row_vector(vec, unit);
        vector<CKKSCiphertext> mat_cts(mat_pieces.size());
        for (int i = 0; i < mat_pieces.size(); i++) {
            mat_cts[i] = eval.encrypt(mat_pieces[i].data(), level);
        }
        return EncryptedRowVector(vec.size(), unit, mat_cts);
    }

    Vector LinearAlgebra::decrypt(const EncryptedRowVector &enc_vec, bool suppress_warnings) const {
        if (!enc_vec.initialized()) {
            throw invalid_argument("Cannot decrypt uninitialized row vector");
        }

        if (!suppress_warnings) {
            decryption_warning(enc_vec.he_level());
        }

        vector<Matrix> mat_pieces(enc_vec.cts.size());
        for (int i = 0; i < enc_vec.cts.size(); i++) {
            mat_pieces[i] = Matrix(enc_vec.encoding_unit().encoding_height(), enc_vec.encoding_unit().encoding_width(),
                                   eval.decrypt(enc_vec.cts[i], true));
        }
        return decode_row_vector(mat_pieces, enc_vec.width());
    }

    template <>
    string LinearAlgebra::dim_string(const EncryptedColVector &arg) {
        return "col " + to_string(arg.height()) + " (" + dim_string(arg.unit) + ")";
    }

    EncryptedColVector LinearAlgebra::encrypt_col_vector(const Vector &vec, const EncodingUnit &unit, int level) {
        vector<Matrix> mat_pieces = encode_col_vector(vec, unit);
        vector<CKKSCiphertext> mat_cts(mat_pieces.size());
        for (int i = 0; i < mat_pieces.size(); i++) {
            mat_cts[i] = eval.encrypt(mat_pieces[i].data(), level);
        }
        return EncryptedColVector(vec.size(), unit, mat_cts);
    }

    EncodingUnit LinearAlgebra::make_unit(int encoding_height) const {
        return EncodingUnit(encoding_height, eval.num_slots() / encoding_height);
    }

    Vector LinearAlgebra::decrypt(const EncryptedColVector &enc_vec, bool suppress_warnings) const {
        if (!enc_vec.initialized()) {
            throw invalid_argument("Cannot decrypt uninitialized column vector");
        }

        if (!suppress_warnings) {
            decryption_warning(enc_vec.he_level());
        }

        vector<Matrix> mat_pieces(enc_vec.cts.size());
        for (int i = 0; i < enc_vec.cts.size(); i++) {
            mat_pieces[i] = Matrix(enc_vec.encoding_unit().encoding_height(), enc_vec.encoding_unit().encoding_width(),
                                   eval.decrypt(enc_vec.cts[i], true));
        }
        return decode_col_vector(mat_pieces, enc_vec.height());
    }

    LinearAlgebra::LinearAlgebra(CKKSEvaluator &eval) : eval(eval) {
    }

    // explicit template instantiation
    template EncryptedMatrix LinearAlgebra::add(const EncryptedMatrix &, const EncryptedMatrix &);
    template void LinearAlgebra::add_inplace(EncryptedMatrix &, const EncryptedMatrix &);
    template EncryptedMatrix LinearAlgebra::add_many(const vector<EncryptedMatrix> &);
    template EncryptedMatrix LinearAlgebra::add_plain(const EncryptedMatrix &, const Matrix &);
    template EncryptedMatrix LinearAlgebra::add_plain(const EncryptedMatrix &, double);
    template void LinearAlgebra::add_plain_inplace(EncryptedMatrix &enc_mat, double scalar);
    template EncryptedMatrix LinearAlgebra::multiply_plain(const EncryptedMatrix &, double);
    template EncryptedMatrix LinearAlgebra::reduce_level_to(const EncryptedMatrix &, int);
    template void LinearAlgebra::reduce_level_to_inplace(EncryptedMatrix &, int);
    template void LinearAlgebra::rescale_to_next_inplace(EncryptedMatrix &);
    template EncryptedMatrix LinearAlgebra::rescale_to_next(const EncryptedMatrix &);
    template void LinearAlgebra::relinearize_inplace(EncryptedMatrix &);
    template void LinearAlgebra::hadamard_square_inplace(EncryptedMatrix &);
    template EncryptedMatrix LinearAlgebra::hadamard_square(const EncryptedMatrix &);
    template EncryptedMatrix LinearAlgebra::hadamard_multiply(const EncryptedMatrix &, const EncryptedMatrix &);
    template void LinearAlgebra::hadamard_multiply_inplace(EncryptedMatrix &, const EncryptedMatrix &);
    template EncryptedMatrix LinearAlgebra::reduce_level_to(const EncryptedMatrix &, const EncryptedMatrix &);
    template EncryptedMatrix LinearAlgebra::reduce_level_to(const EncryptedMatrix &, const EncryptedRowVector &);
    template EncryptedMatrix LinearAlgebra::reduce_level_to(const EncryptedMatrix &, const EncryptedColVector &);
    template void LinearAlgebra::reduce_level_to_inplace(EncryptedMatrix &, const EncryptedMatrix &);
    template void LinearAlgebra::reduce_level_to_inplace(EncryptedMatrix &, const EncryptedRowVector &);
    template void LinearAlgebra::reduce_level_to_inplace(EncryptedMatrix &, const EncryptedColVector &);
    template void LinearAlgebra::reduce_level_to_min_inplace(EncryptedMatrix &, EncryptedMatrix &);
    template void LinearAlgebra::reduce_level_to_min_inplace(EncryptedMatrix &, EncryptedRowVector &);
    template void LinearAlgebra::reduce_level_to_min_inplace(EncryptedMatrix &, EncryptedColVector &);

    // explicit template instantiation
    template EncryptedRowVector LinearAlgebra::add(const EncryptedRowVector &, const EncryptedRowVector &);
    template void LinearAlgebra::add_inplace(EncryptedRowVector &, const EncryptedRowVector &);
    template EncryptedRowVector LinearAlgebra::add_many(const vector<EncryptedRowVector> &);
    template EncryptedRowVector LinearAlgebra::add_plain(const EncryptedRowVector &, const Vector &);
    template EncryptedRowVector LinearAlgebra::add_plain(const EncryptedRowVector &, double);
    template void LinearAlgebra::add_plain_inplace(EncryptedRowVector &enc_vec, double scalar);
    template EncryptedRowVector LinearAlgebra::multiply_plain(const EncryptedRowVector &, double);
    template EncryptedRowVector LinearAlgebra::reduce_level_to(const EncryptedRowVector &, int);
    template void LinearAlgebra::reduce_level_to_inplace(EncryptedRowVector &, int);
    template void LinearAlgebra::rescale_to_next_inplace(EncryptedRowVector &);
    template EncryptedRowVector LinearAlgebra::rescale_to_next(const EncryptedRowVector &);
    template void LinearAlgebra::relinearize_inplace(EncryptedRowVector &);
    template void LinearAlgebra::hadamard_square_inplace(EncryptedRowVector &);
    template EncryptedRowVector LinearAlgebra::hadamard_square(const EncryptedRowVector &);
    template EncryptedRowVector LinearAlgebra::hadamard_multiply(const EncryptedRowVector &,
                                                                 const EncryptedRowVector &);
    template void LinearAlgebra::hadamard_multiply_inplace(EncryptedRowVector &, const EncryptedRowVector &);
    template EncryptedRowVector LinearAlgebra::reduce_level_to(const EncryptedRowVector &, const EncryptedMatrix &);
    template EncryptedRowVector LinearAlgebra::reduce_level_to(const EncryptedRowVector &, const EncryptedRowVector &);
    template EncryptedRowVector LinearAlgebra::reduce_level_to(const EncryptedRowVector &, const EncryptedColVector &);
    template void LinearAlgebra::reduce_level_to_inplace(EncryptedRowVector &, const EncryptedMatrix &);
    template void LinearAlgebra::reduce_level_to_inplace(EncryptedRowVector &, const EncryptedRowVector &);
    template void LinearAlgebra::reduce_level_to_inplace(EncryptedRowVector &, const EncryptedColVector &);
    template void LinearAlgebra::reduce_level_to_min_inplace(EncryptedRowVector &, EncryptedMatrix &);
    template void LinearAlgebra::reduce_level_to_min_inplace(EncryptedRowVector &, EncryptedRowVector &);
    template void LinearAlgebra::reduce_level_to_min_inplace(EncryptedRowVector &, EncryptedColVector &);


    // explicit template instantiation
    template EncryptedColVector LinearAlgebra::add(const EncryptedColVector &, const EncryptedColVector &);
    template void LinearAlgebra::add_inplace(EncryptedColVector &, const EncryptedColVector &);
    template EncryptedColVector LinearAlgebra::add_many(const vector<EncryptedColVector> &);
    template EncryptedColVector LinearAlgebra::add_plain(const EncryptedColVector &, const Vector &);
    template EncryptedColVector LinearAlgebra::add_plain(const EncryptedColVector &, double);
    template void LinearAlgebra::add_plain_inplace(EncryptedColVector &enc_vec, double scalar);
    template EncryptedColVector LinearAlgebra::multiply_plain(const EncryptedColVector &, double);
    template EncryptedColVector LinearAlgebra::reduce_level_to(const EncryptedColVector &, int);
    template void LinearAlgebra::reduce_level_to_inplace(EncryptedColVector &, int);
    template void LinearAlgebra::rescale_to_next_inplace(EncryptedColVector &);
    template EncryptedColVector LinearAlgebra::rescale_to_next(const EncryptedColVector &);
    template void LinearAlgebra::relinearize_inplace(EncryptedColVector &);
    template void LinearAlgebra::hadamard_square_inplace(EncryptedColVector &);
    template EncryptedColVector LinearAlgebra::hadamard_square(const EncryptedColVector &);
    template EncryptedColVector LinearAlgebra::hadamard_multiply(const EncryptedColVector &,
                                                                 const EncryptedColVector &);
    template void LinearAlgebra::hadamard_multiply_inplace(EncryptedColVector &, const EncryptedColVector &);
    template EncryptedColVector LinearAlgebra::reduce_level_to(const EncryptedColVector &, const EncryptedMatrix &);
    template EncryptedColVector LinearAlgebra::reduce_level_to(const EncryptedColVector &, const EncryptedRowVector &);
    template EncryptedColVector LinearAlgebra::reduce_level_to(const EncryptedColVector &, const EncryptedColVector &);
    template void LinearAlgebra::reduce_level_to_inplace(EncryptedColVector &, const EncryptedMatrix &);
    template void LinearAlgebra::reduce_level_to_inplace(EncryptedColVector &, const EncryptedRowVector &);
    template void LinearAlgebra::reduce_level_to_inplace(EncryptedColVector &, const EncryptedColVector &);
    template void LinearAlgebra::reduce_level_to_min_inplace(EncryptedColVector &, EncryptedMatrix &);
    template void LinearAlgebra::reduce_level_to_min_inplace(EncryptedColVector &, EncryptedRowVector &);
    template void LinearAlgebra::reduce_level_to_min_inplace(EncryptedColVector &, EncryptedColVector &);

    void LinearAlgebra::add_plain_inplace(EncryptedMatrix &enc_mat1, const Matrix &mat2) {
        if (!enc_mat1.initialized() || enc_mat1.height() != mat2.size1() || enc_mat1.width() != mat2.size2()) {
            throw invalid_argument("Arguments to LinearAlgebra::add_inplace do not have the same dimensions.");
        }
        vector<vector<Matrix>> encoded_matrix = encode_matrix(mat2, enc_mat1.encoding_unit());

        for (int i = 0; i < enc_mat1.cts.size(); i++) {
            for (int j = 0; j < enc_mat1.cts[0].size(); j++) {
                eval.add_plain_inplace(enc_mat1.cts[i][j], encoded_matrix[i][j].data());
            }
        }
    }

    void LinearAlgebra::add_plain_inplace(EncryptedRowVector &enc_vec1, const Vector &vec2) {
        if (!enc_vec1.initialized() || enc_vec1.width() != vec2.size()) {
            throw invalid_argument("Arguments to LinearAlgebra::add_inplace do not have the same dimensions.");
        }
        vector<Matrix> encoded_vector = encode_row_vector(vec2, enc_vec1.encoding_unit());

        for (int i = 0; i < enc_vec1.cts.size(); i++) {
            eval.add_plain_inplace(enc_vec1.cts[i], encoded_vector[i].data());
        }
    }

    void LinearAlgebra::add_plain_inplace(EncryptedColVector &enc_vec1, const Vector &vec2) {
        if (!enc_vec1.initialized() || enc_vec1.height() != vec2.size()) {
            throw invalid_argument("Arguments to LinearAlgebra::add_inplace do not have the same dimensions.");
        }
        vector<Matrix> encoded_vector = encode_col_vector(vec2, enc_vec1.encoding_unit());

        for (int i = 0; i < enc_vec1.cts.size(); i++) {
            eval.add_plain_inplace(enc_vec1.cts[i], encoded_vector[i].data());
        }
    }

    vector<CKKSCiphertext> LinearAlgebra::matrix_rowvec_hadamard_mul_loop(const EncryptedRowVector &enc_vec,
                                                                          const EncryptedMatrix &enc_mat, int j) {
        vector<CKKSCiphertext> col_prods(enc_mat.num_vertical_units());
        for (int i = 0; i < enc_mat.num_vertical_units(); i++) {
            col_prods[i] = eval.multiply(enc_mat.cts[i][j], enc_vec.cts[i]);
        }
        return col_prods;
    }

    EncryptedMatrix LinearAlgebra::hadamard_multiply(const EncryptedRowVector &enc_vec,
                                                     const EncryptedMatrix &enc_mat) {
        if (!enc_vec.initialized() || !enc_mat.initialized()) {
            throw invalid_argument("LinearAlgebra::hadamard_multiply: arguments not initialized.");
        }
        if (enc_mat.height() != enc_vec.width() || enc_mat.encoding_unit() != enc_vec.encoding_unit()) {
            throw invalid_argument("Dimension mismatch in LinearAlgebra::hadamard_multiply: " + dim_string(enc_mat) +
                                   " vs " + dim_string(enc_vec));
        }

        vector<vector<CKKSCiphertext>> cts_transpose(enc_mat.num_horizontal_units());

        vector<int> iterIdxs(enc_mat.num_horizontal_units());
        for (int i = 0; i < enc_mat.num_horizontal_units(); i++) {
            iterIdxs[i] = i;
        }

        for_each(execution::par, begin(iterIdxs), end(iterIdxs),
                      [&](int j) { cts_transpose[j] = matrix_rowvec_hadamard_mul_loop(enc_vec, enc_mat, j);
        });

        // Because we iterate over the *columns* of the encoding, the encoding units are transposed
        // We un-transpose them here.
        vector<vector<CKKSCiphertext>> cts(enc_mat.num_vertical_units());

        for (int i = 0; i < enc_mat.num_vertical_units(); i++) {
            vector<CKKSCiphertext> mat_row(enc_mat.num_horizontal_units());
            for (int j = 0; j < enc_mat.num_horizontal_units(); j++) {
                mat_row[j] = cts_transpose[j][i];
            }
            cts[i] = mat_row;
        }

        return EncryptedMatrix(enc_mat.height(), enc_mat.width(), enc_mat.encoding_unit(), cts);
    }

    vector<CKKSCiphertext> LinearAlgebra::matrix_colvec_hadamard_mul_loop(const EncryptedMatrix &enc_mat,
                                                                          const EncryptedColVector &enc_vec, int i) {
        vector<CKKSCiphertext> row_prods(enc_mat.num_horizontal_units());
        for (int j = 0; j < enc_mat.num_horizontal_units(); j++) {
            row_prods[j] = eval.multiply(enc_mat.cts[i][j], enc_vec.cts[j]);
        }
        return row_prods;
    }

    EncryptedMatrix LinearAlgebra::hadamard_multiply(const EncryptedMatrix &enc_mat,
                                                     const EncryptedColVector &enc_vec) {
        if (!enc_vec.initialized() || !enc_mat.initialized()) {
            throw invalid_argument("LinearAlgebra::hadamard_multiply: arguments not initialized.");
        }
        if (enc_mat.width() != enc_vec.height() || enc_mat.encoding_unit() != enc_vec.encoding_unit()) {
            throw invalid_argument("Dimension mismatch in LinearAlgebra::hadamard_multiply: " + dim_string(enc_mat) +
                                   " vs " + dim_string(enc_vec));
        }
        if (enc_mat.he_level() != enc_vec.he_level()) {
            throw invalid_argument("LinearAlgebra::hadamard_multiply: arguments are not at the same level");
        }
        if (enc_mat.scale() != enc_vec.scale()) {
            throw invalid_argument("LinearAlgebra::hadamard_multiply: arguments do not have the same scale: " +
                                   to_string(log2(enc_mat.scale())) + " != " + to_string(log2(enc_vec.scale())));
        }
        if (enc_mat.needs_rescale() || enc_vec.needs_rescale()) {
            throw invalid_argument("LinearAlgebra::hadamard_multiply: arguments must have nominal scale");
        }
        if (enc_mat.needs_relin() || enc_vec.needs_relin()) {
            throw invalid_argument("LinearAlgebra::hadamard_multiply: arguments must be linear ciphertexts");
        }

        vector<vector<CKKSCiphertext>> cts(enc_mat.num_vertical_units());

        vector<int> iterIdxs(enc_mat.num_vertical_units());
        for (int i = 0; i < enc_mat.num_vertical_units(); i++) {
            iterIdxs[i] = i;
        }

        for_each(execution::par, begin(iterIdxs), end(iterIdxs),
                      [&](int i) { cts[i] = matrix_colvec_hadamard_mul_loop(enc_mat, enc_vec, i);
        });

        return EncryptedMatrix(enc_mat.height(), enc_mat.width(), enc_mat.encoding_unit(), cts);
    }

    EncryptedColVector LinearAlgebra::multiply(const EncryptedRowVector &enc_vec, const EncryptedMatrix &enc_mat) {
        if (enc_mat.he_level() != enc_vec.he_level()) {
            throw invalid_argument("LinearAlgebra::multiply: arguments are not at the same level");
        }
        if (enc_mat.scale() != enc_vec.scale()) {
            throw invalid_argument("LinearAlgebra::multiply: arguments do not have the same scale: " +
                                   to_string(log2(enc_mat.scale())) + " != " + to_string(log2(enc_vec.scale())));
        }
        if (enc_mat.needs_rescale() || enc_vec.needs_rescale()) {
            throw invalid_argument("LinearAlgebra::multiply: arguments must have nominal scale");
        }
        if (enc_mat.needs_relin() || enc_vec.needs_relin()) {
            throw invalid_argument("LinearAlgebra::multiply: arguments must be linear ciphertexts");
        }
        EncryptedMatrix hadmard_prod = hadamard_multiply(enc_vec, enc_mat);
        // rotation requires a linear ciphertext, but does not require rescaling
        relinearize_inplace(hadmard_prod);
        return sum_rows(hadmard_prod);
    }

    EncryptedRowVector LinearAlgebra::multiply(const EncryptedMatrix &enc_mat, const EncryptedColVector &enc_vec,
                                               double scalar) {
        if (enc_mat.he_level() != enc_vec.he_level()) {
            throw invalid_argument("LinearAlgebra::multiply: arguments are not at the same level");
        }
        if (enc_mat.scale() != enc_vec.scale()) {
            throw invalid_argument("LinearAlgebra::multiply: arguments do not have the same scale: " +
                                   to_string(log2(enc_mat.scale())) + " != " + to_string(log2(enc_vec.scale())));
        }
        if (enc_mat.needs_rescale() || enc_vec.needs_rescale()) {
            throw invalid_argument("LinearAlgebra::multiply: arguments must have nominal scale");
        }
        if (enc_mat.needs_relin() || enc_vec.needs_relin()) {
            throw invalid_argument("LinearAlgebra::multiply: arguments must be linear ciphertexts");
        }
        EncryptedMatrix hadmard_prod = hadamard_multiply(enc_mat, enc_vec);
        relinearize_inplace(hadmard_prod);
        rescale_to_next_inplace(hadmard_prod);
        return sum_cols(hadmard_prod, scalar);
    }

    /* Computes (the encoding of) the k^th row of A, given A^T */
    EncryptedRowVector LinearAlgebra::extract_row(const EncryptedMatrix &enc_mat_a_trans, int row) {
        EncodingUnit unit = enc_mat_a_trans.encoding_unit();

        // create a mask for the k^th column of A^T, which is the k^th row of A
        // col_mask is a single encoding unit, which will be replicated for every
        // vertical unit of the encoding of A^T
        vector<double> col_mask(enc_mat_a_trans.num_slots());

        // compute which unit column the desired row is in
        int unit_col = row / unit.encoding_width();
        // col_in_unit is the column within the encoding unit that contains the masked column
        int col_in_unit = row % unit.encoding_width();

        // create the column mask encoding unit
        for (size_t i = 0; i < enc_mat_a_trans.num_slots(); i++) {
            if (i % unit.encoding_width() == col_in_unit) {
                col_mask[i] = 1;
            } else {
                col_mask[i] = 0;
            }
        }

        vector<CKKSCiphertext> isolated_col_cts(enc_mat_a_trans.num_vertical_units());
        for (int i = 0; i < enc_mat_a_trans.num_vertical_units(); i++) {
            isolated_col_cts[i] = eval.multiply_plain(enc_mat_a_trans.cts[i][unit_col], col_mask);
            eval.rescale_to_next_inplace(isolated_col_cts[i]);
            // we now have isolated the k^th column of A^T. To get an encoding of the k^th row of A
            // we need to replicate this column across all columns of the encoding unit

            // first step is to shift the column to the left
            if (col_in_unit != 0) {
                eval.rotate_left_inplace(isolated_col_cts[i], col_in_unit);
            }

            // now replicate this column to all other columns of the unit
            rot(isolated_col_cts[i], unit.encoding_width(), 1, false);
        }
        return EncryptedRowVector(enc_mat_a_trans.height(), unit, isolated_col_cts);
    }

    /* Computes the k^th row of c*A*B^T given A^T and B, but NOT encoded as a vector.
     * First, mask out the k^th column of A^T, which is the k^th row of A.
     * The goal is to replicate this column to get the encoding of the k^th row of A (as columns)
     */
    EncryptedColVector LinearAlgebra::matrix_matrix_mul_loop(const EncryptedMatrix &enc_mat_a_trans,
                                                             const EncryptedMatrix &enc_mat_b, const double scalar,
                                                             int k, bool transpose_unit) {
        EncryptedRowVector kth_row_A = extract_row(enc_mat_a_trans, k);
        EncryptedColVector kth_row_A_times_BT = multiply(kth_row_A, enc_mat_b);
        rescale_to_next_inplace(kth_row_A_times_BT);

        // kth_row_A_times_BT is a column vector encoded as rows.
        // we need to mask out the desired row (but NOT replicate it; we will add it to the other rows later)

        int num_slots =
            enc_mat_a_trans.encoding_unit().encoding_width() * enc_mat_a_trans.encoding_unit().encoding_height();

        // Currently, each row of kth_row_A_times_BT is identical. We want to mask out one
        // so that we can add it to another row later to get our matrix product.
        // Create a mask for the k^th row of kth_row_A_times_BT.
        // This mask is scaled by c so that we get a constant multiplication for free.
        vector<double> row_mask(num_slots);

        if (transpose_unit) {
            // create a mask for the k^th row in a *transposed* encoding unit
            for (int i = 0; i < enc_mat_a_trans.encoding_unit().encoding_width(); i++) {
                for (int j = 0; j < enc_mat_a_trans.encoding_unit().encoding_height(); j++) {
                    if (i == k && j < enc_mat_b.width()) {
                        row_mask[i * enc_mat_a_trans.encoding_unit().encoding_height() + j] = scalar;
                    } else {
                        row_mask[i * enc_mat_a_trans.encoding_unit().encoding_height() + j] = 0;
                    }
                }
            }
        } else {
            // row_in_unit is the row within the encoding unit that should contain the masked row
            int row_in_unit = k % enc_mat_a_trans.encoding_unit().encoding_height();

            for (int i = 0; i < enc_mat_a_trans.encoding_unit().encoding_height(); i++) {
                for (int j = 0; j < enc_mat_a_trans.encoding_unit().encoding_width(); j++) {
                    if (i == row_in_unit) {
                        row_mask[i * enc_mat_a_trans.encoding_unit().encoding_width() + j] = scalar;
                    } else {
                        row_mask[i * enc_mat_a_trans.encoding_unit().encoding_width() + j] = 0;
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

    // common core for matrix/matrix multiplication; used by both multiply and multiply_unit_transpose
    vector<EncryptedColVector> LinearAlgebra::multiply_common(const EncryptedMatrix &enc_mat_a_trans,
                                                              const EncryptedMatrix &enc_mat_b, double scalar,
                                                              bool transpose_unit) {
        // This function requires b to be at one level below enc_enc_mat_a_trans.

        // we will iterate over all columns of A^T (rows of A)
        // and compute the k^th row of A times B^T
        // then combine the results for each row to get the matrix product
        vector<EncryptedColVector> row_results(enc_mat_a_trans.width());

        vector<int> iterIdxs(enc_mat_a_trans.width());
        for (int i = 0; i < enc_mat_a_trans.width(); i++) {
            iterIdxs[i] = i;
        }

        for_each(execution::par, begin(iterIdxs), end(iterIdxs), [&](int k) {
            row_results[k] = matrix_matrix_mul_loop(enc_mat_a_trans, enc_mat_b, scalar, k, transpose_unit);
        });

        return row_results;
    }

    EncryptedMatrix LinearAlgebra::multiply(const EncryptedMatrix &enc_mat_a_trans, const EncryptedMatrix &enc_mat_b,
                                            double scalar) {
        if (!enc_mat_a_trans.initialized() || !enc_mat_b.initialized()) {
            throw invalid_argument("Arguments to LinearAlgebra::multiply are not initialized");
        }
        if (enc_mat_a_trans.he_level() != enc_mat_b.he_level() + 1) {
            throw invalid_argument("Second argument to LinearAlgebra::multiply must be one level below first argument");
        }
        if (enc_mat_a_trans.height() != enc_mat_b.height() ||
            enc_mat_a_trans.encoding_unit() != enc_mat_b.encoding_unit()) {
            throw invalid_argument("Arguments to LinearAlgebra::multiply do not have compatible dimensions: " +
                                   dim_string(enc_mat_a_trans) + " vs " + dim_string(enc_mat_b));
        }
        if (enc_mat_a_trans.needs_rescale() || enc_mat_b.needs_rescale()) {
            throw invalid_argument("LinearAlgebra::multiply: arguments must have nominal scale");
        }
        if (enc_mat_a_trans.needs_relin() || enc_mat_b.needs_relin()) {
            throw invalid_argument("LinearAlgebra::multiply: arguments must be linear ciphertexts");
        }

        // Multiply each row of A by the matrix B. The result is a list of column vectors.
        vector<EncryptedColVector> row_results = multiply_common(enc_mat_a_trans, enc_mat_b, scalar, false);

        // row_results[i] contains a *single* row (possibily distributed across several cts)
        // containing the i^th row of A times the matrix B
        // The next step is to add unit.encoding_height of these together to make a single unit
        int result_vertical_units =
            ceil(enc_mat_a_trans.width() / static_cast<double>(enc_mat_a_trans.encoding_unit().encoding_height()));
        vector<vector<CKKSCiphertext>> matrix_cts(result_vertical_units);

        for (int i = 0; i < result_vertical_units; i++) {
            // this is the ColVector containing the first row of this horizontal unit
            EncryptedColVector unit_row_i_cts = row_results[i * enc_mat_a_trans.encoding_unit().encoding_height()];
            for (int j = 1; j < enc_mat_a_trans.encoding_unit().encoding_height(); j++) {
                // there are exactly enc_mat_a_trans.width items in row_results, but this may not correspond
                // to the number of rows in the encoding units (because some rows at the end may be 0-padding)
                // thus, we need to break once we add all the ciphertexts in row_results
                // this will break out of the inner loop, but the outer loop will immediately exit because
                // the inner loop can only break when j = result_vertical_units-1
                if (i * enc_mat_a_trans.encoding_unit().encoding_height() + j >= enc_mat_a_trans.width()) {
                    break;
                }
                add_inplace(unit_row_i_cts, row_results[i * enc_mat_a_trans.encoding_unit().encoding_height() + j]);
            }
            matrix_cts[i] = unit_row_i_cts.cts;
        }

        return EncryptedMatrix(enc_mat_a_trans.width(), enc_mat_b.width(), enc_mat_a_trans.encoding_unit(), matrix_cts);
    }

    /* Generic helper for summing or replicating the rows or columns of an encoded matrix
     *
     * To sum columns, set `max` to the width of the matrix (must be a power of two), `stride` to 1, and rotateLeft=true
     * To sum rows, set `max` to the height of the matrix (must be a power of two), `stride` to the matrix width, and
     * rotateLeft=true To replicate columns, set `max` to the width of the matrix (must be a power of two), `stride` to
     * 1, and rotateLeft=false
     */
    void LinearAlgebra::rot(CKKSCiphertext &t1, int max, int stride, bool rotate_left) {
        // serial implementation
        for (int i = 1; i < max; i <<= 1) {
            CKKSCiphertext t2;
            if (rotate_left) {
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
        // if(!is_pow2(ct.width)) {
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
    EncryptedRowVector LinearAlgebra::sum_cols(const EncryptedMatrix &enc_mat, double scalar) {
        if(enc_mat.needs_relin()) {
            throw invalid_argument("Input to sum_cols must be a linear ciphertext");
        }
        if(enc_mat.needs_rescale()) {
            throw invalid_argument("Input to sum_cols must have nominal scale");
        }

        vector<CKKSCiphertext> cts(enc_mat.num_vertical_units());

        vector<int> iterIdxs(enc_mat.num_vertical_units());
        for (int i = 0; i < enc_mat.num_vertical_units(); i++) {
            iterIdxs[i] = i;
        }

        for_each(execution::par, begin(iterIdxs), end(iterIdxs), [&](int i) {
            cts[i] = sum_cols_core(eval.add_many(enc_mat.cts[i]), enc_mat.encoding_unit(), scalar);
        });

        return EncryptedRowVector(enc_mat.height(), enc_mat.encoding_unit(), cts);
    }

    // we just horizontally concatenate the matrices, then call sum_cols
    EncryptedRowVector LinearAlgebra::sum_cols_many(const vector<EncryptedMatrix> &enc_mats, double scalar) {
        vector<vector<CKKSCiphertext>> concat_cts(enc_mats[0].num_vertical_units());

        for (int i = 0; i < enc_mats[0].num_vertical_units(); i++) {
            for (int k = 0; k < enc_mats.size(); k++) {
                if (enc_mats[k].encoding_unit() != enc_mats[0].encoding_unit()) {
                    throw invalid_argument("sum_cols_many args must have the same encoding unit.");
                }
                if (enc_mats[k].height() != enc_mats[0].height()) {
                    throw invalid_argument("sum_cols_many args must have the same height");
                }

                for (int j = 0; j < enc_mats[k].cts[i].size(); j++) {
                    concat_cts[i].push_back(enc_mats[k].cts[i][j]);
                }
            }
        }

        size_t synthetic_width = concat_cts[0].size() * enc_mats[0].encoding_unit().encoding_width();

        return sum_cols(EncryptedMatrix(enc_mats[0].height(), synthetic_width, enc_mats[0].encoding_unit(), concat_cts),
                        scalar);
    }

    // we just vertically concatenate the matrices, then call sum_rows
    EncryptedColVector LinearAlgebra::sum_rows_many(const vector<EncryptedMatrix> &enc_mats) {
        vector<vector<CKKSCiphertext>> concat_cts;

        for (const auto &enc_mat : enc_mats) {
            if (enc_mat.encoding_unit() != enc_mats[0].encoding_unit()) {
                throw invalid_argument("sum_rows_many args must have the same encoding unit.");
            }
            if (enc_mat.width() != enc_mats[0].width()) {
                throw invalid_argument("sum_rows_many args must have the same width");
            }
            for (int i = 0; i < enc_mat.num_vertical_units(); i++) {
                concat_cts.push_back(enc_mat.cts[i]);
            }
        }

        size_t synthetic_height = concat_cts.size() * enc_mats[0].encoding_unit().encoding_height();

        return sum_rows(
            EncryptedMatrix(synthetic_height, enc_mats[0].width(), enc_mats[0].encoding_unit(), concat_cts));
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
    CKKSCiphertext LinearAlgebra::sum_rows_core(const EncryptedMatrix &enc_mat, int j) {
        vector<CKKSCiphertext> col_prods(enc_mat.num_vertical_units());
        // extract the j^th column of encoding units
        for (int i = 0; i < enc_mat.num_vertical_units(); i++) {
            col_prods[i] = enc_mat.cts[i][j];
        }

        CKKSCiphertext output = eval.add_many(col_prods);
        rot(output, enc_mat.encoding_unit().encoding_height(), enc_mat.encoding_unit().encoding_width(), true);
        return output;
    }

    // To sum the rows of a matrix, first sum all of the units in each column,
    // then call sum_rows_core on the result.
    // Repeat for each encoding unit column.
    EncryptedColVector LinearAlgebra::sum_rows(const EncryptedMatrix &enc_mat) {
        if(enc_mat.needs_relin()) {
            throw invalid_argument("Input to sum_rows must be a linear ciphertext");
        }
        vector<CKKSCiphertext> cts(enc_mat.num_horizontal_units());

        vector<int> iterIdxs(enc_mat.num_horizontal_units());
        for (int i = 0; i < enc_mat.num_horizontal_units(); i++) {
            iterIdxs[i] = i;
        }

        for_each(execution::par, begin(iterIdxs), end(iterIdxs),
                      [&](int j) { cts[j] = sum_rows_core(enc_mat, j);
        });

        return EncryptedColVector(enc_mat.width(), enc_mat.encoding_unit(), cts);
    }
}  // namespace hit
