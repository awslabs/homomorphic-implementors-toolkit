// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "linearalgebra.h"
#include "common.h"
#include <algorithm>
#include <execution>

using namespace std;

namespace hit {

    // TODO: ensure encoding unit matches number of slots

    EncodingUnit::EncodingUnit(int encoding_height, int encoding_width)
        : encoding_height(encoding_height), encoding_width(encoding_width) {
        if(!isPow2(encoding_height) || !isPow2(encoding_width)) {
            throw invalid_argument("Encoding unit dimensions must be a power of two.");
        }
    }

    bool operator== ( const EncodingUnit & lhs, const EncodingUnit & rhs )
    {
       return lhs.encoding_width == rhs.encoding_width && lhs.encoding_height == rhs.encoding_height;
    }

    bool operator!= ( const EncodingUnit & lhs, const EncodingUnit & rhs )
    {
       return lhs.encoding_width != rhs.encoding_width || lhs.encoding_height != rhs.encoding_height;
    }

    EncryptedMatrix::EncryptedMatrix(int height, int width, const EncodingUnit &unit, vector<vector<CKKSCiphertext>> &cts)
        : height(height), width(width), unit(unit), cts(cts) {
        if(cts.empty() || num_vertical_units() != cts.size() || cts[0].empty() || num_horizontal_units() != cts[0].size()) {
            throw invalid_argument("Invalid cts to EncryptedMatrix.");
        }
    }

    int EncryptedMatrix::num_vertical_units() const {
        return ceil((double)height / (double)unit.encoding_height);
    }

    int EncryptedMatrix::num_horizontal_units() const {
        return ceil((double)width / (double)unit.encoding_width);
    }

    EncryptedMatrix LinearAlgebra::encrypt_matrix(const Matrix &mat, const EncodingUnit &unit, int level) {
        vector<vector<Matrix>> mat_pieces = encode_matrix(mat, unit);

        vector<vector<CKKSCiphertext>> mat_cts;
        for(int i = 0; i < mat_pieces.size(); i++) {
            vector<CKKSCiphertext> row_cts;
            for(int j = 0; j < mat_pieces[0].size(); j++) {
                row_cts.push_back(inst.encrypt(mat_pieces[i][j].data(), level));
            }
            mat_cts.push_back(row_cts);
        }
        return EncryptedMatrix(mat.size1(), mat.size2(), unit, mat_cts);
    }

    Matrix LinearAlgebra::decrypt(const EncryptedMatrix &mat) const {
        vector<vector<Matrix>> mat_pieces;
        for(int i = 0; i < mat.cts.size(); i++) {
            vector<Matrix> row_pieces;
            for(int j = 0; j < mat.cts[0].size(); j++) {
                row_pieces.push_back(Matrix(mat.unit.encoding_height, mat.unit.encoding_width, inst.decrypt(mat.cts[i][j])));
            }
            mat_pieces.push_back(row_pieces);
        }
        return decode_matrix(mat_pieces, mat.height, mat.width);
    }

    EncryptedRowVector::EncryptedRowVector(int width, const EncodingUnit &unit, std::vector<CKKSCiphertext> &cts)
        : width(width), unit(unit), cts(cts) {
        if(cts.empty() || num_units() != cts.size()) {
            throw invalid_argument("Invalid cts to EncryptedRowVector.");
        }
    }

    int EncryptedRowVector::num_units() const {
        return ceil((double)width / unit.encoding_height);
    }

    EncryptedColVector::EncryptedColVector(int height, const EncodingUnit &unit, std::vector<CKKSCiphertext> &cts)
        : height(height), unit(unit), cts(cts) {
        if(cts.empty() || num_units() != cts.size()) {
            throw invalid_argument("Invalid cts to EncryptedColVector.");
        }
    }

    int EncryptedColVector::num_units() const {
        return ceil((double)height / unit.encoding_width);
    }

    LinearAlgebra::LinearAlgebra(CKKSInstance &inst)
        : inst(inst), eval(*(inst.evaluator)) {
    }

    EncryptedMatrix LinearAlgebra::add(const EncryptedMatrix &mat1, const EncryptedMatrix &mat2) {
        EncryptedMatrix temp = mat1;
        add_inplace(temp, mat2);
        return temp;
    }

    void LinearAlgebra::add_inplace(EncryptedMatrix &mat1, const EncryptedMatrix &mat2) {
        if (mat1.height != mat2.height || mat1.width != mat2.width || mat1.unit != mat2.unit) {
            throw invalid_argument("Arguments to LinearAlgebra::add_inplace do not have the same dimensions.");
        }
        for(int i = 0; i < mat1.cts.size(); i++) {
            for(int j = 0; j < mat1.cts[0].size(); j++) {
                eval.add_inplace(mat1.cts[i][j], mat2.cts[i][j]);
            }
        }
    }

    EncryptedMatrix LinearAlgebra::add(const vector<EncryptedMatrix> &mats) {
        if(mats.empty()) {
            throw invalid_argument("Vector of matrices to LinearAlgebra::add cannot be empty.");
        }
        EncryptedMatrix temp = mats[0];
        for(int i = 1; i < mats.size(); i++) {
            add_inplace(temp, mats[i]);
        }
        return temp;
    }

    EncryptedRowVector LinearAlgebra::add(const EncryptedRowVector &vec1, const EncryptedRowVector &vec2) {
        EncryptedRowVector temp = vec1;
        add_inplace(temp, vec2);
        return temp;
    }

    void LinearAlgebra::add_inplace(EncryptedRowVector &vec1, const EncryptedRowVector &vec2) {
        if (vec1.width != vec2.width || vec1.unit != vec2.unit) {
            throw invalid_argument("Arguments to LinearAlgebra::add_inplace do not have the same dimensions.");
        }
        for(int i = 0; i < vec1.cts.size(); i++) {
            eval.add_inplace(vec1.cts[i], vec2.cts[i]);
        }
    }

    EncryptedColVector LinearAlgebra::add(const EncryptedColVector &vec1, const EncryptedColVector &vec2) {
        EncryptedColVector temp = vec1;
        add_inplace(temp, vec2);
        return temp;
    }

    void LinearAlgebra::add_inplace(EncryptedColVector &vec1, const EncryptedColVector &vec2) {
        if (vec1.height != vec2.height || vec1.unit != vec2.unit) {
            throw invalid_argument("Arguments to LinearAlgebra::add_inplace do not have the same dimensions.");
        }
        vector<CKKSCiphertext> cts;
        for(int i = 0; i < vec1.cts.size(); i++) {
            eval.add_inplace(vec1.cts[i], vec2.cts[i]);
        }
    }

    EncryptedMatrix LinearAlgebra::add(const EncryptedMatrix &mat1, const Matrix &mat2) {
        EncryptedMatrix temp = mat1;
        add_inplace(temp, mat2);
        return temp;
    }

    void LinearAlgebra::add_inplace(EncryptedMatrix &mat1, const Matrix &mat2) {
        if (mat1.height != mat2.size1() || mat1.width != mat2.size2()) {
            throw invalid_argument("Arguments to LinearAlgebra::add_inplace do not have the same dimensions.");
        }
        vector<vector<Matrix>> encoded_matrix = encode_matrix(mat2, mat1.unit);

        for(int i = 0; i < mat1.cts.size(); i++) {
            vector<CKKSCiphertext> row;
            for(int j = 0; j < mat1.cts[0].size(); j++) {
                eval.add_plain_inplace(mat1.cts[i][j], encoded_matrix[i][j].data());
            }
        }
    }

    EncryptedRowVector LinearAlgebra::add(const EncryptedRowVector &vec1, const Vector &vec2) {
        EncryptedRowVector temp = vec1;
        add_inplace(temp, vec2);
        return temp;
    }

    void LinearAlgebra::add_inplace(EncryptedRowVector &vec1, const Vector &vec2) {
        if (vec1.width != vec2.size()) {
            throw invalid_argument("Arguments to LinearAlgebra::add_inplace do not have the same dimensions.");
        }
        vector<Matrix> encoded_vector = encodeRowVector(vec2, vec1.unit);

        for(int i = 0; i < vec1.cts.size(); i++) {
            eval.add_plain_inplace(vec1.cts[i], encoded_vector[i].data());
        }
    }

    EncryptedColVector LinearAlgebra::add(const EncryptedColVector &vec1, const Vector &vec2) {
        EncryptedColVector temp = vec1;
        add_inplace(temp, vec2);
        return temp;
    }

    void LinearAlgebra::add_inplace(EncryptedColVector &vec1, const Vector &vec2) {
        if (vec1.height != vec2.size()) {
            throw invalid_argument("Arguments to LinearAlgebra::add_inplace do not have the same dimensions.");
        }
        vector<Matrix> encoded_vector = encodeColVector(vec2, vec1.unit);

        for(int i = 0; i < vec1.cts.size(); i++) {
            eval.add_plain_inplace(vec1.cts[i], encoded_vector[i].data());
        }
    }

    EncryptedMatrix LinearAlgebra::add(const EncryptedMatrix &mat, double c) {
        EncryptedMatrix temp = mat;
        add_inplace(temp, c);
        return temp;
    }

    void LinearAlgebra::add_inplace(EncryptedMatrix &mat, double c) {
        for(int i = 0; i < mat.cts.size(); i++) {
            for(int j = 0; j < mat.cts[0].size(); j++) {
                eval.add_plain_inplace(mat.cts[i][j], c);
            }
        }
    }

    EncryptedRowVector LinearAlgebra::add(const EncryptedRowVector &vec, double c) {
        EncryptedRowVector temp = vec;
        add_inplace(temp, c);
        return temp;
    }

    void LinearAlgebra::add_inplace(EncryptedRowVector &vec, double c) {
        for(int i = 0; i < vec.cts.size(); i++) {
            eval.add_plain_inplace(vec.cts[i], c);
        }
    }

    EncryptedColVector LinearAlgebra::add(const EncryptedColVector &vec, double c) {
        EncryptedColVector temp = vec;
        add_inplace(temp, c);
        return temp;
    }

    void LinearAlgebra::add_inplace(EncryptedColVector &vec, double c) {
        for(int i = 0; i < vec.cts.size(); i++) {
            eval.add_plain_inplace(vec.cts[i], c);
        }
    }

    EncryptedMatrix LinearAlgebra::multiply(const EncryptedMatrix &mat, double c) {
        EncryptedMatrix temp = mat;
        multiply_inplace(temp, c);
        return temp;
    }

    void LinearAlgebra::multiply_inplace(EncryptedMatrix &mat, double c) {
        for(int i = 0; i < mat.cts.size(); i++) {
            for(int j = 0; j < mat.cts[0].size(); i++) {
                eval.add_plain_inplace(mat.cts[i][j], c);
            }
        }
    }

    EncryptedRowVector LinearAlgebra::multiply(const EncryptedRowVector &vec, double c) {
        EncryptedRowVector temp = vec;
        multiply_inplace(temp, c);
        return temp;
    }

    void LinearAlgebra::multiply_inplace(EncryptedRowVector &vec, double c) {
        for(int i = 0; i < vec.cts.size(); i++) {
            eval.add_plain_inplace(vec.cts[i], c);
        }
    }

    EncryptedColVector LinearAlgebra::multiply(const EncryptedColVector &vec, double c) {
        EncryptedColVector temp = vec;
        multiply_inplace(temp, c);
        return temp;
    }

    void LinearAlgebra::multiply_inplace(EncryptedColVector &vec, double c) {
        for(int i = 0; i < vec.cts.size(); i++) {
            eval.add_plain_inplace(vec.cts[i], c);
        }
    }

    CKKSCiphertext LinearAlgebra::matrix_rowvec_mul_loop(const EncryptedMatrix &mat, const EncryptedRowVector &vec, int j) {
        vector<CKKSCiphertext> col_prods(mat.num_vertical_units());
        for(int i = 0; i < mat.num_vertical_units(); i++) {
            col_prods[i] = eval.multiply(mat.cts[i][j], vec.cts[i]);
            eval.relinearize_inplace(col_prods[i]);
            eval.rescale_to_next_inplace(col_prods[i]);
        }
        return sumRows(eval.add_many(col_prods), mat.unit);
    }

    EncryptedColVector LinearAlgebra::multiply(const EncryptedRowVector &vec, const EncryptedMatrix &mat) {
        if(mat.height != vec.width || mat.unit != vec.unit) {
            throw invalid_argument("Dimension mismatch in LinearAlgebra::multiply.");
        }

        vector<CKKSCiphertext> cts(mat.num_horizontal_units());

        vector<int> iterIdxs;
        for(int i = 0; i < mat.num_horizontal_units(); i++) {
            iterIdxs.push_back(i);
        }

        if(eval.evalPolicy == launch::deferred) {
            std::for_each(execution::seq, begin(iterIdxs), end(iterIdxs), [&](int j) {
                cts[j] = matrix_rowvec_mul_loop(mat, vec, j);
            });
        }
        else {
            std::for_each(execution::par, begin(iterIdxs), end(iterIdxs), [&](int j) {
                cts[j] = matrix_rowvec_mul_loop(mat, vec, j);
            });
        }

        return EncryptedColVector(mat.width, mat.unit, cts);
    }

    CKKSCiphertext LinearAlgebra::matrix_colvec_mul_loop(const EncryptedMatrix &mat, const EncryptedColVector &vec, double c, int i) {
        vector<CKKSCiphertext> row_prods(mat.num_horizontal_units());
        for(int j = 0; j < mat.num_horizontal_units(); j++) {
            row_prods[j] = eval.multiply(mat.cts[i][j], vec.cts[j]);
            eval.relinearize_inplace(row_prods[j]);
            eval.rescale_to_next_inplace(row_prods[j]);
        }
        return sumCols(eval.add_many(row_prods), mat.unit, c);
    }

    EncryptedRowVector LinearAlgebra::multiply(const EncryptedMatrix &mat, const EncryptedColVector &vec, double c) {
        if(mat.width != vec.height || mat.unit != vec.unit) {
            throw invalid_argument("Dimension mismatch in LinearAlgebra::multiply.");
        }

        vector<CKKSCiphertext> cts(mat.num_vertical_units());

        vector<int> iterIdxs;
        for(int i = 0; i < mat.num_vertical_units(); i++) {
            iterIdxs.push_back(i);
        }

        if(eval.evalPolicy == launch::deferred) {
            std::for_each(execution::seq, begin(iterIdxs), end(iterIdxs), [&](int i) {
                cts[i] = matrix_colvec_mul_loop(mat, vec, c, i);
            });
        }
        else {
            std::for_each(execution::par, begin(iterIdxs), end(iterIdxs), [&](int i) {
                cts[i] = matrix_colvec_mul_loop(mat, vec, c, i);
            });
        }

        return EncryptedRowVector(mat.height, mat.unit, cts);
    }

    /* Computes (the encoding of) the k^th row of A, given A^T */
    EncryptedRowVector LinearAlgebra::extractRow(const EncryptedMatrix &aTrans, int row) {

        int num_slots = aTrans.unit.encoding_width*aTrans.unit.encoding_height;

        // create a mask for the k^th column of A^T, which is the k^th row of A
        vector<double> col_mask(num_slots);

        // compute which unit column the desired row is in
        int unit_col = row / aTrans.unit.encoding_width;
        // col_in_unit is the column within the encoding unit that contains the masked column
        int col_in_unit = row % aTrans.unit.encoding_width;

        for (size_t i = 0; i < num_slots; i++) {
            if (i % aTrans.unit.encoding_width == col_in_unit) {
                col_mask[i] = 1;
            }
            else {
                col_mask[i] = 0;
            }
        }

        vector<CKKSCiphertext> isolated_col_cts(aTrans.num_vertical_units());
        for(int i = 0; i < aTrans.num_vertical_units(); i++) {
            isolated_col_cts[i] = eval.multiply_plain(aTrans.cts[i][unit_col], col_mask);
            eval.rescale_to_next_inplace(isolated_col_cts[i]);
            // we now have isolated the k^th column of A^T. To get an encoding of the k^th row of A
            // we need to replicate this column across all columns of the encoding unit

            // first step is to shift the column to the left
            if(col_in_unit != 0) {
                eval.rotate_left_inplace(isolated_col_cts[i], col_in_unit);
            }

            // now replicate this column to all other columns of the unit
            rot(isolated_col_cts[i], aTrans.unit.encoding_width, 1, false);
        }
        return EncryptedRowVector(aTrans.height, aTrans.unit, isolated_col_cts);
    }

    /* Computes the k^th row of c*A*B^T given A^T and B^T, but NOT encoded as a vector.
     * First, mask out the k^th column of A^T, which is the k^th row of A.
     * The goal is to replicate this column to get the encoding of the k^th row of A (as columns)
     */
    vector<CKKSCiphertext> LinearAlgebra::matrix_matrix_mul_loop(const EncryptedMatrix &aTrans, const EncryptedMatrix &bTrans, const double c, int k) {

        EncryptedRowVector kth_row_A = extractRow(aTrans, k);

        EncryptedColVector kth_row_A_times_BT = multiply(kth_row_A, bTrans);

        // kth_row_A_times_BT is a column vector encoded as rows.
        // we need to mask out the desired row (but NOT replicate it; we will add it to the other rows later)

        int num_slots = aTrans.unit.encoding_width*aTrans.unit.encoding_height;

        // Currently, each row of kth_row_A_times_BT is identical. We want to mask out one
        // so that we can add it to another row later to get our matrix product.
        // Create a mask for the k^th row of kth_row_A_times_BT.
        // This mask is scaled by c so that we get a constant multiplication for free.
        vector<double> row_mask(num_slots);
        // row_in_unit is the row within the encoding unit that should contain the masked row
        int row_in_unit = k % aTrans.unit.encoding_height;

        for(int i = 0; i < aTrans.unit.encoding_height; i++) {
            for(int j = 0; j < aTrans.unit.encoding_width; j++) {
                if(i == row_in_unit) {
                    row_mask[i*aTrans.unit.encoding_width+j] = c;
                }
                else {
                    row_mask[i*aTrans.unit.encoding_width+j] = 0;
                }
            }
        }

        // iterate over all the (horizontally adjacent) units of this column vector to mask out the kth row
        for(int i = 0; i < kth_row_A_times_BT.cts.size(); i++) {
            eval.multiply_plain_inplace(kth_row_A_times_BT.cts[i], row_mask);
            eval.rescale_to_next_inplace(kth_row_A_times_BT.cts[i]);
        }

        return kth_row_A_times_BT.cts;
    }

    EncryptedMatrix LinearAlgebra::multiply(const EncryptedMatrix &aTrans, const EncryptedMatrix &bTrans, double c) {
        if (aTrans.height != bTrans.height || aTrans.width != bTrans.width || aTrans.unit != bTrans.unit) {
            throw invalid_argument("Arguments to LinearAlgebra::add_inplace do not have the same dimensions.");
        }

        // we will iterate over all columns of A^T (rows of A)
        // and compute the k^th row of A times B^T
        // then combine the results for each row to get the matrix product
        vector<vector<CKKSCiphertext>> row_results(aTrans.height);

        vector<int> iterIdxs;
        for(int i = 0; i < aTrans.height; i++) {
            iterIdxs.push_back(i);
        }

        if(eval.evalPolicy == launch::deferred) {
            std::for_each(execution::seq, begin(iterIdxs), end(iterIdxs), [&](int k) {
                row_results[k] = matrix_matrix_mul_loop(aTrans, bTrans, c, k);
            });
        }
        else {
            std::for_each(execution::par, begin(iterIdxs), end(iterIdxs), [&](int k) {
                row_results[k] = matrix_matrix_mul_loop(aTrans, bTrans, c, k);
            });
        }

        vector<vector<CKKSCiphertext>> matrix_cts;

        for(int i = 0; i < aTrans.num_vertical_units(); i++) {
            vector<CKKSCiphertext> unit_row_i_cts = row_results[i*aTrans.unit.encoding_height];
            for(int j = 1; j < aTrans.unit.encoding_height; j++) {
                for(int k = 0; k < row_results[0].size(); k++) {
                    eval.add_inplace(unit_row_i_cts[j], row_results[j][k]);
                }
            }
            matrix_cts.push_back(unit_row_i_cts);
        }

        return EncryptedMatrix(aTrans.width, bTrans.width, aTrans.unit, matrix_cts);
    }

    /* Generic helper for summing or replicating the rows or columns of an encoded matrix
     *
     * To sum columns, set `max` to the width of the matrix (must be a power of two), `stride` to 1, and rotateLeft=true
     * To sum rows, set `max` to the height of the matrix (must be a power of two), `stride` to the matrix width, and rotateLeft=true
     * To replicate columns, set `max` to the width of the matrix (must be a power of two), `stride` to 1, and rotateLeft=false
     */
    void LinearAlgebra::rot(CKKSCiphertext &t1, int max, int stride, bool rotateLeft) {
        // serial implementation
        for (int i = 1; i < max; i <<= 1) {
            CKKSCiphertext t2;
            if(rotateLeft) {
                t2 = eval.rotate_left(t1, i*stride);
            }
            else {
                t2 = eval.rotate_right(t1, i*stride);
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
    CKKSCiphertext LinearAlgebra::sumCols(const CKKSCiphertext &ct, const EncodingUnit &unit, double c) {
      // if(!isPow2(ct.width)) {
      //   stringstream buffer;
      //   buffer << "sumCols called with a non-power-2 width: " << ct.width;
      //   throw invalid_argument(buffer.str());
      // }
      // if(ct.encoding != COL_MAT) {
      //   throw invalid_argument("sumCols argument must be a column matrix");
      // }
      CKKSCiphertext output = ct;

      // sum the columns, placing the result in the left-most column
      rot(output, unit.encoding_width, 1, true);

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
      for(int i = 0; i < unit.encoding_height; i++) {
        D.push_back(c);
        for(int j = 1; j < unit.encoding_width; j++) {
            D.push_back(0);
        }
      }

      // mask out the first column
      output = eval.multiply_plain(output, D);
      eval.rescale_to_next_inplace(output);

      // now the first column of the matrix holds the column sum; but we want to repeat the first column in each column.
      rot(output, unit.encoding_width, 1, false);

      return output;
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
    CKKSCiphertext LinearAlgebra::sumRows(const CKKSCiphertext &ct, const EncodingUnit &unit) {
      CKKSCiphertext output = ct;
      rot(output, unit.encoding_height, unit.encoding_width, true);
      return output;
    }

    vector<vector<Matrix>> LinearAlgebra::encode_matrix(const Matrix &mat, const EncodingUnit &unit) {
        int height = mat.size1();
        int width = mat.size2();

        int num_vertical_units = ceil((double)height / (double)unit.encoding_height);
        int num_horizontal_units = ceil((double)width / (double)unit.encoding_width);

        vector<vector<Matrix>> cts;
        for(int i = 0; i < num_vertical_units; i++) {
            vector<Matrix> row_units;
            for(int j = 0; j < num_horizontal_units; j++) {
                vector<double> unit_ij;
                for(int k = 0; k < unit.encoding_height; k++) {
                    for(int l = 0; l < unit.encoding_width; l++) {
                        int row = unit.encoding_height*i + k;
                        int col = unit.encoding_width*j + l;
                        if(row > height || col > width) {
                            unit_ij.push_back(0);
                        }
                        else {
                            unit_ij.push_back(mat.data()[row*width+col]);
                        }
                    }
                }
                row_units.push_back(Matrix(unit.encoding_height, unit.encoding_width, unit_ij));
            }
            cts.push_back(row_units);
        }
        return cts;
    }

    Matrix decode_matrix(const vector<vector<Matrix>> &mats, int trim_height, int trim_width) {
        if(mats.empty() || mats[0].empty()) {
            throw invalid_argument("decode_matrix: input cannot be empty");
        }

        int height = mats[0][0].size1();
        int width = mats[0][0].size2();

        if(trim_height < 0) {
            trim_height = mats.size()*height;
        }
        if(trim_width < 0) {
            trim_width = mats[0].size()*width;
        }

        vector<double> linear_matrix;

        for(int i = 0; i < mats.size(); i++) {
            if(mats[i].size() != mats[0].size()) {
                throw invalid_argument("decode_matrix: all rows must have the same length");
            }
            // for each Matrix row
            for(int j = 0; j < height && i*height+j < trim_height; j++) {
                for(int k = 0; k < mats[0].size(); k++) {
                    if(mats[i][k].size1() != height || mats[i][k].size2() != width) {
                        throw invalid_argument("decode_matrix: all matrices must have the same dimension");
                    }
                    for(int l = 0; l < width && k*width+l < trim_width; l++) {
                        linear_matrix.push_back(mats[i][k].data()[j*width+l]);
                    }
                }
            }
        }
        return Matrix(trim_height, trim_width, linear_matrix);
    }

    vector<Matrix> LinearAlgebra::encodeRowVector(const Vector &vec, const EncodingUnit &unit) {
        int width = vec.size();

        // We encode row vectors as *columns*, which is why the row vector's width is used to
        // calculated the number of vertical units.
        vector<Matrix> cts;
        int num_units = ceil((double)vec.size() / unit.encoding_height);
        for(int i = 0; i < num_units; i++) {
            vector<double> unit_i;
            for(int k = 0; k < unit.encoding_height; k++) {
                for(int l = 0; l < unit.encoding_width; l++) {
                    int col = unit.encoding_height*i + k;
                    if(col > width) {
                        unit_i.push_back(0);
                    }
                    else {
                        unit_i.push_back(vec[col]);
                    }
                }
            }
            cts.push_back(Matrix(unit.encoding_height, unit.encoding_width, unit_i));
        }
        return cts;
    }

    vector<Matrix> LinearAlgebra::encodeColVector(const Vector &vec, const EncodingUnit &unit) {
        int height = vec.size();

        // We encode column vectors as *rows*, which is why the row vector's width is used to
        // calculated the number of vertical units.
        vector<Matrix> cts;
        int num_units = ceil((double)vec.size() / unit.encoding_width);
        for(int i = 0; i < num_units; i++) {
            vector<double> unit_i;
            for(int k = 0; k < unit.encoding_height; k++) {
                for(int l = 0; l < unit.encoding_width; l++) {
                    int row = i*unit.encoding_width+l;
                    if(row > height) {
                        unit_i.push_back(0);
                    }
                    else {
                        unit_i.push_back(vec[row]);
                    }
                }
            }
            cts.push_back(Matrix(unit.encoding_height, unit.encoding_width, unit_i));
        }
        return cts;
    }


/*
    // Extract the side-by-side plaintext from the ciphertext. Note that there is no decryption happening!
    // This returns the "debug" plaintext.
    Matrix ctPlaintextToMatrix(const CKKSCiphertext &ct) {
        return Matrix(ct.height, ct.width, ct.getPlaintext());
    }

    // Extract the encrypted plaintext from the ciphertext. This actually decrypts and returns the output.
    Matrix ctDecryptedToMatrix(CKKSInstance &inst, const CKKSCiphertext &ct) {
        return Matrix(ct.height, ct.width, inst.decrypt(ct));
    }

    // Extract the debug plaintext from each ciphertext and concatenate the results side-by-side.
    Matrix ctPlaintextToMatrix(const vector<CKKSCiphertext> &cts) {
        vector<Matrix> mats;
        mats.reserve(cts.size());
        for (const auto &ct : cts) {
            mats.push_back(ctPlaintextToMatrix(ct));
        }
        return matrixRowConcat(mats);
    }

    Vector ctPlaintextToVector(const vector<CKKSCiphertext> &cts) {
        vector<double> stdvec;
        for (const auto &ct : cts) {
            vector<double> v = ct.getPlaintext();
            stdvec.insert(stdvec.end(), v.begin(), v.end());
        }
        return fromStdVector(stdvec);
    }

    // Decrypt each ciphertext and concatenate the results side-by-side.
    Matrix ctDecryptedToMatrix(CKKSInstance &inst, const vector<CKKSCiphertext> &cts) {
        vector<Matrix> mats;
        mats.reserve(cts.size());
        for (const auto &ct : cts) {
            mats.push_back(ctDecryptedToMatrix(inst, ct));
        }

        return matrixRowConcat(mats);
    }

    Vector ctDecryptedToVector(CKKSInstance &inst, const vector<CKKSCiphertext> &cts) {
        vector<double> stdvec;
        for (const auto &ct : cts) {
            vector<double> v = inst.decrypt(ct);
            stdvec.insert(stdvec.end(), v.begin(), v.end());
        }
        return fromStdVector(stdvec);
    }
*/
}
