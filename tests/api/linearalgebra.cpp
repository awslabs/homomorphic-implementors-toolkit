// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/matrix.h"

#include <iostream>
#include <stdexcept>

#include "gtest/gtest.h"

using namespace std;
using namespace hit;

// A helper function to createMatrix with dimensions (height x width), and set value of each cell.
Matrix randomMatrix(int mat_height, int mat_width, double maxNorm) {
    vector<double> vals = randomVector(mat_height*mat_width, maxNorm);
    return Matrix(mat_height, mat_width, vals);
}

EncryptedMatrix ncryptedMatrix(Matrix mat, EncodingUnit unit) {
    vector<vector<Matrix>> encoded_mat = encodeMatrix(mat, unit);


}

// test whether num_vertical_units() computation is correct
Test(LinearAlgebraTest, add_matrix_matrix) {


    EncodingUnit unit(16, 32);
    int mat_height = 8;
    int mat_width = 8;

    Matrix mat1 = randomMatrix(mat_height, mat_width, 10);
    Matrix mat2 = randomMatrix(mat_height, mat_width, 10);
    EncryptedMatrix enc_mat1 =





}

TEST(MatrixTest, MatrixRowConcat_EmptyMatrix) {
    ASSERT_THROW(
        {
            vector<Matrix> matrix_vec;
            matrixRowConcat(matrix_vec);
        },
        invalid_argument);
}

TEST(MatrixTest, MatrixRowConcat_DiffMatrixHeight) {
    ASSERT_THROW(
        {
            vector<Matrix> matrix_vec;
            matrix_vec.push_back(createMatrix(1, 2));
            matrix_vec.push_back(createMatrix(2, 2));
            matrixRowConcat(matrix_vec);
        },
        invalid_argument);
}

TEST(MatrixTest, MatrixRowConcat) {
    vector<Matrix> matrix_vec;
    matrix_vec.push_back(createMatrix(2, 1, 0));
    matrix_vec.push_back(createMatrix(2, 2, 1));
    Matrix concat_matrix = matrixRowConcat(matrix_vec);
    ASSERT_EQ(concat_matrix.size1(), 2);
    ASSERT_EQ(concat_matrix.size2(), 3);
    vector<double> vector1 = {0, 1, 1, 0, 1, 1};
    ASSERT_TRUE(concat_matrix.data() == vector1);
}
