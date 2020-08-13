// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>
#include <stdexcept>

#include "gtest/gtest.h"

#include "matrix.h"

using namespace std;

// A helper function to createMatrix with dimensions (height x width), and set value of each cell.
Matrix createMatrix(const int height, const int width, const int value = 1) {
    vector<double> vector1(height * width, value);
    Matrix matrix1(height, width);
    matrix1.data() = vector1;
    return matrix1;
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
