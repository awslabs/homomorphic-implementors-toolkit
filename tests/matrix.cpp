// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/matrix.h"

#include <iostream>
#include <stdexcept>

#include "gtest/gtest.h"

using namespace std;
using namespace hit;

// A helper function to create_matrix with dimensions (height x width), and set value of each cell.
Matrix create_matrix(const int height, const int width, const int value = 1) {
    vector<double> vector1(height * width, value);
    Matrix matrix1(height, width);
    matrix1.data() = vector1;
    return matrix1;
}

TEST(MatrixTest, matrix_row_concat_EmptyMatrix) {
    ASSERT_THROW(
        {
            vector<Matrix> matrix_vec;
            matrix_row_concat(matrix_vec);
        },
        invalid_argument);
}

TEST(MatrixTest, matrix_row_concat_DiffMatrixHeight) {
    ASSERT_THROW(
        {
            vector<Matrix> matrix_vec;
            matrix_vec.push_back(create_matrix(1, 2));
            matrix_vec.push_back(create_matrix(2, 2));
            matrix_row_concat(matrix_vec);
        },
        invalid_argument);
}

TEST(MatrixTest, matrix_row_concat) {
    vector<Matrix> matrix_vec;
    matrix_vec.push_back(create_matrix(2, 1, 0));
    matrix_vec.push_back(create_matrix(2, 2, 1));
    Matrix concat_matrix = matrix_row_concat(matrix_vec);
    ASSERT_EQ(concat_matrix.size1(), 2);
    ASSERT_EQ(concat_matrix.size2(), 3);
    vector<double> vector1 = {0, 1, 1, 0, 1, 1};
    ASSERT_TRUE(concat_matrix.data() == vector1);
}
