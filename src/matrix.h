// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <boost/numeric/ublas/io.hpp>
#include <boost/numeric/ublas/matrix.hpp>
#include <boost/numeric/ublas/vector.hpp>

namespace ublas = boost::numeric::ublas;

typedef ublas::matrix<double, ublas::row_major, std::vector<double>> Matrix;  // NOLINT(modernize-use-using)
typedef ublas::vector<double, std::vector<double>> Vector;                    // NOLINT(modernize-use-using)

/* Encode a C++ vector representing a linear algebra row vector as
 * a matrix of width `width`, where each column is the input.
 */
Matrix rowVecToMatrix(const std::vector<double> &x, int width);

/* Encode a C++ vector representing a linear algebra column vector as
 * a matrix of height `height`, where each row is the input.
 */
Matrix colVecToMatrix(const std::vector<double> &x, int height);

/* Given a vector of matrices <A_0, A_1, ..., A_n>, each with the same height,
 * return a single matrix [ A_0 | A_1 | ... | A_n ] that concatenates
 * the matrices horizontally.
 */
Matrix matrixRowConcat(const std::vector<Matrix> &xs);

Matrix hadamard_prod(const Matrix &a, const Matrix &b);

Vector fromStdVector(const std::vector<double> &v);
