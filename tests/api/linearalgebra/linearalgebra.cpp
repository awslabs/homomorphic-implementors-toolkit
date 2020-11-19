// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/api/linearalgebra/linearalgebra.h"

#include <iostream>

#include "../../testutil.h"
#include "gtest/gtest.h"
#include "hit/api/ciphertext.h"
#include "hit/api/evaluator/homomorphic.h"
#include "hit/common.h"
#include "hit/sealutils.h"

using namespace std;
using namespace hit;

const int NUM_OF_SLOTS = 4096;
const int ZERO_MULTI_DEPTH = 0;
const int ONE_MULTI_DEPTH = 1;
const int TWO_MULTI_DEPTH = 2;
const int THREE_MULTI_DEPTH = 3;
const int LOG_SCALE = 45;
const double PI = 3.14;

void test_encrypt_matrix(LinearAlgebra &linear_algebra, int mat_height, int mat_width, EncodingUnit &unit) {
    Matrix plaintext = random_mat(mat_height, mat_width);
    EncryptedMatrix ciphertext = linear_algebra.encrypt_matrix(plaintext, unit);
    Matrix output = linear_algebra.decrypt(ciphertext);
    ASSERT_LT(relative_error(plaintext, output), MAX_NORM);
    ASSERT_FALSE(ciphertext.needs_relin());
    ASSERT_FALSE(ciphertext.needs_rescale());
}

TEST(LinearAlgebraTest, EncryptMatrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    test_encrypt_matrix(linear_algebra, 64, 64, unit1);
    test_encrypt_matrix(linear_algebra, 32, 32, unit1);
    test_encrypt_matrix(linear_algebra, 60, 64, unit1);
    test_encrypt_matrix(linear_algebra, 64, 60, unit1);
    test_encrypt_matrix(linear_algebra, 256, 64, unit1);
    test_encrypt_matrix(linear_algebra, 300, 64, unit1);
    test_encrypt_matrix(linear_algebra, 300, 60, unit1);
    test_encrypt_matrix(linear_algebra, 64, 256, unit1);
    test_encrypt_matrix(linear_algebra, 64, 300, unit1);
    test_encrypt_matrix(linear_algebra, 60, 300, unit1);
    test_encrypt_matrix(linear_algebra, 128, 256, unit1);
    test_encrypt_matrix(linear_algebra, 200, 200, unit1);
    test_encrypt_matrix(linear_algebra, 200, 201, unit1);

    int unit2_height = 16;  // a 16x256 encoding unit
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);
    test_encrypt_matrix(linear_algebra, 16, 256, unit2);
    test_encrypt_matrix(linear_algebra, 8, 128, unit2);
    test_encrypt_matrix(linear_algebra, 13, 256, unit2);
    test_encrypt_matrix(linear_algebra, 16, 247, unit2);
    test_encrypt_matrix(linear_algebra, 256, 256, unit2);
    test_encrypt_matrix(linear_algebra, 300, 256, unit2);
    test_encrypt_matrix(linear_algebra, 300, 247, unit2);
    test_encrypt_matrix(linear_algebra, 16, 512, unit2);
    test_encrypt_matrix(linear_algebra, 16, 300, unit2);
    test_encrypt_matrix(linear_algebra, 13, 300, unit2);
    test_encrypt_matrix(linear_algebra, 32, 512, unit2);
    test_encrypt_matrix(linear_algebra, 200, 500, unit2);
}

void test_encrypt_row_vector(LinearAlgebra &linear_algebra, int vec_width, EncodingUnit &unit) {
    Vector plaintext = random_vec(vec_width);
    EncryptedRowVector ciphertext = linear_algebra.encrypt_row_vector(plaintext, unit);
    Vector output = linear_algebra.decrypt(ciphertext);
    ASSERT_LT(relative_error(plaintext, output), MAX_NORM);
    ASSERT_FALSE(ciphertext.needs_relin());
    ASSERT_FALSE(ciphertext.needs_rescale());
}

TEST(LinearAlgebraTest, EncryptRowVector) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    test_encrypt_row_vector(linear_algebra, 64, unit1);
    test_encrypt_row_vector(linear_algebra, 32, unit1);
    test_encrypt_row_vector(linear_algebra, 128, unit1);
    test_encrypt_row_vector(linear_algebra, 61, unit1);
    test_encrypt_row_vector(linear_algebra, 89, unit1);

    int unit2_height = 16;  // a 16x256 encoding unit
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);
    test_encrypt_row_vector(linear_algebra, 16, unit2);
    test_encrypt_row_vector(linear_algebra, 8, unit2);
    test_encrypt_row_vector(linear_algebra, 10, unit2);
    test_encrypt_row_vector(linear_algebra, 32, unit2);
    test_encrypt_row_vector(linear_algebra, 77, unit2);
}

void test_encrypt_col_vector(LinearAlgebra &linear_algebra, int vec_height, EncodingUnit &unit) {
    Vector plaintext = random_vec(vec_height);
    EncryptedColVector ciphertext = linear_algebra.encrypt_col_vector(plaintext, unit);
    Vector output = linear_algebra.decrypt(ciphertext);
    ASSERT_LT(relative_error(plaintext, output), MAX_NORM);
    ASSERT_FALSE(ciphertext.needs_relin());
    ASSERT_FALSE(ciphertext.needs_rescale());
}

TEST(LinearAlgebraTest, EncryptColVector) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    test_encrypt_col_vector(linear_algebra, 64, unit1);
    test_encrypt_col_vector(linear_algebra, 32, unit1);
    test_encrypt_col_vector(linear_algebra, 128, unit1);
    test_encrypt_col_vector(linear_algebra, 61, unit1);
    test_encrypt_col_vector(linear_algebra, 89, unit1);

    int unit2_height = 16;  // a 16x256 encoding unit
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);
    test_encrypt_col_vector(linear_algebra, 256, unit2);
    test_encrypt_col_vector(linear_algebra, 128, unit2);
    test_encrypt_col_vector(linear_algebra, 153, unit2);
    test_encrypt_col_vector(linear_algebra, 512, unit2);
    test_encrypt_col_vector(linear_algebra, 519, unit2);
}

TEST(LinearAlgebraTest, AddMatrixMatrix_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    // a 128x32 encoding unit
    int unit2_height = 128;
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);

    Matrix mat1 = random_mat(200, 300);
    Matrix mat2 = random_mat(200, 301);
    Matrix mat3 = random_mat(201, 300);
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);
    EncryptedMatrix ciphertext2 = linear_algebra.encrypt_matrix(mat2, unit1);
    EncryptedMatrix ciphertext3 = linear_algebra.encrypt_matrix(mat3, unit1);
    EncryptedMatrix ciphertext4 = linear_algebra.encrypt_matrix(mat1, unit2);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because widths do not match.
        (linear_algebra.add_inplace(ciphertext1, ciphertext2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because heights do not match.
        (linear_algebra.add_inplace(ciphertext1, ciphertext3)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (linear_algebra.add_inplace(ciphertext1, ciphertext4)), invalid_argument);
}

TEST(LinearAlgebraTest, AddMatrixMatrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int height = 200;
    int width = 300;

    Matrix mat1 = random_mat(height, width);
    Matrix mat2 = random_mat(height, width);
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);
    EncryptedMatrix ciphertext2 = linear_algebra.encrypt_matrix(mat2, unit1);

    EncryptedMatrix ciphertext3 = linear_algebra.add(ciphertext1, ciphertext2);
    Matrix actual_result = linear_algebra.decrypt(ciphertext3);
    Matrix expected_result = mat1 + mat2;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, AddRowRow_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    // a 128x32 encoding unit
    int unit2_height = 128;
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);

    Vector vec1 = random_vec(200);
    Vector vec2 = random_vec(201);
    EncryptedRowVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);
    EncryptedRowVector ciphertext2 = linear_algebra.encrypt_row_vector(vec2, unit1);
    EncryptedRowVector ciphertext3 = linear_algebra.encrypt_row_vector(vec1, unit2);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because sizes do not match.
        (linear_algebra.add_inplace(ciphertext1, ciphertext2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (linear_algebra.add_inplace(ciphertext1, ciphertext3)), invalid_argument);
}

TEST(LinearAlgebraTest, AddRowRow) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    Vector vec2 = random_vec(width);
    EncryptedRowVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);
    EncryptedRowVector ciphertext2 = linear_algebra.encrypt_row_vector(vec2, unit1);

    EncryptedRowVector ciphertext3 = linear_algebra.add(ciphertext1, ciphertext2);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = vec1 + vec2;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, AddColCol_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    // a 128x32 encoding unit
    int unit2_height = 128;
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);

    Vector vec1 = random_vec(200);
    Vector vec2 = random_vec(201);
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_col_vector(vec1, unit1);
    EncryptedColVector ciphertext2 = linear_algebra.encrypt_col_vector(vec2, unit1);
    EncryptedColVector ciphertext3 = linear_algebra.encrypt_col_vector(vec1, unit2);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because sizes do not match.
        (linear_algebra.add_inplace(ciphertext1, ciphertext2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (linear_algebra.add_inplace(ciphertext1, ciphertext3)), invalid_argument);
}

TEST(LinearAlgebraTest, AddColCol) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    Vector vec2 = random_vec(width);
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_col_vector(vec1, unit1);
    EncryptedColVector ciphertext2 = linear_algebra.encrypt_col_vector(vec2, unit1);

    EncryptedColVector ciphertext3 = linear_algebra.add(ciphertext1, ciphertext2);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = vec1 + vec2;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, AddMatrixPlaintextMatrix_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    Matrix mat1 = random_mat(200, 300);
    Matrix mat2 = random_mat(200, 301);
    Matrix mat3 = random_mat(201, 300);
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because widths do not match.
        (linear_algebra.add_plain_inplace(ciphertext1, mat2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because heights do not match.
        (linear_algebra.add_plain_inplace(ciphertext1, mat3)), invalid_argument);
}

TEST(LinearAlgebraTest, AddMatrixPlaintextMatrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int height = 200;
    int width = 300;

    Matrix mat1 = random_mat(height, width);
    Matrix mat2 = random_mat(height, width);
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);

    EncryptedMatrix ciphertext3 = linear_algebra.add_plain(ciphertext1, mat2);
    Matrix actual_result = linear_algebra.decrypt(ciphertext3);
    Matrix expected_result = mat1 + mat2;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, AddRowPlaintextRow_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    Vector vec1 = random_vec(200);
    Vector vec2 = random_vec(201);
    EncryptedRowVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because sizes do not match.
        (linear_algebra.add_plain_inplace(ciphertext1, vec2)), invalid_argument);
}

TEST(LinearAlgebraTest, AddRowPlaintextRow) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    Vector vec2 = random_vec(width);
    EncryptedRowVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);

    EncryptedRowVector ciphertext3 = linear_algebra.add_plain(ciphertext1, vec2);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = vec1 + vec2;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, AddColPlaintextCol_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    Vector vec1 = random_vec(200);
    Vector vec2 = random_vec(201);
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_col_vector(vec1, unit1);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because sizes do not match.
        (linear_algebra.add_plain_inplace(ciphertext1, vec2)), invalid_argument);
}

TEST(LinearAlgebraTest, AddColPlaintextCol) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    Vector vec2 = random_vec(width);
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_col_vector(vec1, unit1);

    EncryptedColVector ciphertext3 = linear_algebra.add_plain(ciphertext1, vec2);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = vec1 + vec2;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, AddMatrixScalar) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int height = 200;
    int width = 300;

    Matrix mat1 = random_mat(height, width);
    double scalar = 3.14;
    Matrix mat2 = Matrix(height, width, vector<double>(height * width, scalar));
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);

    EncryptedMatrix ciphertext3 = linear_algebra.add_plain(ciphertext1, scalar);
    Matrix actual_result = linear_algebra.decrypt(ciphertext3);
    Matrix expected_result = mat1 + mat2;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, AddRowScalar) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    double scalar = 3.14;
    Vector vec2 = Vector(vector<double>(width, scalar));
    EncryptedRowVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);

    EncryptedRowVector ciphertext3 = linear_algebra.add_plain(ciphertext1, scalar);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = vec1 + vec2;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, AddColScalar) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int height = 300;

    Vector vec1 = random_vec(height);
    double scalar = 3.14;
    Vector vec2 = Vector(vector<double>(height, scalar));
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_col_vector(vec1, unit1);

    EncryptedColVector ciphertext3 = linear_algebra.add_plain(ciphertext1, scalar);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = vec1 + vec2;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, AddMultipleMatrix_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    // a 128x32 encoding unit
    int unit2_height = 128;
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);

    Matrix mat1 = random_mat(200, 300);
    Matrix mat2 = random_mat(200, 301);
    Matrix mat3 = random_mat(201, 300);
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);
    EncryptedMatrix ciphertext2 = linear_algebra.encrypt_matrix(mat2, unit1);
    EncryptedMatrix ciphertext3 = linear_algebra.encrypt_matrix(mat3, unit1);
    EncryptedMatrix ciphertext4 = linear_algebra.encrypt_matrix(mat1, unit2);

    vector<EncryptedMatrix> set1{ciphertext1, ciphertext2};
    vector<EncryptedMatrix> set2{ciphertext1, ciphertext3};
    vector<EncryptedMatrix> set3{ciphertext1, ciphertext4};

    ASSERT_THROW(
        // Expect invalid_argument is thrown because widths do not match.
        (linear_algebra.add_many(set1)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because heights do not match.
        (linear_algebra.add_many(set2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (linear_algebra.add_many(set3)), invalid_argument);
}

TEST(LinearAlgebraTest, AddMultipleMatrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int height = 200;
    int width = 300;

    vector<EncryptedMatrix> cts;
    Matrix matrix1 = random_mat(height, width);
    cts.emplace_back(linear_algebra.encrypt_matrix(matrix1, unit1));
    Matrix matrix2 = random_mat(height, width);
    cts.emplace_back(linear_algebra.encrypt_matrix(matrix2, unit1));
    Matrix matrix3 = random_mat(height, width);
    cts.emplace_back(linear_algebra.encrypt_matrix(matrix3, unit1));

    EncryptedMatrix ciphertext = linear_algebra.add_many(cts);
    Matrix actual_result = linear_algebra.decrypt(ciphertext);
    Matrix expected_result = matrix1 + matrix2 + matrix3;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext.needs_relin());
    ASSERT_FALSE(ciphertext.needs_rescale());
}

TEST(LinearAlgebraTest, AddMultipleRow_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    // a 128x32 encoding unit
    int unit2_height = 128;
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);

    Vector vec1 = random_vec(200);
    Vector vec2 = random_vec(201);
    EncryptedRowVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);
    EncryptedRowVector ciphertext2 = linear_algebra.encrypt_row_vector(vec2, unit1);
    EncryptedRowVector ciphertext3 = linear_algebra.encrypt_row_vector(vec1, unit2);

    vector<EncryptedRowVector> set1{ciphertext1, ciphertext2};
    vector<EncryptedRowVector> set2{ciphertext1, ciphertext3};

    ASSERT_THROW(
        // Expect invalid_argument is thrown because dimensions do not match.
        (linear_algebra.add_many(set1)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because units do not match.
        (linear_algebra.add_many(set2)), invalid_argument);
}

TEST(LinearAlgebraTest, AddMultipleRow) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    vector<EncryptedRowVector> cts;
    Vector vec1 = random_vec(width);
    cts.emplace_back(linear_algebra.encrypt_row_vector(vec1, unit1));
    Vector vec2 = random_vec(width);
    cts.emplace_back(linear_algebra.encrypt_row_vector(vec2, unit1));
    Vector vec3 = random_vec(width);
    cts.emplace_back(linear_algebra.encrypt_row_vector(vec3, unit1));

    EncryptedRowVector ciphertext = linear_algebra.add_many(cts);
    Vector actual_result = linear_algebra.decrypt(ciphertext);
    Vector expected_result = vec1 + vec2 + vec3;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext.needs_relin());
    ASSERT_FALSE(ciphertext.needs_rescale());
}

TEST(LinearAlgebraTest, AddMultipleCol_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    // a 128x32 encoding unit
    int unit2_height = 128;
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);

    Vector vec1 = random_vec(200);
    Vector vec2 = random_vec(201);
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_col_vector(vec1, unit1);
    EncryptedColVector ciphertext2 = linear_algebra.encrypt_col_vector(vec2, unit1);
    EncryptedColVector ciphertext3 = linear_algebra.encrypt_col_vector(vec1, unit2);

    vector<EncryptedColVector> set1{ciphertext1, ciphertext2};
    vector<EncryptedColVector> set2{ciphertext1, ciphertext3};

    ASSERT_THROW(
        // Expect invalid_argument is thrown because dimensions do not match.
        (linear_algebra.add_many(set1)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because units do not match.
        (linear_algebra.add_many(set2)), invalid_argument);
}

TEST(LinearAlgebraTest, AddMultipleCol) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    vector<EncryptedColVector> cts;
    Vector vec1 = random_vec(width);
    cts.emplace_back(linear_algebra.encrypt_col_vector(vec1, unit1));
    Vector vec2 = random_vec(width);
    cts.emplace_back(linear_algebra.encrypt_col_vector(vec2, unit1));
    Vector vec3 = random_vec(width);
    cts.emplace_back(linear_algebra.encrypt_col_vector(vec3, unit1));

    EncryptedColVector ciphertext = linear_algebra.add_many(cts);
    Vector actual_result = linear_algebra.decrypt(ciphertext);
    Vector expected_result = vec1 + vec2 + vec3;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext.needs_relin());
    ASSERT_FALSE(ciphertext.needs_rescale());
}

TEST(LinearAlgebraTest, SubMatrixMatrix_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    // a 128x32 encoding unit
    int unit2_height = 128;
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);

    Matrix mat1 = random_mat(200, 300);
    Matrix mat2 = random_mat(200, 301);
    Matrix mat3 = random_mat(201, 300);
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);
    EncryptedMatrix ciphertext2 = linear_algebra.encrypt_matrix(mat2, unit1);
    EncryptedMatrix ciphertext3 = linear_algebra.encrypt_matrix(mat3, unit1);
    EncryptedMatrix ciphertext4 = linear_algebra.encrypt_matrix(mat1, unit2);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because widths do not match.
        (linear_algebra.sub_inplace(ciphertext1, ciphertext2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because heights do not match.
        (linear_algebra.sub_inplace(ciphertext1, ciphertext3)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (linear_algebra.sub_inplace(ciphertext1, ciphertext4)), invalid_argument);
}

TEST(LinearAlgebraTest, SubMatrixMatrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int height = 200;
    int width = 300;

    Matrix mat1 = random_mat(height, width);
    Matrix mat2 = random_mat(height, width);
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);
    EncryptedMatrix ciphertext2 = linear_algebra.encrypt_matrix(mat2, unit1);

    EncryptedMatrix ciphertext3 = linear_algebra.sub(ciphertext1, ciphertext2);
    Matrix actual_result = linear_algebra.decrypt(ciphertext3);
    Matrix expected_result = mat1 - mat2;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, SubRowRow_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    // a 128x32 encoding unit
    int unit2_height = 128;
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);

    Vector vec1 = random_vec(200);
    Vector vec2 = random_vec(201);
    EncryptedRowVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);
    EncryptedRowVector ciphertext2 = linear_algebra.encrypt_row_vector(vec2, unit1);
    EncryptedRowVector ciphertext3 = linear_algebra.encrypt_row_vector(vec1, unit2);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because sizes do not match.
        (linear_algebra.sub_inplace(ciphertext1, ciphertext2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (linear_algebra.sub_inplace(ciphertext1, ciphertext3)), invalid_argument);
}

TEST(LinearAlgebraTest, SubRowRow) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    Vector vec2 = random_vec(width);
    EncryptedRowVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);
    EncryptedRowVector ciphertext2 = linear_algebra.encrypt_row_vector(vec2, unit1);

    EncryptedRowVector ciphertext3 = linear_algebra.sub(ciphertext1, ciphertext2);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = vec1 - vec2;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, SubColCol_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    // a 128x32 encoding unit
    int unit2_height = 128;
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);

    Vector vec1 = random_vec(200);
    Vector vec2 = random_vec(201);
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_col_vector(vec1, unit1);
    EncryptedColVector ciphertext2 = linear_algebra.encrypt_col_vector(vec2, unit1);
    EncryptedColVector ciphertext3 = linear_algebra.encrypt_col_vector(vec1, unit2);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because sizes do not match.
        (linear_algebra.sub_inplace(ciphertext1, ciphertext2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (linear_algebra.sub_inplace(ciphertext1, ciphertext3)), invalid_argument);
}

TEST(LinearAlgebraTest, SubColCol) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    Vector vec2 = random_vec(width);
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_col_vector(vec1, unit1);
    EncryptedColVector ciphertext2 = linear_algebra.encrypt_col_vector(vec2, unit1);

    EncryptedColVector ciphertext3 = linear_algebra.sub(ciphertext1, ciphertext2);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = vec1 - vec2;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, SubMatrixPlaintextMatrix_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    Matrix mat1 = random_mat(200, 300);
    Matrix mat2 = random_mat(200, 301);
    Matrix mat3 = random_mat(201, 300);
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because widths do not match.
        (linear_algebra.sub_plain_inplace(ciphertext1, mat2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because heights do not match.
        (linear_algebra.sub_plain_inplace(ciphertext1, mat3)), invalid_argument);
}

TEST(LinearAlgebraTest, SubMatrixPlaintextMatrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int height = 200;
    int width = 300;

    Matrix mat1 = random_mat(height, width);
    Matrix mat2 = random_mat(height, width);
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);

    EncryptedMatrix ciphertext3 = linear_algebra.sub_plain(ciphertext1, mat2);
    Matrix actual_result = linear_algebra.decrypt(ciphertext3);
    Matrix expected_result = mat1 - mat2;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, SubRowPlaintextRow_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    Vector vec1 = random_vec(200);
    Vector vec2 = random_vec(201);
    EncryptedRowVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because sizes do not match.
        (linear_algebra.sub_plain_inplace(ciphertext1, vec2)), invalid_argument);
}

TEST(LinearAlgebraTest, SubRowPlaintextRow) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    Vector vec2 = random_vec(width);
    EncryptedRowVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);

    EncryptedRowVector ciphertext3 = linear_algebra.sub_plain(ciphertext1, vec2);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = vec1 - vec2;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, SubColPlaintextCol_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    Vector vec1 = random_vec(200);
    Vector vec2 = random_vec(201);
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_col_vector(vec1, unit1);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because sizes do not match.
        (linear_algebra.sub_plain_inplace(ciphertext1, vec2)), invalid_argument);
}

TEST(LinearAlgebraTest, SubColPlaintextCol) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    Vector vec2 = random_vec(width);
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_col_vector(vec1, unit1);

    EncryptedColVector ciphertext3 = linear_algebra.sub_plain(ciphertext1, vec2);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = vec1 - vec2;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, SubMatrixScalar) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int height = 200;
    int width = 300;

    Matrix mat1 = random_mat(height, width);
    double scalar = 3.14;
    Matrix mat2 = Matrix(height, width, vector<double>(height * width, scalar));
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);

    EncryptedMatrix ciphertext3 = linear_algebra.sub_plain(ciphertext1, scalar);
    Matrix actual_result = linear_algebra.decrypt(ciphertext3);
    Matrix expected_result = mat1 - mat2;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, SubRowScalar) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    double scalar = 3.14;
    Vector vec2 = Vector(vector<double>(width, scalar));
    EncryptedRowVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);

    EncryptedRowVector ciphertext3 = linear_algebra.sub_plain(ciphertext1, scalar);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = vec1 - vec2;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, SubColScalar) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int height = 300;

    Vector vec1 = random_vec(height);
    double scalar = 3.14;
    Vector vec2 = Vector(vector<double>(height, scalar));
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_col_vector(vec1, unit1);

    EncryptedColVector ciphertext3 = linear_algebra.sub_plain(ciphertext1, scalar);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = vec1 - vec2;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, NegateMatrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int height = 200;
    int width = 300;

    Matrix mat1 = random_mat(height, width);
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);

    EncryptedMatrix ciphertext3 = linear_algebra.negate(ciphertext1);
    Matrix actual_result = linear_algebra.decrypt(ciphertext3);
    Matrix expected_result = -mat1;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, NegateRow) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    EncryptedRowVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);

    EncryptedRowVector ciphertext3 = linear_algebra.negate(ciphertext1);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = -vec1;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, NegateCol) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int height = 300;

    Vector vec1 = random_vec(height);
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_col_vector(vec1, unit1);

    EncryptedColVector ciphertext3 = linear_algebra.negate(ciphertext1);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = -vec1;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_FALSE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, MultiplyMatrixScalar) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int height = 200;
    int width = 300;

    Matrix mat1 = random_mat(height, width);
    double scalar = 3.14;
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);

    EncryptedMatrix ciphertext3 = linear_algebra.multiply_plain(ciphertext1, scalar);
    Matrix actual_result = linear_algebra.decrypt(ciphertext3);
    Matrix expected_result = scalar * mat1;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_TRUE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, MultiplyRowScalar) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    double scalar = 3.14;
    EncryptedRowVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);

    EncryptedRowVector ciphertext3 = linear_algebra.multiply_plain(ciphertext1, scalar);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = scalar * vec1;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_TRUE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, MultiplyColScalar) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int height = 300;

    Vector vec1 = random_vec(height);
    double scalar = 3.14;
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_col_vector(vec1, unit1);

    EncryptedColVector ciphertext3 = linear_algebra.multiply_plain(ciphertext1, scalar);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = scalar * vec1;
    ASSERT_LT(relative_error(actual_result, expected_result), MAX_NORM);
    ASSERT_FALSE(ciphertext3.needs_relin());
    ASSERT_TRUE(ciphertext3.needs_rescale());
}

TEST(LinearAlgebraTest, MultiplyMatrixMatrix_Row_Major_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(8192, THREE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x128 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    // a 128x64 encoding unit
    int unit2_height = 128;
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);

    Matrix mat1 = random_mat(55, 78);
    Matrix mat2 = random_mat(77, 39);
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);
    EncryptedMatrix ciphertext2 = linear_algebra.encrypt_matrix(mat2, unit1);
    EncryptedMatrix ciphertext3 = linear_algebra.encrypt_matrix(mat1, unit2);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because inner dimensions do not match.
        (linear_algebra.multiply_row_major(ciphertext1, ciphertext2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (linear_algebra.multiply_row_major(ciphertext1, ciphertext3)), invalid_argument);
}

void test_multiply_matrix_matrix_row_major(LinearAlgebra &linear_algebra, int left_dim, int inner_dim, int right_dim,
                                           double scalar, EncodingUnit &unit) {
    // matrix-matrix mutliplication takes A^T and B as inputs and computes c*A*B for a scalar c and matrices A, B with
    // compatible dimensions Matrix A is left_dim x inner_dim, so A^T is the reverse
    Matrix matrix_a_transpose = random_mat(inner_dim, left_dim);
    // Matrix B is inner_dim x right_dim
    Matrix matrix_b = random_mat(inner_dim, right_dim);

    EncryptedMatrix ct_a_transpose = linear_algebra.encrypt_matrix(matrix_a_transpose, unit);
    EncryptedMatrix ct_b = linear_algebra.encrypt_matrix(matrix_b, unit, ct_a_transpose.he_level() - 1);
    EncryptedMatrix ct_c_times_A_times_B = linear_algebra.multiply_row_major(ct_a_transpose, ct_b, scalar);
    Matrix actual_output = linear_algebra.decrypt(ct_c_times_A_times_B);

    // Transpose of A^T is A
    Matrix matrix_a = trans(matrix_a_transpose);
    Matrix expected_output = scalar * prec_prod(matrix_a, matrix_b);

    ASSERT_LT(relative_error(actual_output, expected_output), MAX_NORM);
    ASSERT_FALSE(ct_c_times_A_times_B.needs_relin());
    ASSERT_TRUE(ct_c_times_A_times_B.needs_rescale());
    ASSERT_EQ(ct_c_times_A_times_B.he_level(), ONE_MULTI_DEPTH);
}

TEST(LinearAlgebraTest, MultiplyMatrixMatrix_Row_Major) {
    HomomorphicEval ckks_instance = HomomorphicEval(8192, THREE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x128 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    int unit1_width = 8192 / unit1_height;

    // both matrices are exactly the size of the encoding unit
    test_multiply_matrix_matrix_row_major(linear_algebra, unit1_width, unit1_height, unit1_width, 1.0, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, unit1_width, unit1_height, unit1_width, PI, unit1);

    // one or more dimensions are are multiple of the encoding unit (no padding)
    int large_width = 2 * unit1_width;
    int large_height = 2 * unit1_height;
    test_multiply_matrix_matrix_row_major(linear_algebra, large_width, unit1_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, unit1_width, large_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, unit1_width, unit1_height, large_width, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, large_width, unit1_height, large_width, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, unit1_width, large_height, large_width, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, large_width, large_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, large_width, large_height, large_width, PI, unit1);

    // one or more dimensions are larger than the encoding unit (padding required)
    large_width = unit1_width + 17;
    large_height = unit1_height + 11;
    test_multiply_matrix_matrix_row_major(linear_algebra, large_width, unit1_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, unit1_width, large_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, unit1_width, unit1_height, large_width, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, large_width, unit1_height, large_width, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, unit1_width, large_height, large_width, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, large_width, large_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, large_width, large_height, large_width, PI, unit1);

    // // one or more dimensions are are fraction of the encoding unit (padding required)
    int half_width = unit1_width / 2;
    int half_height = unit1_height / 2;
    test_multiply_matrix_matrix_row_major(linear_algebra, half_width, unit1_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, unit1_width, half_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, unit1_width, unit1_height, half_width, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, half_width, unit1_height, half_width, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, unit1_width, half_height, half_width, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, half_width, half_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, half_width, half_height, half_width, PI, unit1);

    // // some random dimensions
    test_multiply_matrix_matrix_row_major(linear_algebra, 13, 78, 141, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, 67, 17, 312, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, 134, 134, 134, PI, unit1);
    test_multiply_matrix_matrix_row_major(linear_algebra, 300, 27, 29, PI, unit1);
}

TEST(LinearAlgebraTest, MultiplyMatrixMatrix_Row_Major_Mixed_Unit_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(8192, THREE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // both of these units are valid for inputs to multiply_mixed_unit
    // a 256x32 encoding unit
    int unit1_height = 256;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    // a 128x64 encoding unit
    int unit2_height = 128;
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);

    Matrix mat1 = random_mat(17, 16);
    Matrix mat2 = random_mat(16, 16);
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);
    EncryptedMatrix ciphertext2 = linear_algebra.encrypt_matrix(mat2, unit1);
    EncryptedMatrix ciphertext3 = linear_algebra.encrypt_matrix(mat1, unit2);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because inner dimensions do not match
        // (mat1 is 17-by-16, but represents the *transpose* of the left argument to the multiplication)
        (linear_algebra.multiply_row_major_mixed_unit(ciphertext1, ciphertext2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (linear_algebra.multiply_row_major_mixed_unit(ciphertext1, ciphertext3)), invalid_argument);

    // Everything above here is copied from the normal matrix invalid test
    // multiply_row_major_mixed_unit has several additional invalid cases:
    // 1. n-by-m unit where m > n
    // 2. s > m
    // 3. u > m

    // a 64x128 encoding unit, invalid for inputs
    int unit3_height = 64;
    EncodingUnit unit3 = linear_algebra.make_unit(unit3_height);
    EncryptedMatrix ciphertext4 = linear_algebra.encrypt_matrix(mat1, unit3);
    EncryptedMatrix ciphertext5 = linear_algebra.encrypt_matrix(mat2, unit3);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because unit3 is invalid:
        // n-by-m unit is 64-by-128, but m > n
        (linear_algebra.multiply_row_major_mixed_unit(ciphertext4, ciphertext5)), invalid_argument);

    Matrix mat3 = random_mat(64, 64);
    Matrix mat4 = random_mat(64, 32);
    EncryptedMatrix ciphertext6 = linear_algebra.encrypt_matrix(mat3, unit1);
    EncryptedMatrix ciphertext7 = linear_algebra.encrypt_matrix(mat4, unit1);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because mat3 is t-by-s=64x64, so s=64>m=32
        (linear_algebra.multiply_row_major_mixed_unit(ciphertext6, ciphertext7)), invalid_argument);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because mat3 is t-by-u=64x64, so u=64>m=32
        (linear_algebra.multiply_row_major_mixed_unit(ciphertext7, ciphertext6)), invalid_argument);
}

void test_multiply_matrix_matrix_row_major_mixed_unit(LinearAlgebra &linear_algebra, int left_dim, int inner_dim, int right_dim,
                                                      double scalar, EncodingUnit &unit) {
    // matrix-matrix mutliplication takes A^T and B as inputs and computes c*A*B for a scalar c and matrices A, B with
    // compatible dimensions Matrix A is left_dim x inner_dim, so A^T is the reverse
    Matrix matrix_a_transpose = random_mat(inner_dim, left_dim);
    // Matrix B is inner_dim x right_dim
    Matrix matrix_b = random_mat(inner_dim, right_dim);

    EncryptedMatrix ct_a_transpose = linear_algebra.encrypt_matrix(matrix_a_transpose, unit);
    EncryptedMatrix ct_b = linear_algebra.encrypt_matrix(matrix_b, unit, ct_a_transpose.he_level() - 1);
    EncryptedMatrix ct_c_times_A_times_B = linear_algebra.multiply_row_major_mixed_unit(ct_a_transpose, ct_b, scalar);
    Matrix actual_output = linear_algebra.decrypt(ct_c_times_A_times_B);

    // Transpose of A^T is A
    Matrix matrix_a = trans(matrix_a_transpose);
    Matrix expected_output = scalar * prec_prod(matrix_a, matrix_b);

    ASSERT_LT(relative_error(actual_output.data(), expected_output.data()), MAX_NORM);
    ASSERT_EQ(unit.encoding_height(), ct_c_times_A_times_B.encoding_unit().encoding_width());
    ASSERT_EQ(unit.encoding_width(), ct_c_times_A_times_B.encoding_unit().encoding_height());
}

TEST(LinearAlgebraTest, MultiplyMatrixMatrix_Row_Major_Mixed_Unit) {
    HomomorphicEval ckks_instance = HomomorphicEval(8192, THREE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 128x64 encoding unit
    int unit1_height = 128;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    int unit1_width = 8192 / unit1_height;

    // both matrices are exactly the size of the encoding unit
    test_multiply_matrix_matrix_row_major_mixed_unit(linear_algebra, unit1_width, unit1_height, unit1_width, 1.0, unit1);
    test_multiply_matrix_matrix_row_major_mixed_unit(linear_algebra, unit1_width, unit1_height, unit1_width, PI, unit1);

    // one or more matrices are smaller than the encoding unit
    test_multiply_matrix_matrix_row_major_mixed_unit(linear_algebra, unit1_width - 9, unit1_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_row_major_mixed_unit(linear_algebra, unit1_width, unit1_height - 9, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_row_major_mixed_unit(linear_algebra, unit1_width, unit1_height, unit1_width - 9, PI, unit1);
    test_multiply_matrix_matrix_row_major_mixed_unit(linear_algebra, unit1_width - 9, unit1_height, unit1_width - 11, PI, unit1);
    test_multiply_matrix_matrix_row_major_mixed_unit(linear_algebra, unit1_width - 9, unit1_height - 11, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_row_major_mixed_unit(linear_algebra, unit1_width, unit1_height - 9, unit1_width - 11, PI, unit1);
    test_multiply_matrix_matrix_row_major_mixed_unit(linear_algebra, unit1_width - 13, unit1_height - 9, unit1_width - 11, PI, unit1);
}

TEST(LinearAlgebraTest, MultiplyMatrixMatrix_Col_Major_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(8192, THREE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x128 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    // a 128x64 encoding unit
    int unit2_height = 128;
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);

    Matrix mat1 = random_mat(55, 78);
    Matrix mat2 = random_mat(77, 39);
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);
    EncryptedMatrix ciphertext2 = linear_algebra.encrypt_matrix(mat2, unit1);
    EncryptedMatrix ciphertext3 = linear_algebra.encrypt_matrix(mat1, unit2);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because inner dimensions do not match.
        (linear_algebra.multiply_col_major(ciphertext1, ciphertext2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (linear_algebra.multiply_col_major(ciphertext1, ciphertext3)), invalid_argument);
}

void test_multiply_matrix_matrix_col_major(LinearAlgebra &linear_algebra, int left_dim, int inner_dim, int right_dim,
                                           double scalar, EncodingUnit &unit) {
    // matrix-matrix mutliplication takes A and B^T as inputs and computes c*A*B for a scalar c and matrices A, B with
    // compatible dimensions Matrix A is left_dim x inner_dim
    Matrix matrix_a = random_mat(left_dim, inner_dim);
    // Matrix B is inner_dim x right_dim,, so B^T is the reverse
    Matrix matrix_b_transpose = random_mat(right_dim, inner_dim);

    EncryptedMatrix ct_b_transpose = linear_algebra.encrypt_matrix(matrix_b_transpose, unit);
    EncryptedMatrix ct_a = linear_algebra.encrypt_matrix(matrix_a, unit, ct_b_transpose.he_level() - 1);
    EncryptedMatrix ct_c_times_A_times_B = linear_algebra.multiply_col_major(ct_a, ct_b_transpose, scalar);
    Matrix actual_output = linear_algebra.decrypt(ct_c_times_A_times_B);

    // Transpose of B^T is B
    Matrix matrix_b = trans(matrix_b_transpose);
    Matrix expected_output = scalar * prec_prod(matrix_a, matrix_b);

    ASSERT_LT(relative_error(actual_output, expected_output), MAX_NORM);
    ASSERT_FALSE(ct_c_times_A_times_B.needs_relin());
    ASSERT_TRUE(ct_c_times_A_times_B.needs_rescale());
    ASSERT_EQ(ct_c_times_A_times_B.he_level(), ONE_MULTI_DEPTH);
}

TEST(LinearAlgebraTest, MultiplyMatrixMatrix_Col_Major) {
    HomomorphicEval ckks_instance = HomomorphicEval(8192, THREE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x128 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    int unit1_width = 8192 / unit1_height;

    // both matrices are exactly the size of the encoding unit
    test_multiply_matrix_matrix_col_major(linear_algebra, unit1_width, unit1_height, unit1_width, 1.0, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, unit1_width, unit1_height, unit1_width, PI, unit1);

    // one or more dimensions are are multiple of the encoding unit (no padding)
    int large_width = 2 * unit1_width;
    int large_height = 2 * unit1_height;
    test_multiply_matrix_matrix_col_major(linear_algebra, large_width, unit1_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, unit1_width, large_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, unit1_width, unit1_height, large_width, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, large_width, unit1_height, large_width, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, unit1_width, large_height, large_width, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, large_width, large_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, large_width, large_height, large_width, PI, unit1);

    // one or more dimensions are larger than the encoding unit (padding required)
    large_width = unit1_width + 17;
    large_height = unit1_height + 11;
    test_multiply_matrix_matrix_col_major(linear_algebra, large_width, unit1_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, unit1_width, large_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, unit1_width, unit1_height, large_width, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, large_width, unit1_height, large_width, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, unit1_width, large_height, large_width, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, large_width, large_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, large_width, large_height, large_width, PI, unit1);

    // // one or more dimensions are are fraction of the encoding unit (padding required)
    int half_width = unit1_width / 2;
    int half_height = unit1_height / 2;
    test_multiply_matrix_matrix_col_major(linear_algebra, half_width, unit1_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, unit1_width, half_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, unit1_width, unit1_height, half_width, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, half_width, unit1_height, half_width, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, unit1_width, half_height, half_width, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, half_width, half_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, half_width, half_height, half_width, PI, unit1);

    // // some random dimensions
    test_multiply_matrix_matrix_col_major(linear_algebra, 13, 78, 141, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, 67, 17, 312, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, 134, 134, 134, PI, unit1);
    test_multiply_matrix_matrix_col_major(linear_algebra, 300, 27, 29, PI, unit1);
}

TEST(LinearAlgebraTest, MultiplyRowMatrix_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    // a 128x32 encoding unit
    int unit2_height = 128;
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);

    Vector vec1 = random_vec(54);
    Vector vec2 = random_vec(55);
    Matrix mat = random_mat(55, 78);
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);
    EncryptedColVector ciphertext2 = linear_algebra.encrypt_row_vector(vec1, unit2);
    EncryptedMatrix ciphertext3 = linear_algebra.encrypt_matrix(mat, unit1);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because dimensions do not match.
        (linear_algebra.multiply(ciphertext1, ciphertext3)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (linear_algebra.multiply(ciphertext2, ciphertext3)), invalid_argument);
}

void test_multiply_row_matrix(LinearAlgebra &linear_algebra, int left_dim, int right_dim, EncodingUnit &unit, bool mixed_unit) {
    // Matrix A is left_dim x right_dim
    Vector vec = random_vec(left_dim);
    Matrix mat = random_mat(left_dim, right_dim);

    EncryptedRowVector ct_vec = linear_algebra.encrypt_row_vector(vec, unit);
    EncryptedMatrix ct_mat = linear_algebra.encrypt_matrix(mat, unit);
    EncryptedColVector result;
    if (mixed_unit) {
        result = linear_algebra.multiply_mixed_unit(ct_vec, ct_mat);
    }
    else {
        result = linear_algebra.multiply(ct_vec, ct_mat);
    }
    Vector actual_output = linear_algebra.decrypt(result);

    Vector expected_output = prec_prod(vec, mat);

    ASSERT_LT(relative_error(actual_output, expected_output), MAX_NORM);
    ASSERT_FALSE(result.needs_relin());
    ASSERT_TRUE(result.needs_rescale());
    ASSERT_EQ(result.he_level(), ONE_MULTI_DEPTH);
}

TEST(LinearAlgebraTest, MultiplyRowMatrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    int unit1_width = NUM_OF_SLOTS / unit1_height;

    bool mixed_unit = false;

    // matrix is are exactly the size of the encoding unit
    test_multiply_row_matrix(linear_algebra, unit1_width, unit1_height, unit1, mixed_unit);

    // one or more dimensions are are multiple of the encoding unit (no padding)
    int large_height = 2 * unit1_height;
    int large_width = 2 * unit1_width;
    test_multiply_row_matrix(linear_algebra, large_height, unit1_width, unit1, mixed_unit);
    test_multiply_row_matrix(linear_algebra, unit1_height, large_width, unit1, mixed_unit);
    test_multiply_row_matrix(linear_algebra, large_height, large_width, unit1, mixed_unit);

    // one or more dimensions are larger than the encoding unit (padding required)
    large_height = unit1_height + 11;
    large_width = unit1_width + 17;
    test_multiply_row_matrix(linear_algebra, large_height, unit1_width, unit1, mixed_unit);
    test_multiply_row_matrix(linear_algebra, unit1_height, large_width, unit1, mixed_unit);
    test_multiply_row_matrix(linear_algebra, large_height, large_width, unit1, mixed_unit);

    // one or more dimensions are are fraction of the encoding unit (padding required)
    int half_height = unit1_height / 2;
    int half_width = unit1_width / 2;
    test_multiply_row_matrix(linear_algebra, half_width, unit1_width, unit1, mixed_unit);
    test_multiply_row_matrix(linear_algebra, unit1_height, half_height, unit1, mixed_unit);
    test_multiply_row_matrix(linear_algebra, half_width, half_height, unit1, mixed_unit);

    // some random dimensions
    test_multiply_row_matrix(linear_algebra, 13, 78, unit1, mixed_unit);
    test_multiply_row_matrix(linear_algebra, 67, 17, unit1, mixed_unit);
    test_multiply_row_matrix(linear_algebra, 134, 134, unit1, mixed_unit);
    test_multiply_row_matrix(linear_algebra, 300, 27, unit1, mixed_unit);
}

// Covers EncryptedColVector multiply_mixed_unit(const EncryptedRowVector &enc_vec, const EncryptedMatrix &enc_mat)
TEST(LinearAlgebraTest, MultiplyRowMatrix_Mixed_Unit_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    // a 32x128 encoding unit
    int unit2_height = 32;
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);

    Vector vec1 = random_vec(54);
    Matrix mat1 = random_mat(55, 32);
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);
    EncryptedColVector ciphertext2 = linear_algebra.encrypt_row_vector(vec1, unit2);
    EncryptedMatrix ciphertext3 = linear_algebra.encrypt_matrix(mat1, unit1);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because dimensions do not match.
        (linear_algebra.multiply(ciphertext1, ciphertext3)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (linear_algebra.multiply(ciphertext2, ciphertext3)), invalid_argument);


    // Both arguments must be encoded with the same m-by-n unit where g <= m <= n.
    // a 128x32 encoding unit
    int unit3_height = 128;
    EncodingUnit unit3 = linear_algebra.make_unit(unit3_height);
    EncryptedColVector ciphertext4 = linear_algebra.encrypt_row_vector(vec1, unit3);
    EncryptedMatrix ciphertext5 = linear_algebra.encrypt_matrix(mat, unit3);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because unit is invalid for this operation.
        (linear_algebra.multiply(ciphertext4, ciphertext5)), invalid_argument);

    Matrix mat2 = random_mat(55, 33);
    Vector vec2 = random_vec(55);
    EncryptedColVector ciphertext6 = linear_algebra.encrypt_row_vector(vec2, unit2);
    EncryptedMatrix ciphertext7 = linear_algebra.encrypt_matrix(mat2, unit2);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because the matrix width (33) is larger than the unit height (32)
        (linear_algebra.multiply(ciphertext6, ciphertext7)), invalid_argument);
}

// Covers EncryptedColVector multiply_mixed_unit(const EncryptedRowVector &enc_vec, const EncryptedMatrix &enc_mat)
TEST(LinearAlgebraTest, MultiplyRowMatrix_Mixed_Unit) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    int unit1_width = NUM_OF_SLOTS / unit1_height;

    bool mixed_unit = true;

    /// In this test, the matrix width cannot exceed the encoding unit height

    // matrix is exactly the size of the encoding unit
    test_multiply_row_matrix(linear_algebra, unit1_height, unit1_width, unit1, mixed_unit);

    // one or more dimensions are are multiple of the encoding unit (no padding)
    int large_height = 2 * unit1_height;
    test_multiply_row_matrix(linear_algebra, large_height, unit1_width, unit1, mixed_unit);

    // one or more dimensions are larger than the encoding unit (padding required)
    large_height = unit1_height + 11;
    test_multiply_row_matrix(linear_algebra, large_height, unit1_width, unit1, mixed_unit);

    // one or more dimensions are are fraction of the encoding unit (padding required)
    int half_height = unit1_height / 2;
    int half_width = unit1_width / 2;
    test_multiply_row_matrix(linear_algebra, half_height, unit1_width, unit1, mixed_unit);
    test_multiply_row_matrix(linear_algebra, unit1_height, half_width, unit1, mixed_unit);
    test_multiply_row_matrix(linear_algebra, half_height, half_width, unit1, mixed_unit);

    // some random dimensions
    test_multiply_row_matrix(linear_algebra, 13, 63, unit1, mixed_unit);
    test_multiply_row_matrix(linear_algebra, 67, 17, unit1, mixed_unit);
    test_multiply_row_matrix(linear_algebra, 134, 11, unit1, mixed_unit);
    test_multiply_row_matrix(linear_algebra, 300, 27, unit1, mixed_unit);
}

TEST(LinearAlgebraTest, MultiplyMatrixCol_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    // a 128x32 encoding unit
    int unit2_height = 128;
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);

    Vector vec1 = random_vec(79);
    Vector vec2 = random_vec(78);
    Matrix mat = random_mat(55, 78);
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_col_vector(vec1, unit1);
    EncryptedColVector ciphertext2 = linear_algebra.encrypt_col_vector(vec1, unit2);
    EncryptedMatrix ciphertext3 = linear_algebra.encrypt_matrix(mat, unit1);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because dimensions do not match.
        (linear_algebra.multiply(ciphertext3, ciphertext1)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (linear_algebra.multiply(ciphertext3, ciphertext2)), invalid_argument);
}

void test_multiply_matrix_col(LinearAlgebra &linear_algebra, int left_dim, int right_dim, double scalar,
                              EncodingUnit &unit) {
    // Matrix A is left_dim x right_dim
    Vector vec = random_vec(right_dim);
    Matrix mat = random_mat(left_dim, right_dim);

    EncryptedColVector ct_vec = linear_algebra.encrypt_col_vector(vec, unit);
    EncryptedMatrix ct_mat = linear_algebra.encrypt_matrix(mat, unit);
    EncryptedRowVector result = linear_algebra.multiply(ct_mat, ct_vec, scalar);
    Vector actual_output = linear_algebra.decrypt(result);

    Vector expected_output = scalar * prec_prod(mat, vec);

    ASSERT_LT(relative_error(actual_output, expected_output), MAX_NORM);
    ASSERT_FALSE(result.needs_relin());
    ASSERT_TRUE(result.needs_rescale());
    ASSERT_EQ(result.he_level(), ONE_MULTI_DEPTH);
}

// this test also covers EncryptedMatrix hadamard_multiply(const EncryptedRowVector &vec, const EncryptedMatrix &mat);
TEST(LinearAlgebraTest, MultiplyMatrixCol) {
    HomomorphicEval ckks_instance = HomomorphicEval(8192, TWO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    int unit1_width = 8192 / unit1_height;

    // both matrices are exactly the size of the encoding unit
    test_multiply_matrix_col(linear_algebra, unit1_width, unit1_height, 1.0, unit1);
    test_multiply_matrix_col(linear_algebra, unit1_width, unit1_height, PI, unit1);

    // one or more dimensions are are multiple of the encoding unit (no padding)
    int large_width = 2 * unit1_width;
    int large_height = 2 * unit1_height;
    test_multiply_matrix_col(linear_algebra, large_width, unit1_height, PI, unit1);
    test_multiply_matrix_col(linear_algebra, unit1_width, large_height, PI, unit1);
    test_multiply_matrix_col(linear_algebra, large_width, large_height, PI, unit1);

    // one or more dimensions are larger than the encoding unit (padding required)
    large_width = unit1_width + 17;
    large_height = unit1_height + 11;
    test_multiply_matrix_col(linear_algebra, large_width, unit1_height, PI, unit1);
    test_multiply_matrix_col(linear_algebra, unit1_width, large_height, PI, unit1);
    test_multiply_matrix_col(linear_algebra, large_width, large_height, PI, unit1);

    // one or more dimensions are are fraction of the encoding unit (padding required)
    int half_width = unit1_width / 2;
    int half_height = unit1_height / 2;
    test_multiply_matrix_col(linear_algebra, half_width, unit1_height, PI, unit1);
    test_multiply_matrix_col(linear_algebra, unit1_width, half_height, PI, unit1);
    test_multiply_matrix_col(linear_algebra, half_width, half_height, PI, unit1);

    // some random dimensions
    test_multiply_matrix_col(linear_algebra, 13, 78, PI, unit1);
    test_multiply_matrix_col(linear_algebra, 67, 17, PI, unit1);
    test_multiply_matrix_col(linear_algebra, 134, 134, PI, unit1);
    test_multiply_matrix_col(linear_algebra, 300, 27, PI, unit1);
}

TEST(LinearAlgebraTest, ReduceLevelToMinMatrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    Matrix mat = random_mat(64, 64);
    EncryptedMatrix ct_mat1 = linear_algebra.encrypt_matrix(mat, unit1);
    EncryptedMatrix ct_mat0 = linear_algebra.encrypt_matrix(mat, unit1, 0);
    ASSERT_EQ(ct_mat1.he_level(), 1);
    ASSERT_EQ(ct_mat0.he_level(), 0);
    linear_algebra.reduce_level_to_min_inplace(ct_mat1, ct_mat0);
    ASSERT_EQ(ct_mat1.he_level(), 0);

    ct_mat1 = linear_algebra.encrypt_matrix(mat, unit1);
    ASSERT_EQ(ct_mat1.he_level(), 1);
    ASSERT_EQ(ct_mat0.he_level(), 0);
    linear_algebra.reduce_level_to_min_inplace(ct_mat0, ct_mat1);
    ASSERT_EQ(ct_mat1.he_level(), 0);
}

TEST(LinearAlgebraTest, ReduceLevelToMinRow) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    Vector vec = random_vec(64);
    EncryptedRowVector ct_vec1 = linear_algebra.encrypt_row_vector(vec, unit1);
    EncryptedRowVector ct_vec0 = linear_algebra.encrypt_row_vector(vec, unit1, 0);
    ASSERT_EQ(ct_vec1.he_level(), 1);
    ASSERT_EQ(ct_vec0.he_level(), 0);
    linear_algebra.reduce_level_to_min_inplace(ct_vec1, ct_vec0);
    ASSERT_EQ(ct_vec1.he_level(), 0);

    ct_vec1 = linear_algebra.encrypt_row_vector(vec, unit1);
    ASSERT_EQ(ct_vec1.he_level(), 1);
    ASSERT_EQ(ct_vec0.he_level(), 0);
    linear_algebra.reduce_level_to_min_inplace(ct_vec0, ct_vec1);
    ASSERT_EQ(ct_vec1.he_level(), 0);
}

TEST(LinearAlgebraTest, ReduceLevelToMinCol) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    Vector vec = random_vec(64);
    EncryptedColVector ct_vec1 = linear_algebra.encrypt_col_vector(vec, unit1);
    EncryptedColVector ct_vec0 = linear_algebra.encrypt_col_vector(vec, unit1, 0);
    ASSERT_EQ(ct_vec1.he_level(), 1);
    ASSERT_EQ(ct_vec0.he_level(), 0);
    linear_algebra.reduce_level_to_min_inplace(ct_vec1, ct_vec0);
    ASSERT_EQ(ct_vec1.he_level(), 0);

    ct_vec1 = linear_algebra.encrypt_col_vector(vec, unit1);
    ASSERT_EQ(ct_vec1.he_level(), 1);
    ASSERT_EQ(ct_vec0.he_level(), 0);
    linear_algebra.reduce_level_to_min_inplace(ct_vec0, ct_vec1);
    ASSERT_EQ(ct_vec1.he_level(), 0);
}

TEST(LinearAlgebraTest, ReduceLevelToMatrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    Matrix mat = random_mat(64, 64);
    EncryptedMatrix ct_mat1 = linear_algebra.encrypt_matrix(mat, unit1);
    ASSERT_EQ(ct_mat1.he_level(), 1);
    linear_algebra.reduce_level_to_inplace(ct_mat1, 0);
    ASSERT_EQ(ct_mat1.he_level(), 0);
}

TEST(LinearAlgebraTest, ReduceLevelToRow) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    Vector vec = random_vec(64);
    EncryptedRowVector ct_vec1 = linear_algebra.encrypt_row_vector(vec, unit1);
    ASSERT_EQ(ct_vec1.he_level(), 1);
    linear_algebra.reduce_level_to_inplace(ct_vec1, 0);
    ASSERT_EQ(ct_vec1.he_level(), 0);
}

TEST(LinearAlgebraTest, ReduceLevelToCol) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    Vector vec = random_vec(64);
    EncryptedColVector ct_vec1 = linear_algebra.encrypt_col_vector(vec, unit1);
    ASSERT_EQ(ct_vec1.he_level(), 1);
    linear_algebra.reduce_level_to_inplace(ct_vec1, 0);
    ASSERT_EQ(ct_vec1.he_level(), 0);
}

TEST(LinearAlgebraTest, RescaleToNextMatrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    Matrix mat = random_mat(64, 64);
    EncryptedMatrix ct_mat1 = linear_algebra.encrypt_matrix(mat, unit1);
    EncryptedMatrix ct_mat2 = linear_algebra.multiply_plain(ct_mat1, 3.14);

    ASSERT_EQ(pow(2, LOG_SCALE * 2), ct_mat2.scale());
    uint64_t prime = get_last_prime(ckks_instance.context, ct_mat1.he_level());
    linear_algebra.rescale_to_next_inplace(ct_mat2);
    ASSERT_EQ(pow(2, LOG_SCALE * 2) / prime, ct_mat2.scale());
}

TEST(LinearAlgebraTest, RescaleToNextRow) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    Vector vec = random_vec(64);
    EncryptedRowVector ct_vec1 = linear_algebra.encrypt_row_vector(vec, unit1);
    EncryptedRowVector ct_vec2 = linear_algebra.multiply_plain(ct_vec1, 3.14);

    ASSERT_EQ(pow(2, LOG_SCALE * 2), ct_vec2.scale());
    uint64_t prime = get_last_prime(ckks_instance.context, ct_vec1.he_level());
    linear_algebra.rescale_to_next_inplace(ct_vec2);
    ASSERT_EQ(pow(2, LOG_SCALE * 2) / prime, ct_vec2.scale());
}

TEST(LinearAlgebraTest, RescaleToNextCol) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    Vector vec = random_vec(64);
    EncryptedColVector ct_vec1 = linear_algebra.encrypt_col_vector(vec, unit1);
    EncryptedColVector ct_vec2 = linear_algebra.multiply_plain(ct_vec1, 3.14);

    ASSERT_EQ(pow(2, LOG_SCALE * 2), ct_vec2.scale());
    uint64_t prime = get_last_prime(ckks_instance.context, ct_vec1.he_level());
    linear_algebra.rescale_to_next_inplace(ct_vec2);
    ASSERT_EQ(pow(2, LOG_SCALE * 2) / prime, ct_vec2.scale());
}

Vector sum_rows_plaintext(Matrix mat) {
    vector<double> coeffs(mat.size2());

    for (int j = 0; j < mat.size2(); j++) {
        double sum = 0;
        for (int i = 0; i < mat.size1(); i++) {
            sum += mat(i, j);
        }
        coeffs[j] = sum;
    }
    return Vector(coeffs);
}

void test_sum_rows(LinearAlgebra &linear_algebra, int height, int width, EncodingUnit &unit) {
    Matrix mat = random_mat(height, width);
    EncryptedMatrix ct_mat = linear_algebra.encrypt_matrix(mat, unit);
    EncryptedColVector ct_vec = linear_algebra.sum_rows(ct_mat);
    Vector actual_output = linear_algebra.decrypt(ct_vec);

    Vector expected_output = sum_rows_plaintext(mat);
    ASSERT_LT(relative_error(actual_output, expected_output), MAX_NORM);
    ASSERT_FALSE(ct_vec.needs_relin());
    ASSERT_FALSE(ct_vec.needs_rescale());
}

TEST(LinearAlgebraTest, SumRows) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    test_sum_rows(linear_algebra, 39, 37, unit1);
    test_sum_rows(linear_algebra, 35, 64, unit1);
    test_sum_rows(linear_algebra, 64, 31, unit1);
    test_sum_rows(linear_algebra, 64, 64, unit1);
    test_sum_rows(linear_algebra, 64, 67, unit1);
    test_sum_rows(linear_algebra, 69, 64, unit1);
    test_sum_rows(linear_algebra, 69, 67, unit1);
    test_sum_rows(linear_algebra, 128, 64, unit1);
    test_sum_rows(linear_algebra, 64, 128, unit1);
    test_sum_rows(linear_algebra, 128, 128, unit1);
}

void test_sum_rows_many(LinearAlgebra &linear_algebra, int height1, int width1, int height2, int width2,
                        EncodingUnit &unit) {
    Matrix mat1 = random_mat(height1, width1);
    Matrix mat2 = random_mat(height2, width2);

    EncryptedMatrix ct_mat1 = linear_algebra.encrypt_matrix(mat1, unit);
    EncryptedMatrix ct_mat2 = linear_algebra.encrypt_matrix(mat2, unit);
    EncryptedColVector ct_vec = linear_algebra.sum_rows_many({ct_mat1, ct_mat2});
    Vector actual_output = linear_algebra.decrypt(ct_vec);

    Vector expected_output = sum_rows_plaintext(mat1) + sum_rows_plaintext(mat2);
    ASSERT_LT(relative_error(actual_output, expected_output), MAX_NORM);
}

TEST(LinearAlgebraTest, SumRowsMany) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    test_sum_rows_many(linear_algebra, 64, 64, 64, 64, unit1);
    test_sum_rows_many(linear_algebra, 64, 64, 65, 64, unit1);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because widths do not match.
        test_sum_rows_many(linear_algebra, 64, 64, 64, 65, unit1), invalid_argument);

    test_sum_rows_many(linear_algebra, 64, 64, 128, 64, unit1);
    test_sum_rows_many(linear_algebra, 32, 64, 128, 64, unit1);
    test_sum_rows_many(linear_algebra, 128, 64, 128, 64, unit1);
    test_sum_rows_many(linear_algebra, 128, 128, 129, 128, unit1);
}

Vector sum_cols_plaintext(Matrix mat) {
    vector<double> coeffs(mat.size1());

    for (int i = 0; i < mat.size1(); i++) {
        double sum = 0;
        for (int j = 0; j < mat.size2(); j++) {
            sum += mat(i, j);
        }
        coeffs[i] = sum;
    }
    return Vector(coeffs);
}

void test_sum_cols(LinearAlgebra &linear_algebra, int height, int width, double scalar, EncodingUnit &unit) {
    Matrix mat = random_mat(height, width);
    EncryptedMatrix ct_mat = linear_algebra.encrypt_matrix(mat, unit);
    EncryptedRowVector ct_vec = linear_algebra.sum_cols(ct_mat, scalar);
    Vector actual_output = linear_algebra.decrypt(ct_vec);

    Vector expected_output = scalar * sum_cols_plaintext(mat);
    ASSERT_LT(relative_error(actual_output, expected_output), MAX_NORM);
    ASSERT_FALSE(ct_vec.needs_relin());
    ASSERT_TRUE(ct_vec.needs_rescale());
}

TEST(LinearAlgebraTest, SumCols) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    test_sum_cols(linear_algebra, 39, 37, PI, unit1);
    test_sum_cols(linear_algebra, 35, 64, PI, unit1);
    test_sum_cols(linear_algebra, 64, 64, 1, unit1);
    test_sum_cols(linear_algebra, 64, 64, PI, unit1);
    test_sum_cols(linear_algebra, 64, 67, PI, unit1);
    test_sum_cols(linear_algebra, 69, 64, PI, unit1);
    test_sum_cols(linear_algebra, 69, 67, PI, unit1);
    test_sum_cols(linear_algebra, 128, 64, PI, unit1);
    test_sum_cols(linear_algebra, 64, 128, PI, unit1);
    test_sum_cols(linear_algebra, 128, 128, PI, unit1);
}

void test_sum_cols_many(LinearAlgebra &linear_algebra, int height1, int width1, int height2, int width2,
                        EncodingUnit &unit) {
    Matrix mat1 = random_mat(height1, width1);
    Matrix mat2 = random_mat(height2, width2);

    EncryptedMatrix ct_mat1 = linear_algebra.encrypt_matrix(mat1, unit);
    EncryptedMatrix ct_mat2 = linear_algebra.encrypt_matrix(mat2, unit);
    EncryptedRowVector ct_vec = linear_algebra.sum_cols_many({ct_mat1, ct_mat2});
    Vector actual_output = linear_algebra.decrypt(ct_vec);

    Vector expected_output = sum_cols_plaintext(mat1) + sum_cols_plaintext(mat2);
    ASSERT_LT(relative_error(actual_output, expected_output), MAX_NORM);
}

TEST(LinearAlgebraTest, SumColsMany) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    test_sum_cols_many(linear_algebra, 64, 64, 64, 64, unit1);
    test_sum_cols_many(linear_algebra, 64, 64, 64, 65, unit1);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because heights do not match.
        test_sum_cols_many(linear_algebra, 64, 64, 65, 64, unit1), invalid_argument);

    test_sum_cols_many(linear_algebra, 64, 64, 64, 128, unit1);
    test_sum_cols_many(linear_algebra, 64, 32, 64, 128, unit1);
    test_sum_cols_many(linear_algebra, 64, 128, 64, 128, unit1);
    test_sum_cols_many(linear_algebra, 128, 128, 128, 129, unit1);
}

void test_hadamard_mul_matrix_matrix(LinearAlgebra &linear_algebra, int height, int width, EncodingUnit &unit) {
    Matrix mat1 = random_mat(height, width);
    Matrix mat2 = random_mat(height, width);

    vector<double> hprod_coeffs(height * width);
    for (int i = 0; i < height * width; i++) {
        hprod_coeffs[i] = mat1.data()[i] * mat2.data()[i];
    }

    EncryptedMatrix ct_mat1 = linear_algebra.encrypt_matrix(mat1, unit);
    EncryptedMatrix ct_mat2 = linear_algebra.encrypt_matrix(mat2, unit);

    EncryptedMatrix ct_mat3 = linear_algebra.hadamard_multiply(ct_mat1, ct_mat2);
    Matrix actual_output = linear_algebra.decrypt(ct_mat3);
    ASSERT_LT(relative_error(actual_output.data(), hprod_coeffs), MAX_NORM);
    ASSERT_TRUE(ct_mat3.needs_relin());
    ASSERT_TRUE(ct_mat3.needs_rescale());
}

TEST(LinearAlgebraTest, HadamardMulMatrixMatrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    test_hadamard_mul_matrix_matrix(linear_algebra, 39, 37, unit1);
    test_hadamard_mul_matrix_matrix(linear_algebra, 35, 64, unit1);
    test_hadamard_mul_matrix_matrix(linear_algebra, 64, 31, unit1);
    test_hadamard_mul_matrix_matrix(linear_algebra, 64, 64, unit1);
    test_hadamard_mul_matrix_matrix(linear_algebra, 64, 67, unit1);
    test_hadamard_mul_matrix_matrix(linear_algebra, 69, 64, unit1);
    test_hadamard_mul_matrix_matrix(linear_algebra, 69, 67, unit1);
    test_hadamard_mul_matrix_matrix(linear_algebra, 128, 64, unit1);
    test_hadamard_mul_matrix_matrix(linear_algebra, 64, 128, unit1);
    test_hadamard_mul_matrix_matrix(linear_algebra, 128, 128, unit1);
}

void test_hadamard_mul_row_row(LinearAlgebra &linear_algebra, int width, EncodingUnit &unit) {
    Vector vec1 = random_vec(width);
    Vector vec2 = random_vec(width);

    vector<double> hprod_coeffs(width);
    for (int i = 0; i < width; i++) {
        hprod_coeffs[i] = vec1.data()[i] * vec2.data()[i];
    }

    EncryptedRowVector ct_vec1 = linear_algebra.encrypt_row_vector(vec1, unit);
    EncryptedRowVector ct_vec2 = linear_algebra.encrypt_row_vector(vec2, unit);

    EncryptedRowVector ct_vec3 = linear_algebra.hadamard_multiply(ct_vec1, ct_vec2);
    Vector actual_output = linear_algebra.decrypt(ct_vec3);
    ASSERT_LT(relative_error(actual_output, hprod_coeffs), MAX_NORM);
    ASSERT_TRUE(ct_vec3.needs_relin());
    ASSERT_TRUE(ct_vec3.needs_rescale());
}

TEST(LinearAlgebraTest, HadamardMulRowRow) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    test_hadamard_mul_row_row(linear_algebra, 31, unit1);
    test_hadamard_mul_row_row(linear_algebra, 64, unit1);
    test_hadamard_mul_row_row(linear_algebra, 69, unit1);
    test_hadamard_mul_row_row(linear_algebra, 128, unit1);
}

void test_hadamard_mul_col_col(LinearAlgebra &linear_algebra, int height, EncodingUnit &unit) {
    Vector vec1 = random_vec(height);
    Vector vec2 = random_vec(height);

    vector<double> hprod_coeffs(height);
    for (int i = 0; i < height; i++) {
        hprod_coeffs[i] = vec1.data()[i] * vec2.data()[i];
    }

    EncryptedColVector ct_vec1 = linear_algebra.encrypt_col_vector(vec1, unit);
    EncryptedColVector ct_vec2 = linear_algebra.encrypt_col_vector(vec2, unit);

    EncryptedColVector ct_vec3 = linear_algebra.hadamard_multiply(ct_vec1, ct_vec2);
    Vector actual_output = linear_algebra.decrypt(ct_vec3);
    ASSERT_LT(relative_error(actual_output, hprod_coeffs), MAX_NORM);
    ASSERT_TRUE(ct_vec3.needs_relin());
    ASSERT_TRUE(ct_vec3.needs_rescale());
}

TEST(LinearAlgebraTest, HadamardMulColCol) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    test_hadamard_mul_col_col(linear_algebra, 31, unit1);
    test_hadamard_mul_col_col(linear_algebra, 64, unit1);
    test_hadamard_mul_col_col(linear_algebra, 69, unit1);
    test_hadamard_mul_col_col(linear_algebra, 128, unit1);
}

void test_hadamard_mul_matrix_square(LinearAlgebra &linear_algebra, int height, int width, EncodingUnit &unit) {
    Matrix mat1 = random_mat(height, width);

    vector<double> hprod_coeffs(height * width);
    for (int i = 0; i < height * width; i++) {
        hprod_coeffs[i] = mat1.data()[i] * mat1.data()[i];
    }

    EncryptedMatrix ct_mat1 = linear_algebra.encrypt_matrix(mat1, unit);
    EncryptedMatrix ct_mat3 = linear_algebra.hadamard_square(ct_mat1);
    Matrix actual_output = linear_algebra.decrypt(ct_mat3);
    ASSERT_LT(relative_error(actual_output.data(), hprod_coeffs), MAX_NORM);
    ASSERT_TRUE(ct_mat3.needs_relin());
    ASSERT_TRUE(ct_mat3.needs_rescale());
}

TEST(LinearAlgebraTest, HadamardMulMatrixSquare) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    test_hadamard_mul_matrix_square(linear_algebra, 39, 37, unit1);
    test_hadamard_mul_matrix_square(linear_algebra, 35, 64, unit1);
    test_hadamard_mul_matrix_square(linear_algebra, 64, 31, unit1);
    test_hadamard_mul_matrix_square(linear_algebra, 64, 64, unit1);
    test_hadamard_mul_matrix_square(linear_algebra, 64, 67, unit1);
    test_hadamard_mul_matrix_square(linear_algebra, 69, 64, unit1);
    test_hadamard_mul_matrix_square(linear_algebra, 69, 67, unit1);
    test_hadamard_mul_matrix_square(linear_algebra, 128, 64, unit1);
    test_hadamard_mul_matrix_square(linear_algebra, 64, 128, unit1);
    test_hadamard_mul_matrix_square(linear_algebra, 128, 128, unit1);
}

void test_hadamard_mul_row_square(LinearAlgebra &linear_algebra, int width, EncodingUnit &unit) {
    Vector vec1 = random_vec(width);

    vector<double> hprod_coeffs(width);
    for (int i = 0; i < width; i++) {
        hprod_coeffs[i] = vec1.data()[i] * vec1.data()[i];
    }

    EncryptedRowVector ct_vec1 = linear_algebra.encrypt_row_vector(vec1, unit);
    EncryptedRowVector ct_vec3 = linear_algebra.hadamard_square(ct_vec1);
    Vector actual_output = linear_algebra.decrypt(ct_vec3);
    ASSERT_LT(relative_error(actual_output.data(), hprod_coeffs), MAX_NORM);
    ASSERT_TRUE(ct_vec3.needs_relin());
    ASSERT_TRUE(ct_vec3.needs_rescale());
}

TEST(LinearAlgebraTest, HadamardMulRowSquare) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    test_hadamard_mul_row_square(linear_algebra, 31, unit1);
    test_hadamard_mul_row_square(linear_algebra, 64, unit1);
    test_hadamard_mul_row_square(linear_algebra, 69, unit1);
    test_hadamard_mul_row_square(linear_algebra, 128, unit1);
}

void test_hadamard_mul_col_square(LinearAlgebra &linear_algebra, int height, EncodingUnit &unit) {
    Vector vec1 = random_vec(height);

    vector<double> hprod_coeffs(height);
    for (int i = 0; i < height; i++) {
        hprod_coeffs[i] = vec1.data()[i] * vec1.data()[i];
    }

    EncryptedColVector ct_vec1 = linear_algebra.encrypt_col_vector(vec1, unit);

    EncryptedColVector ct_vec3 = linear_algebra.hadamard_square(ct_vec1);
    Vector actual_output = linear_algebra.decrypt(ct_vec3);
    ASSERT_LT(relative_error(actual_output.data(), hprod_coeffs), MAX_NORM);
    ASSERT_TRUE(ct_vec3.needs_relin());
    ASSERT_TRUE(ct_vec3.needs_rescale());
}

TEST(LinearAlgebraTest, HadamardMulColSquare) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    test_hadamard_mul_col_square(linear_algebra, 31, unit1);
    test_hadamard_mul_col_square(linear_algebra, 64, unit1);
    test_hadamard_mul_col_square(linear_algebra, 69, unit1);
    test_hadamard_mul_col_square(linear_algebra, 128, unit1);
}

TEST(LinearAlgebraTest, ReduceLevelToMin_Matrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit = linear_algebra.make_unit(unit1_height);

    Matrix mat1 = random_mat(128, 128);

    EncryptedMatrix ct_mat1 = linear_algebra.encrypt_matrix(mat1, unit);
    EncryptedMatrix ct_mat2 = linear_algebra.encrypt_matrix(mat1, unit, 0);
    linear_algebra.reduce_level_to_min_inplace(ct_mat1, ct_mat2);
    ASSERT_EQ(ct_mat1.he_level(), 0);

    EncryptedMatrix ct_mat3 = linear_algebra.encrypt_matrix(mat1, unit);
    linear_algebra.reduce_level_to_min_inplace(ct_mat2, ct_mat3);
    ASSERT_EQ(ct_mat3.he_level(), 0);
    ASSERT_FALSE(ct_mat3.needs_relin());
    ASSERT_FALSE(ct_mat3.needs_rescale());
}

TEST(LinearAlgebraTest, ReduceLevelToMin_ColVec) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit = linear_algebra.make_unit(unit1_height);

    Vector vec1 = random_vec(128);

    EncryptedColVector ct_vec1 = linear_algebra.encrypt_col_vector(vec1, unit);
    EncryptedColVector ct_vec2 = linear_algebra.encrypt_col_vector(vec1, unit, 0);
    linear_algebra.reduce_level_to_min_inplace(ct_vec1, ct_vec2);
    ASSERT_EQ(ct_vec1.he_level(), 0);

    EncryptedColVector ct_vec3 = linear_algebra.encrypt_col_vector(vec1, unit);
    linear_algebra.reduce_level_to_min_inplace(ct_vec2, ct_vec3);
    ASSERT_EQ(ct_vec3.he_level(), 0);
    ASSERT_FALSE(ct_vec3.needs_relin());
    ASSERT_FALSE(ct_vec3.needs_rescale());
}

TEST(LinearAlgebraTest, ReduceLevelToMin_RowVec) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit = linear_algebra.make_unit(unit1_height);

    Vector vec1 = random_vec(128);

    EncryptedRowVector ct_vec1 = linear_algebra.encrypt_row_vector(vec1, unit);
    EncryptedRowVector ct_vec2 = linear_algebra.encrypt_row_vector(vec1, unit, 0);
    linear_algebra.reduce_level_to_min_inplace(ct_vec1, ct_vec2);
    ASSERT_EQ(ct_vec1.he_level(), 0);

    EncryptedRowVector ct_vec3 = linear_algebra.encrypt_row_vector(vec1, unit);
    linear_algebra.reduce_level_to_min_inplace(ct_vec2, ct_vec3);
    ASSERT_EQ(ct_vec3.he_level(), 0);
    ASSERT_FALSE(ct_vec3.needs_relin());
    ASSERT_FALSE(ct_vec3.needs_rescale());
}

TEST(LinearAlgebraTest, ReduceLevelTo_Matrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit = linear_algebra.make_unit(unit1_height);

    Matrix mat1 = random_mat(128, 128);

    EncryptedMatrix ct_mat1 = linear_algebra.encrypt_matrix(mat1, unit);
    EncryptedMatrix ct_mat2 = linear_algebra.reduce_level_to(ct_mat1, 0);
    ASSERT_EQ(ct_mat2.he_level(), 0);
    ASSERT_FALSE(ct_mat2.needs_relin());
    ASSERT_FALSE(ct_mat2.needs_rescale());
}

TEST(LinearAlgebraTest, ReduceLevelTo_ColVec) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit = linear_algebra.make_unit(unit1_height);

    Vector vec1 = random_vec(128);

    EncryptedColVector ct_vec1 = linear_algebra.encrypt_col_vector(vec1, unit);
    EncryptedColVector ct_vec2 = linear_algebra.reduce_level_to(ct_vec1, 0);
    ASSERT_EQ(ct_vec2.he_level(), 0);
    ASSERT_FALSE(ct_vec2.needs_relin());
    ASSERT_FALSE(ct_vec2.needs_rescale());
}

TEST(LinearAlgebraTest, ReduceLevelTo_RowVec) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit = linear_algebra.make_unit(unit1_height);

    Vector vec1 = random_vec(128);

    EncryptedRowVector ct_vec1 = linear_algebra.encrypt_row_vector(vec1, unit);
    EncryptedRowVector ct_vec2 = linear_algebra.reduce_level_to(ct_vec1, 0);
    ASSERT_EQ(ct_vec2.he_level(), 0);
    ASSERT_FALSE(ct_vec2.needs_relin());
    ASSERT_FALSE(ct_vec2.needs_rescale());
}

TEST(LinearAlgebraTest, RescaleToNext_Matrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit = linear_algebra.make_unit(unit1_height);

    Matrix mat1 = random_mat(128, 128);

    EncryptedMatrix ct_mat1 = linear_algebra.encrypt_matrix(mat1, unit);
    ASSERT_EQ(ct_mat1.scale(), pow(2, LOG_SCALE));
    linear_algebra.multiply_plain_inplace(ct_mat1, 2);
    ASSERT_EQ(ct_mat1.scale(), pow(2, 2 * LOG_SCALE));
    ASSERT_EQ(ct_mat1.he_level(), 1);
    linear_algebra.rescale_to_next_inplace(ct_mat1);
    ASSERT_EQ(ct_mat1.he_level(), 0);
    uint64_t prime = get_last_prime(ckks_instance.context, 1);
    ASSERT_EQ(ct_mat1.scale(), pow(2, 2 * LOG_SCALE) / prime);
    ASSERT_FALSE(ct_mat1.needs_relin());
    ASSERT_FALSE(ct_mat1.needs_rescale());
}

TEST(LinearAlgebraTest, RescaleToNext_ColVec) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit = linear_algebra.make_unit(unit1_height);

    Vector vec1 = random_vec(128);

    EncryptedColVector ct_vec1 = linear_algebra.encrypt_col_vector(vec1, unit);
    ASSERT_EQ(ct_vec1.scale(), pow(2, LOG_SCALE));
    linear_algebra.multiply_plain_inplace(ct_vec1, 2);
    ASSERT_EQ(ct_vec1.scale(), pow(2, 2 * LOG_SCALE));
    ASSERT_EQ(ct_vec1.he_level(), 1);
    linear_algebra.rescale_to_next_inplace(ct_vec1);
    ASSERT_EQ(ct_vec1.he_level(), 0);
    uint64_t prime = get_last_prime(ckks_instance.context, 1);
    ASSERT_EQ(ct_vec1.scale(), pow(2, 2 * LOG_SCALE) / prime);
    ASSERT_FALSE(ct_vec1.needs_relin());
    ASSERT_FALSE(ct_vec1.needs_rescale());
}

TEST(LinearAlgebraTest, RescaleToNext_RowVec) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    // a 64x64 encoding unit
    int unit1_height = 64;
    EncodingUnit unit = linear_algebra.make_unit(unit1_height);

    Vector vec1 = random_vec(128);

    EncryptedRowVector ct_vec1 = linear_algebra.encrypt_row_vector(vec1, unit);
    ASSERT_EQ(ct_vec1.scale(), pow(2, LOG_SCALE));
    linear_algebra.multiply_plain_inplace(ct_vec1, 2);
    ASSERT_EQ(ct_vec1.scale(), pow(2, 2 * LOG_SCALE));
    ASSERT_EQ(ct_vec1.he_level(), 1);
    linear_algebra.rescale_to_next_inplace(ct_vec1);
    ASSERT_EQ(ct_vec1.he_level(), 0);
    uint64_t prime = get_last_prime(ckks_instance.context, 1);
    ASSERT_EQ(ct_vec1.scale(), pow(2, 2 * LOG_SCALE) / prime);
    ASSERT_FALSE(ct_vec1.needs_relin());
    ASSERT_FALSE(ct_vec1.needs_rescale());
}
