// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/api/linearalgebra/linearalgebra.h"

#include <iostream>

#include "../../testutil.h"
#include "gtest/gtest.h"
#include "hit/api/evaluator/homomorphic.h"
#include "hit/api/ciphertext.h"
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
    ASSERT_LT(diff2_norm(plaintext.data(), output.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, EncryptMatrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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
    ASSERT_LT(diff2_norm(plaintext.data(), output.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, EncryptRowVector) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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
    ASSERT_LT(diff2_norm(plaintext.data(), output.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, EncryptColVector) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int unit2_height = 128;  // a 128x32 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
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
    ASSERT_LT(diff2_norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddRowRow_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int unit2_height = 128;  // a 128x32 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    Vector vec2 = random_vec(width);
    EncryptedRowVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);
    EncryptedRowVector ciphertext2 = linear_algebra.encrypt_row_vector(vec2, unit1);

    EncryptedRowVector ciphertext3 = linear_algebra.add(ciphertext1, ciphertext2);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = vec1 + vec2;
    ASSERT_LT(diff2_norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddColCol_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int unit2_height = 128;  // a 128x32 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    Vector vec2 = random_vec(width);
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_col_vector(vec1, unit1);
    EncryptedColVector ciphertext2 = linear_algebra.encrypt_col_vector(vec2, unit1);

    EncryptedColVector ciphertext3 = linear_algebra.add(ciphertext1, ciphertext2);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = vec1 + vec2;
    ASSERT_LT(diff2_norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddMatrixPlaintextMatrix_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int height = 200;
    int width = 300;

    Matrix mat1 = random_mat(height, width);
    Matrix mat2 = random_mat(height, width);
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);

    EncryptedMatrix ciphertext3 = linear_algebra.add_plain(ciphertext1, mat2);
    Matrix actual_result = linear_algebra.decrypt(ciphertext3);
    Matrix expected_result = mat1 + mat2;
    ASSERT_LT(diff2_norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddRowPlaintextRow_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    Vector vec2 = random_vec(width);
    EncryptedRowVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);

    EncryptedRowVector ciphertext3 = linear_algebra.add_plain(ciphertext1, vec2);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = vec1 + vec2;
    ASSERT_LT(diff2_norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddColPlaintextCol_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    Vector vec2 = random_vec(width);
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_col_vector(vec1, unit1);

    EncryptedColVector ciphertext3 = linear_algebra.add_plain(ciphertext1, vec2);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = vec1 + vec2;
    ASSERT_LT(diff2_norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddMatrixScalar) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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
    ASSERT_LT(diff2_norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddRowScalar) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    double scalar = 3.14;
    Vector vec2 = Vector(vector<double>(width, scalar));
    EncryptedRowVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);

    EncryptedRowVector ciphertext3 = linear_algebra.add_plain(ciphertext1, scalar);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = vec1 + vec2;
    ASSERT_LT(diff2_norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddColScalar) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int height = 300;

    Vector vec1 = random_vec(height);
    double scalar = 3.14;
    Vector vec2 = Vector(vector<double>(height, scalar));
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_col_vector(vec1, unit1);

    EncryptedColVector ciphertext3 = linear_algebra.add_plain(ciphertext1, scalar);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = vec1 + vec2;
    ASSERT_LT(diff2_norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddMultipleMatrix_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int unit2_height = 128;  // a 128x32 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
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
    ASSERT_LT(diff2_norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddMultipleRow_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int unit2_height = 128;  // a 128x32 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
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
    ASSERT_LT(diff2_norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddMultipleCol_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int unit2_height = 128;  // a 128x32 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
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
    ASSERT_LT(diff2_norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, MultiplyMatrixScalar) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int height = 200;
    int width = 300;

    Matrix mat1 = random_mat(height, width);
    double scalar = 3.14;
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);

    EncryptedMatrix ciphertext3 = linear_algebra.multiply_plain(ciphertext1, scalar);
    Matrix actual_result = linear_algebra.decrypt(ciphertext3);
    Matrix expected_result = scalar * mat1;
    ASSERT_LT(diff2_norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, MultiplyRowScalar) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    double scalar = 3.14;
    EncryptedRowVector ciphertext1 = linear_algebra.encrypt_row_vector(vec1, unit1);

    EncryptedRowVector ciphertext3 = linear_algebra.multiply_plain(ciphertext1, scalar);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = scalar * vec1;
    ASSERT_LT(diff2_norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, MultiplyColScalar) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int height = 300;

    Vector vec1 = random_vec(height);
    double scalar = 3.14;
    EncryptedColVector ciphertext1 = linear_algebra.encrypt_col_vector(vec1, unit1);

    EncryptedColVector ciphertext3 = linear_algebra.multiply_plain(ciphertext1, scalar);
    Vector actual_result = linear_algebra.decrypt(ciphertext3);
    Vector expected_result = scalar * vec1;
    ASSERT_LT(diff2_norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, MultiplyMatrixMatrix_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(8192, THREE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x128 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int unit2_height = 128;  // a 128x64 encoding unit
    EncodingUnit unit2 = linear_algebra.make_unit(unit2_height);

    Matrix mat1 = random_mat(55, 78);
    Matrix mat2 = random_mat(77, 39);
    EncryptedMatrix ciphertext1 = linear_algebra.encrypt_matrix(mat1, unit1);
    EncryptedMatrix ciphertext2 = linear_algebra.encrypt_matrix(mat2, unit1);
    EncryptedMatrix ciphertext3 = linear_algebra.encrypt_matrix(mat1, unit2);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because inner dimensions do not match.
        (linear_algebra.multiply(ciphertext1, ciphertext2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (linear_algebra.multiply(ciphertext1, ciphertext3)), invalid_argument);
}

void test_multiply_matrix_matrix(LinearAlgebra &linear_algebra, int left_dim, int inner_dim, int right_dim, double scalar,
                                 EncodingUnit &unit) {
    // matrix-matrix mutliplication takes A^T and B as inputs and computes c*A*B for a scalar c and matrices A, B with
    // compatible dimensions Matrix A is left_dim x inner_dim, so A^T is the reverse
    Matrix matrix_a_transpose = random_mat(inner_dim, left_dim);
    // Matrix B is inner_dim x right_dim
    Matrix matrix_b = random_mat(inner_dim, right_dim);

    EncryptedMatrix ct_a_transpose = linear_algebra.encrypt_matrix(matrix_a_transpose, unit);
    EncryptedMatrix ct_b = linear_algebra.encrypt_matrix(matrix_b, unit, ct_a_transpose.he_level() - 1);
    EncryptedMatrix ct_c_times_A_times_B = linear_algebra.multiply(ct_a_transpose, ct_b, scalar);
    Matrix actual_output = linear_algebra.decrypt(ct_c_times_A_times_B);

    // Transpose of A^T is A
    Matrix matrix_a = trans(matrix_a_transpose);
    Matrix expected_output = scalar * prec_prod(matrix_a, matrix_b);

    ASSERT_LT(diff2_norm(actual_output.data(), expected_output.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, MultiplyMatrixMatrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(8192, THREE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x128 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    int unit1_width = 8192 / unit1_height;

    // both matrices are exactly the size of the encoding unit
    test_multiply_matrix_matrix(linear_algebra, unit1_width, unit1_height, unit1_width, 1.0, unit1);
    test_multiply_matrix_matrix(linear_algebra, unit1_width, unit1_height, unit1_width, PI, unit1);

    // one or more dimensions are are multiple of the encoding unit (no padding)
    int large_width = 2 * unit1_width;
    int large_height = 2 * unit1_height;
    test_multiply_matrix_matrix(linear_algebra, large_width, unit1_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, unit1_width, large_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, unit1_width, unit1_height, large_width, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, large_width, unit1_height, large_width, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, unit1_width, large_height, large_width, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, large_width, large_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, large_width, large_height, large_width, PI, unit1);

    // one or more dimensions are larger than the encoding unit (padding required)
    large_width = unit1_width + 17;
    large_height = unit1_height + 11;
    test_multiply_matrix_matrix(linear_algebra, large_width, unit1_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, unit1_width, large_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, unit1_width, unit1_height, large_width, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, large_width, unit1_height, large_width, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, unit1_width, large_height, large_width, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, large_width, large_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, large_width, large_height, large_width, PI, unit1);

    // // one or more dimensions are are fraction of the encoding unit (padding required)
    int half_width = unit1_width / 2;
    int half_height = unit1_height / 2;
    test_multiply_matrix_matrix(linear_algebra, half_width, unit1_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, unit1_width, half_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, unit1_width, unit1_height, half_width, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, half_width, unit1_height, half_width, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, unit1_width, half_height, half_width, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, half_width, half_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, half_width, half_height, half_width, PI, unit1);

    // // some random dimensions
    test_multiply_matrix_matrix(linear_algebra, 13, 78, 141, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, 67, 17, 312, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, 134, 134, 134, PI, unit1);
    test_multiply_matrix_matrix(linear_algebra, 300, 27, 29, PI, unit1);
}

void test_multiply_row_matrix(LinearAlgebra &linear_algebra, int left_dim, int right_dim, EncodingUnit &unit) {
    // Matrix A is left_dim x right_dim
    Vector vec = random_vec(left_dim);
    Matrix mat = random_mat(left_dim, right_dim);

    EncryptedRowVector ct_vec = linear_algebra.encrypt_row_vector(vec, unit);
    EncryptedMatrix ct_mat = linear_algebra.encrypt_matrix(mat, unit);
    EncryptedColVector result = linear_algebra.multiply(ct_vec, ct_mat);
    Vector actual_output = linear_algebra.decrypt(result);

    Vector expected_output = prec_prod(vec, mat);

    ASSERT_LT(diff2_norm(actual_output.data(), expected_output.data()), MAX_NORM);
}

// this test also covers EncryptedMatrix hadamard_multiply(const EncryptedMatrix &mat, const EncryptedColVector &vec);
TEST(LinearAlgebraTest, MultiplyRowMatrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);

    int unit1_width = NUM_OF_SLOTS / unit1_height;

    // both matrices are exactly the size of the encoding unit
    test_multiply_row_matrix(linear_algebra, unit1_width, unit1_height, unit1);

    // one or more dimensions are are multiple of the encoding unit (no padding)
    int large_width = 2 * unit1_width;
    int large_height = 2 * unit1_height;
    test_multiply_row_matrix(linear_algebra, large_width, unit1_height, unit1);
    test_multiply_row_matrix(linear_algebra, unit1_width, large_height, unit1);
    test_multiply_row_matrix(linear_algebra, large_width, large_height, unit1);

    // one or more dimensions are larger than the encoding unit (padding required)
    large_width = unit1_width + 17;
    large_height = unit1_height + 11;
    test_multiply_row_matrix(linear_algebra, large_width, unit1_height, unit1);
    test_multiply_row_matrix(linear_algebra, unit1_width, large_height, unit1);
    test_multiply_row_matrix(linear_algebra, large_width, large_height, unit1);

    // one or more dimensions are are fraction of the encoding unit (padding required)
    int half_width = unit1_width / 2;
    int half_height = unit1_height / 2;
    test_multiply_row_matrix(linear_algebra, half_width, unit1_height, unit1);
    test_multiply_row_matrix(linear_algebra, unit1_width, half_height, unit1);
    test_multiply_row_matrix(linear_algebra, half_width, half_height, unit1);

    // some random dimensions
    test_multiply_row_matrix(linear_algebra, 13, 78, unit1);
    test_multiply_row_matrix(linear_algebra, 67, 17, unit1);
    test_multiply_row_matrix(linear_algebra, 134, 134, unit1);
    test_multiply_row_matrix(linear_algebra, 300, 27, unit1);
}

TEST(LinearAlgebraTest, MultiplyMatrixCol_InvalidCase) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    int unit2_height = 128;  // a 128x32 encoding unit
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

void test_multiply_matrix_col(LinearAlgebra &linear_algebra, int left_dim, int right_dim, double scalar, EncodingUnit &unit) {
    // Matrix A is left_dim x right_dim
    Vector vec = random_vec(right_dim);
    Matrix mat = random_mat(left_dim, right_dim);

    EncryptedColVector ct_vec = linear_algebra.encrypt_col_vector(vec, unit);
    EncryptedMatrix ct_mat = linear_algebra.encrypt_matrix(mat, unit);
    EncryptedRowVector result = linear_algebra.multiply(ct_mat, ct_vec, scalar);
    Vector actual_output = linear_algebra.decrypt(result);

    Vector expected_output = scalar * prec_prod(mat, vec);

    ASSERT_LT(diff2_norm(actual_output.data(), expected_output.data()), MAX_NORM);
}

// this test also covers EncryptedMatrix hadamard_multiply(const EncryptedRowVector &vec, const EncryptedMatrix &mat);
TEST(LinearAlgebraTest, MultiplyMatrixCol) {
    HomomorphicEval ckks_instance = HomomorphicEval(8192, TWO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
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

    int unit1_height = 64;  // a 64x64 encoding unit
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
    ASSERT_LT(diff2_norm(actual_output.data(), expected_output.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, SumRows) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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

void test_sum_rows_many(LinearAlgebra &linear_algebra, int height1, int width1, int height2, int width2, EncodingUnit &unit) {
    Matrix mat1 = random_mat(height1, width1);
    Matrix mat2 = random_mat(height2, width2);

    EncryptedMatrix ct_mat1 = linear_algebra.encrypt_matrix(mat1, unit);
    EncryptedMatrix ct_mat2 = linear_algebra.encrypt_matrix(mat2, unit);
    EncryptedColVector ct_vec = linear_algebra.sum_rows_many({ct_mat1, ct_mat2});
    Vector actual_output = linear_algebra.decrypt(ct_vec);

    Vector expected_output = sum_rows_plaintext(mat1) + sum_rows_plaintext(mat2);
    ASSERT_LT(diff2_norm(actual_output.data(), expected_output.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, SumRowsMany) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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
    ASSERT_LT(diff2_norm(actual_output.data(), expected_output.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, SumCols) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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

void test_sum_cols_many(LinearAlgebra &linear_algebra, int height1, int width1, int height2, int width2, EncodingUnit &unit) {
    Matrix mat1 = random_mat(height1, width1);
    Matrix mat2 = random_mat(height2, width2);

    EncryptedMatrix ct_mat1 = linear_algebra.encrypt_matrix(mat1, unit);
    EncryptedMatrix ct_mat2 = linear_algebra.encrypt_matrix(mat2, unit);
    EncryptedRowVector ct_vec = linear_algebra.sum_cols_many({ct_mat1, ct_mat2});
    Vector actual_output = linear_algebra.decrypt(ct_vec);

    Vector expected_output = sum_cols_plaintext(mat1) + sum_cols_plaintext(mat2);
    ASSERT_LT(diff2_norm(actual_output.data(), expected_output.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, SumColsMany) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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
    ASSERT_LT(diff2_norm(actual_output.data(), hprod_coeffs), MAX_NORM);
}

TEST(LinearAlgebraTest, HadamardMulMatrixMatrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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
    ASSERT_LT(diff2_norm(actual_output.data(), hprod_coeffs), MAX_NORM);
}

TEST(LinearAlgebraTest, HadamardMulRowRow) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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
    ASSERT_LT(diff2_norm(actual_output.data(), hprod_coeffs), MAX_NORM);
}

TEST(LinearAlgebraTest, HadamardMulColCol) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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
    ASSERT_LT(diff2_norm(actual_output.data(), hprod_coeffs), MAX_NORM);
}

TEST(LinearAlgebraTest, HadamardMulMatrixSquare) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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
    ASSERT_LT(diff2_norm(actual_output.data(), hprod_coeffs), MAX_NORM);
}

TEST(LinearAlgebraTest, HadamardMulRowSquare) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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
    ASSERT_LT(diff2_norm(actual_output.data(), hprod_coeffs), MAX_NORM);
}

TEST(LinearAlgebraTest, HadamardMulColSquare) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = linear_algebra.make_unit(unit1_height);
    test_hadamard_mul_col_square(linear_algebra, 31, unit1);
    test_hadamard_mul_col_square(linear_algebra, 64, unit1);
    test_hadamard_mul_col_square(linear_algebra, 69, unit1);
    test_hadamard_mul_col_square(linear_algebra, 128, unit1);
}

TEST(LinearAlgebraTest, ReduceLevelToMin_Matrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit = linear_algebra.make_unit(unit1_height);

    Matrix mat1 = random_mat(128, 128);

    EncryptedMatrix ct_mat1 = linear_algebra.encrypt_matrix(mat1, unit);
    EncryptedMatrix ct_mat2 = linear_algebra.encrypt_matrix(mat1, unit, 0);
    linear_algebra.reduce_level_to_min_inplace(ct_mat1, ct_mat2);
    ASSERT_EQ(ct_mat1.he_level(), 0);

    EncryptedMatrix ct_vec3 = linear_algebra.encrypt_matrix(mat1, unit);
    linear_algebra.reduce_level_to_min_inplace(ct_mat2, ct_vec3);
    ASSERT_EQ(ct_vec3.he_level(), 0);
}

TEST(LinearAlgebraTest, ReduceLevelToMin_ColVec) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit = linear_algebra.make_unit(unit1_height);

    Vector vec1 = random_vec(128);

    EncryptedColVector ct_vec1 = linear_algebra.encrypt_col_vector(vec1, unit);
    EncryptedColVector ct_vec2 = linear_algebra.encrypt_col_vector(vec1, unit, 0);
    linear_algebra.reduce_level_to_min_inplace(ct_vec1, ct_vec2);
    ASSERT_EQ(ct_vec1.he_level(), 0);

    EncryptedColVector ct_vec3 = linear_algebra.encrypt_col_vector(vec1, unit);
    linear_algebra.reduce_level_to_min_inplace(ct_vec2, ct_vec3);
    ASSERT_EQ(ct_vec3.he_level(), 0);
}

TEST(LinearAlgebraTest, ReduceLevelToMin_RowVec) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit = linear_algebra.make_unit(unit1_height);

    Vector vec1 = random_vec(128);

    EncryptedRowVector ct_vec1 = linear_algebra.encrypt_row_vector(vec1, unit);
    EncryptedRowVector ct_vec2 = linear_algebra.encrypt_row_vector(vec1, unit, 0);
    linear_algebra.reduce_level_to_min_inplace(ct_vec1, ct_vec2);
    ASSERT_EQ(ct_vec1.he_level(), 0);

    EncryptedRowVector ct_vec3 = linear_algebra.encrypt_row_vector(vec1, unit);
    linear_algebra.reduce_level_to_min_inplace(ct_vec2, ct_vec3);
    ASSERT_EQ(ct_vec3.he_level(), 0);
}

TEST(LinearAlgebraTest, ReduceLevelTo_Matrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit = linear_algebra.make_unit(unit1_height);

    Matrix mat1 = random_mat(128, 128);

    EncryptedMatrix ct_mat1 = linear_algebra.encrypt_matrix(mat1, unit);
    EncryptedMatrix ct_mat2 = linear_algebra.reduce_level_to(ct_mat1, 0);
    ASSERT_EQ(ct_mat2.he_level(), 0);
}

TEST(LinearAlgebraTest, ReduceLevelTo_ColVec) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit = linear_algebra.make_unit(unit1_height);

    Vector vec1 = random_vec(128);

    EncryptedColVector ct_vec1 = linear_algebra.encrypt_col_vector(vec1, unit);
    EncryptedColVector ct_vec2 = linear_algebra.reduce_level_to(ct_vec1, 0);
    ASSERT_EQ(ct_vec2.he_level(), 0);
}

TEST(LinearAlgebraTest, ReduceLevelTo_RowVec) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit = linear_algebra.make_unit(unit1_height);

    Vector vec1 = random_vec(128);

    EncryptedRowVector ct_vec1 = linear_algebra.encrypt_row_vector(vec1, unit);
    EncryptedRowVector ct_vec2 = linear_algebra.reduce_level_to(ct_vec1, 0);
    ASSERT_EQ(ct_vec2.he_level(), 0);
}

TEST(LinearAlgebraTest, RescaleToNext_Matrix) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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
}

TEST(LinearAlgebraTest, RescaleToNext_ColVec) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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
}

TEST(LinearAlgebraTest, RescaleToNext_RowVec) {
    HomomorphicEval ckks_instance = HomomorphicEval(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra linear_algebra = LinearAlgebra(ckks_instance);

    int unit1_height = 64;  // a 64x64 encoding unit
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
}
