// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/api/linearalgebra.h"

#include <iostream>

#include "../testutil.h"
#include "gtest/gtest.h"
#include "hit/CKKSInstance.h"
#include "hit/api/ciphertext.h"
#include "hit/common.h"
#include "hit/sealutils.h"

using namespace std;
using namespace hit;

const int max_vec_norm = 10;
const int NUM_OF_SLOTS = 4096;
const int ZERO_MULTI_DEPTH = 0;
const int ONE_MULTI_DEPTH = 1;
const int TWO_MULTI_DEPTH = 2;
const int THREE_MULTI_DEPTH = 3;
const int LOG_SCALE = 45;

Matrix random_mat(int height, int width) {
    return Matrix(height, width, randomVector(height * width, max_vec_norm));
}

Vector random_vec(int size) {
    return Vector(randomVector(size, max_vec_norm));
}

void test_encrypt_matrix(LinearAlgebra &laInst, int mat_height, int mat_width, EncodingUnit &unit) {
    Matrix plaintext = random_mat(mat_height, mat_width);
    EncryptedMatrix ciphertext = laInst.encrypt_matrix(plaintext, unit);
    Matrix output = laInst.decrypt(ciphertext);
    ASSERT_LT(diff2Norm(plaintext.data(), output.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, EncryptMatrix) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    test_encrypt_matrix(laInst, 64, 64, unit1);
    test_encrypt_matrix(laInst, 32, 32, unit1);
    test_encrypt_matrix(laInst, 60, 64, unit1);
    test_encrypt_matrix(laInst, 64, 60, unit1);
    test_encrypt_matrix(laInst, 256, 64, unit1);
    test_encrypt_matrix(laInst, 300, 64, unit1);
    test_encrypt_matrix(laInst, 300, 60, unit1);
    test_encrypt_matrix(laInst, 64, 256, unit1);
    test_encrypt_matrix(laInst, 64, 300, unit1);
    test_encrypt_matrix(laInst, 60, 300, unit1);
    test_encrypt_matrix(laInst, 128, 256, unit1);
    test_encrypt_matrix(laInst, 200, 200, unit1);
    test_encrypt_matrix(laInst, 200, 201, unit1);

    int unit2_height = 16;  // a 16x256 encoding unit
    EncodingUnit unit2 = laInst.make_unit(unit2_height);
    test_encrypt_matrix(laInst, 16, 256, unit2);
    test_encrypt_matrix(laInst, 8, 128, unit2);
    test_encrypt_matrix(laInst, 13, 256, unit2);
    test_encrypt_matrix(laInst, 16, 247, unit2);
    test_encrypt_matrix(laInst, 256, 256, unit2);
    test_encrypt_matrix(laInst, 300, 256, unit2);
    test_encrypt_matrix(laInst, 300, 247, unit2);
    test_encrypt_matrix(laInst, 16, 512, unit2);
    test_encrypt_matrix(laInst, 16, 300, unit2);
    test_encrypt_matrix(laInst, 13, 300, unit2);
    test_encrypt_matrix(laInst, 32, 512, unit2);
    test_encrypt_matrix(laInst, 200, 500, unit2);
}

void test_encrypt_row_vector(LinearAlgebra &laInst, int vec_width, EncodingUnit &unit) {
    Vector plaintext = random_vec(vec_width);
    EncryptedRowVector ciphertext = laInst.encrypt_row_vector(plaintext, unit);
    Vector output = laInst.decrypt(ciphertext);
    ASSERT_LT(diff2Norm(plaintext.data(), output.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, EncryptRowVector) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    test_encrypt_row_vector(laInst, 64, unit1);
    test_encrypt_row_vector(laInst, 32, unit1);
    test_encrypt_row_vector(laInst, 128, unit1);
    test_encrypt_row_vector(laInst, 61, unit1);
    test_encrypt_row_vector(laInst, 89, unit1);

    int unit2_height = 16;  // a 16x256 encoding unit
    EncodingUnit unit2 = laInst.make_unit(unit2_height);
    test_encrypt_row_vector(laInst, 16, unit2);
    test_encrypt_row_vector(laInst, 8, unit2);
    test_encrypt_row_vector(laInst, 10, unit2);
    test_encrypt_row_vector(laInst, 32, unit2);
    test_encrypt_row_vector(laInst, 77, unit2);
}

void test_encrypt_col_vector(LinearAlgebra &laInst, int vec_height, EncodingUnit &unit) {
    Vector plaintext = random_vec(vec_height);
    EncryptedColVector ciphertext = laInst.encrypt_col_vector(plaintext, unit);
    Vector output = laInst.decrypt(ciphertext);
    ASSERT_LT(diff2Norm(plaintext.data(), output.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, EncryptColVector) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    test_encrypt_col_vector(laInst, 64, unit1);
    test_encrypt_col_vector(laInst, 32, unit1);
    test_encrypt_col_vector(laInst, 128, unit1);
    test_encrypt_col_vector(laInst, 61, unit1);
    test_encrypt_col_vector(laInst, 89, unit1);

    int unit2_height = 16;  // a 16x256 encoding unit
    EncodingUnit unit2 = laInst.make_unit(unit2_height);
    test_encrypt_col_vector(laInst, 256, unit2);
    test_encrypt_col_vector(laInst, 128, unit2);
    test_encrypt_col_vector(laInst, 153, unit2);
    test_encrypt_col_vector(laInst, 512, unit2);
    test_encrypt_col_vector(laInst, 519, unit2);
}

TEST(LinearAlgebraTest, AddMatrixMatrix_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int unit2_height = 128;  // a 128x32 encoding unit
    EncodingUnit unit2 = laInst.make_unit(unit2_height);

    Matrix mat1 = random_mat(200, 300);
    Matrix mat2 = random_mat(200, 301);
    Matrix mat3 = random_mat(201, 300);
    EncryptedMatrix ciphertext1 = laInst.encrypt_matrix(mat1, unit1);
    EncryptedMatrix ciphertext2 = laInst.encrypt_matrix(mat2, unit1);
    EncryptedMatrix ciphertext3 = laInst.encrypt_matrix(mat3, unit1);
    EncryptedMatrix ciphertext4 = laInst.encrypt_matrix(mat1, unit2);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because widths do not match.
        (laInst.add_inplace(ciphertext1, ciphertext2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because heights do not match.
        (laInst.add_inplace(ciphertext1, ciphertext3)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (laInst.add_inplace(ciphertext1, ciphertext4)), invalid_argument);
}

TEST(LinearAlgebraTest, AddMatrixMatrix) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int height = 200;
    int width = 300;

    Matrix mat1 = random_mat(height, width);
    Matrix mat2 = random_mat(height, width);
    EncryptedMatrix ciphertext1 = laInst.encrypt_matrix(mat1, unit1);
    EncryptedMatrix ciphertext2 = laInst.encrypt_matrix(mat2, unit1);

    EncryptedMatrix ciphertext3 = laInst.add(ciphertext1, ciphertext2);
    Matrix actual_result = laInst.decrypt(ciphertext3);
    Matrix expected_result = mat1 + mat2;
    ASSERT_LT(diff2Norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddRowRow_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int unit2_height = 128;  // a 128x32 encoding unit
    EncodingUnit unit2 = laInst.make_unit(unit2_height);

    Vector vec1 = random_vec(200);
    Vector vec2 = random_vec(201);
    EncryptedRowVector ciphertext1 = laInst.encrypt_row_vector(vec1, unit1);
    EncryptedRowVector ciphertext2 = laInst.encrypt_row_vector(vec2, unit1);
    EncryptedRowVector ciphertext3 = laInst.encrypt_row_vector(vec1, unit2);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because sizes do not match.
        (laInst.add_inplace(ciphertext1, ciphertext2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (laInst.add_inplace(ciphertext1, ciphertext3)), invalid_argument);
}

TEST(LinearAlgebraTest, AddRowRow) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    Vector vec2 = random_vec(width);
    EncryptedRowVector ciphertext1 = laInst.encrypt_row_vector(vec1, unit1);
    EncryptedRowVector ciphertext2 = laInst.encrypt_row_vector(vec2, unit1);

    EncryptedRowVector ciphertext3 = laInst.add(ciphertext1, ciphertext2);
    Vector actual_result = laInst.decrypt(ciphertext3);
    Vector expected_result = vec1 + vec2;
    ASSERT_LT(diff2Norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddColCol_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int unit2_height = 128;  // a 128x32 encoding unit
    EncodingUnit unit2 = laInst.make_unit(unit2_height);

    Vector vec1 = random_vec(200);
    Vector vec2 = random_vec(201);
    EncryptedColVector ciphertext1 = laInst.encrypt_col_vector(vec1, unit1);
    EncryptedColVector ciphertext2 = laInst.encrypt_col_vector(vec2, unit1);
    EncryptedColVector ciphertext3 = laInst.encrypt_col_vector(vec1, unit2);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because sizes do not match.
        (laInst.add_inplace(ciphertext1, ciphertext2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (laInst.add_inplace(ciphertext1, ciphertext3)), invalid_argument);
}

TEST(LinearAlgebraTest, AddColCol) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    Vector vec2 = random_vec(width);
    EncryptedColVector ciphertext1 = laInst.encrypt_col_vector(vec1, unit1);
    EncryptedColVector ciphertext2 = laInst.encrypt_col_vector(vec2, unit1);

    EncryptedColVector ciphertext3 = laInst.add(ciphertext1, ciphertext2);
    Vector actual_result = laInst.decrypt(ciphertext3);
    Vector expected_result = vec1 + vec2;
    ASSERT_LT(diff2Norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddMatrixPlaintextMatrix_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);

    Matrix mat1 = random_mat(200, 300);
    Matrix mat2 = random_mat(200, 301);
    Matrix mat3 = random_mat(201, 300);
    EncryptedMatrix ciphertext1 = laInst.encrypt_matrix(mat1, unit1);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because widths do not match.
        (laInst.add_inplace(ciphertext1, mat2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because heights do not match.
        (laInst.add_inplace(ciphertext1, mat3)), invalid_argument);
}

TEST(LinearAlgebraTest, AddMatrixPlaintextMatrix) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int height = 200;
    int width = 300;

    Matrix mat1 = random_mat(height, width);
    Matrix mat2 = random_mat(height, width);
    EncryptedMatrix ciphertext1 = laInst.encrypt_matrix(mat1, unit1);

    EncryptedMatrix ciphertext3 = laInst.add(ciphertext1, mat2);
    Matrix actual_result = laInst.decrypt(ciphertext3);
    Matrix expected_result = mat1 + mat2;
    ASSERT_LT(diff2Norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddRowPlaintextRow_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);

    Vector vec1 = random_vec(200);
    Vector vec2 = random_vec(201);
    EncryptedRowVector ciphertext1 = laInst.encrypt_row_vector(vec1, unit1);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because sizes do not match.
        (laInst.add_inplace(ciphertext1, vec2)), invalid_argument);
}

TEST(LinearAlgebraTest, AddRowPlaintextRow) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    Vector vec2 = random_vec(width);
    EncryptedRowVector ciphertext1 = laInst.encrypt_row_vector(vec1, unit1);

    EncryptedRowVector ciphertext3 = laInst.add(ciphertext1, vec2);
    Vector actual_result = laInst.decrypt(ciphertext3);
    Vector expected_result = vec1 + vec2;
    ASSERT_LT(diff2Norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddColPlaintextCol_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);

    Vector vec1 = random_vec(200);
    Vector vec2 = random_vec(201);
    EncryptedColVector ciphertext1 = laInst.encrypt_col_vector(vec1, unit1);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because sizes do not match.
        (laInst.add_inplace(ciphertext1, vec2)), invalid_argument);
}

TEST(LinearAlgebraTest, AddColPlaintextCol) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    Vector vec2 = random_vec(width);
    EncryptedColVector ciphertext1 = laInst.encrypt_col_vector(vec1, unit1);

    EncryptedColVector ciphertext3 = laInst.add(ciphertext1, vec2);
    Vector actual_result = laInst.decrypt(ciphertext3);
    Vector expected_result = vec1 + vec2;
    ASSERT_LT(diff2Norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddMatrixScalar) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int height = 200;
    int width = 300;

    Matrix mat1 = random_mat(height, width);
    double scalar = 3.14;
    Matrix mat2 = Matrix(height, width, vector<double>(height * width, scalar));
    EncryptedMatrix ciphertext1 = laInst.encrypt_matrix(mat1, unit1);

    EncryptedMatrix ciphertext3 = laInst.add(ciphertext1, scalar);
    Matrix actual_result = laInst.decrypt(ciphertext3);
    Matrix expected_result = mat1 + mat2;
    ASSERT_LT(diff2Norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddRowScalar) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    double scalar = 3.14;
    Vector vec2 = Vector(vector<double>(width, scalar));
    EncryptedRowVector ciphertext1 = laInst.encrypt_row_vector(vec1, unit1);

    EncryptedRowVector ciphertext3 = laInst.add(ciphertext1, scalar);
    Vector actual_result = laInst.decrypt(ciphertext3);
    Vector expected_result = vec1 + vec2;
    ASSERT_LT(diff2Norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddColScalar) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int height = 300;

    Vector vec1 = random_vec(height);
    double scalar = 3.14;
    Vector vec2 = Vector(vector<double>(height, scalar));
    EncryptedColVector ciphertext1 = laInst.encrypt_col_vector(vec1, unit1);

    EncryptedColVector ciphertext3 = laInst.add(ciphertext1, scalar);
    Vector actual_result = laInst.decrypt(ciphertext3);
    Vector expected_result = vec1 + vec2;
    ASSERT_LT(diff2Norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddMultipleMatrix_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int unit2_height = 128;  // a 128x32 encoding unit
    EncodingUnit unit2 = laInst.make_unit(unit2_height);

    Matrix mat1 = random_mat(200, 300);
    Matrix mat2 = random_mat(200, 301);
    Matrix mat3 = random_mat(201, 300);
    EncryptedMatrix ciphertext1 = laInst.encrypt_matrix(mat1, unit1);
    EncryptedMatrix ciphertext2 = laInst.encrypt_matrix(mat2, unit1);
    EncryptedMatrix ciphertext3 = laInst.encrypt_matrix(mat3, unit1);
    EncryptedMatrix ciphertext4 = laInst.encrypt_matrix(mat1, unit2);

    vector<EncryptedMatrix> set1{ciphertext1, ciphertext2};
    vector<EncryptedMatrix> set2{ciphertext1, ciphertext3};
    vector<EncryptedMatrix> set3{ciphertext1, ciphertext4};

    ASSERT_THROW(
        // Expect invalid_argument is thrown because widths do not match.
        (laInst.add(set1)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because heights do not match.
        (laInst.add(set2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (laInst.add(set3)), invalid_argument);
}

TEST(LinearAlgebraTest, AddMultipleMatrix) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int height = 200;
    int width = 300;

    vector<EncryptedMatrix> cts;
    Matrix matrix1 = random_mat(height, width);
    cts.emplace_back(laInst.encrypt_matrix(matrix1, unit1));
    Matrix matrix2 = random_mat(height, width);
    cts.emplace_back(laInst.encrypt_matrix(matrix2, unit1));
    Matrix matrix3 = random_mat(height, width);
    cts.emplace_back(laInst.encrypt_matrix(matrix3, unit1));

    EncryptedMatrix ciphertext = laInst.add(cts);
    Matrix actual_result = laInst.decrypt(ciphertext);
    Matrix expected_result = matrix1 + matrix2 + matrix3;
    ASSERT_LT(diff2Norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddMultipleRow_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int unit2_height = 128;  // a 128x32 encoding unit
    EncodingUnit unit2 = laInst.make_unit(unit2_height);

    Vector vec1 = random_vec(200);
    Vector vec2 = random_vec(201);
    EncryptedRowVector ciphertext1 = laInst.encrypt_row_vector(vec1, unit1);
    EncryptedRowVector ciphertext2 = laInst.encrypt_row_vector(vec2, unit1);
    EncryptedRowVector ciphertext3 = laInst.encrypt_row_vector(vec1, unit2);

    vector<EncryptedRowVector> set1{ciphertext1, ciphertext2};
    vector<EncryptedRowVector> set2{ciphertext1, ciphertext3};

    ASSERT_THROW(
        // Expect invalid_argument is thrown because dimensions do not match.
        (laInst.add(set1)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because units do not match.
        (laInst.add(set2)), invalid_argument);
}

TEST(LinearAlgebraTest, AddMultipleRow) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int width = 300;

    vector<EncryptedRowVector> cts;
    Vector vec1 = random_vec(width);
    cts.emplace_back(laInst.encrypt_row_vector(vec1, unit1));
    Vector vec2 = random_vec(width);
    cts.emplace_back(laInst.encrypt_row_vector(vec2, unit1));
    Vector vec3 = random_vec(width);
    cts.emplace_back(laInst.encrypt_row_vector(vec3, unit1));

    EncryptedRowVector ciphertext = laInst.add(cts);
    Vector actual_result = laInst.decrypt(ciphertext);
    Vector expected_result = vec1 + vec2 + vec3;
    ASSERT_LT(diff2Norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, AddMultipleCol_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int unit2_height = 128;  // a 128x32 encoding unit
    EncodingUnit unit2 = laInst.make_unit(unit2_height);

    Vector vec1 = random_vec(200);
    Vector vec2 = random_vec(201);
    EncryptedColVector ciphertext1 = laInst.encrypt_col_vector(vec1, unit1);
    EncryptedColVector ciphertext2 = laInst.encrypt_col_vector(vec2, unit1);
    EncryptedColVector ciphertext3 = laInst.encrypt_col_vector(vec1, unit2);

    vector<EncryptedColVector> set1{ciphertext1, ciphertext2};
    vector<EncryptedColVector> set2{ciphertext1, ciphertext3};

    ASSERT_THROW(
        // Expect invalid_argument is thrown because dimensions do not match.
        (laInst.add(set1)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because units do not match.
        (laInst.add(set2)), invalid_argument);
}

TEST(LinearAlgebraTest, AddMultipleCol) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ZERO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int width = 300;

    vector<EncryptedColVector> cts;
    Vector vec1 = random_vec(width);
    cts.emplace_back(laInst.encrypt_col_vector(vec1, unit1));
    Vector vec2 = random_vec(width);
    cts.emplace_back(laInst.encrypt_col_vector(vec2, unit1));
    Vector vec3 = random_vec(width);
    cts.emplace_back(laInst.encrypt_col_vector(vec3, unit1));

    EncryptedColVector ciphertext = laInst.add(cts);
    Vector actual_result = laInst.decrypt(ciphertext);
    Vector expected_result = vec1 + vec2 + vec3;
    ASSERT_LT(diff2Norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, MultiplyMatrixScalar) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int height = 200;
    int width = 300;

    Matrix mat1 = random_mat(height, width);
    double scalar = 3.14;
    EncryptedMatrix ciphertext1 = laInst.encrypt_matrix(mat1, unit1);

    EncryptedMatrix ciphertext3 = laInst.multiply(ciphertext1, scalar);
    Matrix actual_result = laInst.decrypt(ciphertext3);
    Matrix expected_result = scalar * mat1;
    ASSERT_LT(diff2Norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, MultiplyRowScalar) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int width = 300;

    Vector vec1 = random_vec(width);
    double scalar = 3.14;
    EncryptedRowVector ciphertext1 = laInst.encrypt_row_vector(vec1, unit1);

    EncryptedRowVector ciphertext3 = laInst.multiply(ciphertext1, scalar);
    Vector actual_result = laInst.decrypt(ciphertext3);
    Vector expected_result = scalar * vec1;
    ASSERT_LT(diff2Norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, MultiplyColScalar) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int height = 300;

    Vector vec1 = random_vec(height);
    double scalar = 3.14;
    EncryptedColVector ciphertext1 = laInst.encrypt_col_vector(vec1, unit1);

    EncryptedColVector ciphertext3 = laInst.multiply(ciphertext1, scalar);
    Vector actual_result = laInst.decrypt(ciphertext3);
    Vector expected_result = scalar * vec1;
    ASSERT_LT(diff2Norm(actual_result.data(), expected_result.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, MultiplyMatrixMatrix_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(8192, THREE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x128 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int unit2_height = 128;  // a 128x64 encoding unit
    EncodingUnit unit2 = laInst.make_unit(unit2_height);

    Matrix mat1 = random_mat(55, 78);
    Matrix mat2 = random_mat(77, 39);
    EncryptedMatrix ciphertext1 = laInst.encrypt_matrix(mat1, unit1);
    EncryptedMatrix ciphertext2 = laInst.encrypt_matrix(mat2, unit1);
    EncryptedMatrix ciphertext3 = laInst.encrypt_matrix(mat1, unit2);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because inner dimensions do not match.
        (laInst.multiply(ciphertext1, ciphertext2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (laInst.multiply(ciphertext1, ciphertext3)), invalid_argument);
}

void test_multiply_matrix_matrix(LinearAlgebra &laInst, int left_dim, int inner_dim, int right_dim, double scalar,
                                 EncodingUnit &unit) {
    // matrix-matrix mutliplication takes A^T and B as inputs and computes c*A*B for a scalar c and matrices A, B with
    // compatible dimensions Matrix A is left_dim x inner_dim, so A^T is the reverse
    Matrix matrix_a_transpose = random_mat(inner_dim, left_dim);
    // Matrix B is inner_dim x right_dim
    Matrix matrix_b = random_mat(inner_dim, right_dim);

    EncryptedMatrix ct_a_transpose = laInst.encrypt_matrix(matrix_a_transpose, unit);
    EncryptedMatrix ct_b = laInst.encrypt_matrix(matrix_b, unit, ct_a_transpose.he_level() - 1);
    EncryptedMatrix ct_c_times_A_times_B = laInst.multiply(ct_a_transpose, ct_b, scalar);
    Matrix actual_output = laInst.decrypt(ct_c_times_A_times_B);

    // Transpose of A^T is A
    Matrix matrix_a = trans(matrix_a_transpose);
    Matrix expected_output = scalar * prec_prod(matrix_a, matrix_b);

    ASSERT_LT(diff2Norm(actual_output.data(), expected_output.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, MultiplyMatrixMatrix) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(8192, THREE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x128 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);

    double PI = 3.14;

    int unit1_width = 8192 / unit1_height;

    // both matrices are exactly the size of the encoding unit
    test_multiply_matrix_matrix(laInst, unit1_width, unit1_height, unit1_width, 1.0, unit1);
    test_multiply_matrix_matrix(laInst, unit1_width, unit1_height, unit1_width, PI, unit1);

    // one or more dimensions are are multiple of the encoding unit (no padding)
    int large_width = 2 * unit1_width;
    int large_height = 2 * unit1_height;
    test_multiply_matrix_matrix(laInst, large_width, unit1_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix(laInst, unit1_width, large_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix(laInst, unit1_width, unit1_height, large_width, PI, unit1);
    test_multiply_matrix_matrix(laInst, large_width, unit1_height, large_width, PI, unit1);
    test_multiply_matrix_matrix(laInst, unit1_width, large_height, large_width, PI, unit1);
    test_multiply_matrix_matrix(laInst, large_width, large_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix(laInst, large_width, large_height, large_width, PI, unit1);

    // one or more dimensions are larger than the encoding unit (padding required)
    large_width = unit1_width + 17;
    large_height = unit1_height + 11;
    test_multiply_matrix_matrix(laInst, large_width, unit1_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix(laInst, unit1_width, large_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix(laInst, unit1_width, unit1_height, large_width, PI, unit1);
    test_multiply_matrix_matrix(laInst, large_width, unit1_height, large_width, PI, unit1);
    test_multiply_matrix_matrix(laInst, unit1_width, large_height, large_width, PI, unit1);
    test_multiply_matrix_matrix(laInst, large_width, large_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix(laInst, large_width, large_height, large_width, PI, unit1);

    // // one or more dimensions are are fraction of the encoding unit (padding required)
    int half_width = unit1_width / 2;
    int half_height = unit1_height / 2;
    test_multiply_matrix_matrix(laInst, half_width, unit1_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix(laInst, unit1_width, half_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix(laInst, unit1_width, unit1_height, half_width, PI, unit1);
    test_multiply_matrix_matrix(laInst, half_width, unit1_height, half_width, PI, unit1);
    test_multiply_matrix_matrix(laInst, unit1_width, half_height, half_width, PI, unit1);
    test_multiply_matrix_matrix(laInst, half_width, half_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix(laInst, half_width, half_height, half_width, PI, unit1);

    // // some random dimensions
    test_multiply_matrix_matrix(laInst, 13, 78, 141, PI, unit1);
    test_multiply_matrix_matrix(laInst, 67, 17, 312, PI, unit1);
    test_multiply_matrix_matrix(laInst, 134, 134, 134, PI, unit1);
    test_multiply_matrix_matrix(laInst, 300, 27, 29, PI, unit1);
}

TEST(LinearAlgebraTest, MultiplyMatrixMatrixMixedUnit_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(8192, THREE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    // both of these units are valid for multiply_mixed_unit
    int unit1_height = 256;  // a 256x32 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int unit2_height = 128;  // a 128x64 encoding unit
    EncodingUnit unit2 = laInst.make_unit(unit2_height);

    Matrix mat1 = random_mat(17, 16);
    Matrix mat2 = random_mat(16, 16);
    EncryptedMatrix ciphertext1 = laInst.encrypt_matrix(mat1, unit1);
    EncryptedMatrix ciphertext2 = laInst.encrypt_matrix(mat2, unit1);
    EncryptedMatrix ciphertext3 = laInst.encrypt_matrix(mat1, unit2);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because inner dimensions do not match.
        (laInst.multiply_mixed_unit(ciphertext1, ciphertext2)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (laInst.multiply_mixed_unit(ciphertext1, ciphertext3)), invalid_argument);

    // Everything above here is copied from the normal matrix invalid test
    // multiply_mixed_unit has several additional invalid cases:
    // 1. n-by-m unit where m > n
    // 2. s > m
    // 3. u > m
    // 4. t > n

    int unit3_height = 64;  // a 64x128 encoding unit
    EncodingUnit unit3 = laInst.make_unit(unit3_height);
    EncryptedMatrix ciphertext4 = laInst.encrypt_matrix(mat1, unit3);
    EncryptedMatrix ciphertext5 = laInst.encrypt_matrix(mat2, unit3);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because unit3 is invalid: m > n
        (laInst.multiply_mixed_unit(ciphertext4, ciphertext5)), invalid_argument);

    Matrix mat3 = random_mat(64, 64);
    Matrix mat4 = random_mat(64, 32);
    EncryptedMatrix ciphertext6 = laInst.encrypt_matrix(mat3, unit1);
    EncryptedMatrix ciphertext7 = laInst.encrypt_matrix(mat4, unit1);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because mat3 is t-by-s=64x64, so s=64>m=32
        (laInst.multiply_mixed_unit(ciphertext6, ciphertext7)), invalid_argument);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because mat3 is t-by-u=64x64, so u=64>m=32
        (laInst.multiply_mixed_unit(ciphertext7, ciphertext6)), invalid_argument);

    Matrix mat5 = random_mat(129, 32);
    EncryptedMatrix ciphertext8 = laInst.encrypt_matrix(mat5, unit2);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because mat5 is t-by-u=129x32, so t=129>n=128
        (laInst.multiply_mixed_unit(ciphertext8, ciphertext8)), invalid_argument);
}

void test_multiply_matrix_matrix_mixed_unit(LinearAlgebra &laInst, int left_dim, int inner_dim, int right_dim,
                                            double scalar, EncodingUnit &unit) {
    // matrix-matrix mutliplication takes A^T and B as inputs and computes c*A*B for a scalar c and matrices A, B with
    // compatible dimensions Matrix A is left_dim x inner_dim, so A^T is the reverse
    Matrix matrix_a_transpose = random_mat(inner_dim, left_dim);
    // Matrix B is inner_dim x right_dim
    Matrix matrix_b = random_mat(inner_dim, right_dim);

    EncryptedMatrix ct_a_transpose = laInst.encrypt_matrix(matrix_a_transpose, unit);
    EncryptedMatrix ct_b = laInst.encrypt_matrix(matrix_b, unit, ct_a_transpose.he_level() - 1);
    EncryptedMatrix ct_c_times_A_times_B = laInst.multiply_mixed_unit(ct_a_transpose, ct_b, scalar);
    Matrix actual_output = laInst.decrypt(ct_c_times_A_times_B);

    // Transpose of A^T is A
    Matrix matrix_a = trans(matrix_a_transpose);
    Matrix expected_output = scalar * prec_prod(matrix_a, matrix_b);

    ASSERT_LT(diff2Norm(actual_output.data(), expected_output.data()), MAX_NORM);
    ASSERT_EQ(unit.encoding_height(), ct_c_times_A_times_B.encoding_unit().encoding_width());
    ASSERT_EQ(unit.encoding_width(), ct_c_times_A_times_B.encoding_unit().encoding_height());
}

TEST(LinearAlgebraTest, MultiplyMatrixMatrixMixedUnit) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(8192, THREE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 128;  // a 128x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);

    double PI = 3.14;

    int unit1_width = 8192 / unit1_height;

    // both matrices are exactly the size of the encoding unit
    test_multiply_matrix_matrix_mixed_unit(laInst, unit1_width, unit1_height, unit1_width, 1.0, unit1);
    test_multiply_matrix_matrix_mixed_unit(laInst, unit1_width, unit1_height, unit1_width, PI, unit1);

    // one or more matrices are smaller than the encoding unit
    test_multiply_matrix_matrix_mixed_unit(laInst, unit1_width - 9, unit1_height, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_mixed_unit(laInst, unit1_width, unit1_height - 9, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_mixed_unit(laInst, unit1_width, unit1_height, unit1_width - 9, PI, unit1);
    test_multiply_matrix_matrix_mixed_unit(laInst, unit1_width - 9, unit1_height, unit1_width - 11, PI, unit1);
    test_multiply_matrix_matrix_mixed_unit(laInst, unit1_width - 9, unit1_height - 11, unit1_width, PI, unit1);
    test_multiply_matrix_matrix_mixed_unit(laInst, unit1_width, unit1_height - 9, unit1_width - 11, PI, unit1);
    test_multiply_matrix_matrix_mixed_unit(laInst, unit1_width - 13, unit1_height - 9, unit1_width - 11, PI, unit1);
}

TEST(LinearAlgebraTest, MultiplyRowMatrix_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int unit2_height = 128;  // a 128x32 encoding unit
    EncodingUnit unit2 = laInst.make_unit(unit2_height);

    Vector vec1 = random_vec(13);
    Vector vec2 = random_vec(55);
    Matrix mat = random_mat(55, 78);
    EncryptedRowVector ciphertext1 = laInst.encrypt_row_vector(vec1, unit1);
    EncryptedRowVector ciphertext2 = laInst.encrypt_row_vector(vec1, unit2);
    EncryptedMatrix ciphertext3 = laInst.encrypt_matrix(mat, unit1);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because dimensions do not match.
        (laInst.multiply(ciphertext1, ciphertext3)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (laInst.multiply(ciphertext2, ciphertext3)), invalid_argument);
}

void test_multiply_row_matrix(LinearAlgebra &laInst, int left_dim, int right_dim, EncodingUnit &unit) {
    // Matrix A is left_dim x right_dim
    Vector vec = random_vec(left_dim);
    Matrix mat = random_mat(left_dim, right_dim);

    EncryptedRowVector ct_vec = laInst.encrypt_row_vector(vec, unit);
    EncryptedMatrix ct_mat = laInst.encrypt_matrix(mat, unit);
    EncryptedColVector result = laInst.multiply(ct_vec, ct_mat);
    Vector actual_output = laInst.decrypt(result);

    Vector expected_output = prec_prod(vec, mat);

    ASSERT_LT(diff2Norm(actual_output.data(), expected_output.data()), MAX_NORM);
}

// this test also covers EncryptedMatrix hadamard_multiply(const EncryptedMatrix &mat, const EncryptedColVector &vec);
TEST(LinearAlgebraTest, MultiplyRowMatrix) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);

    int unit1_width = NUM_OF_SLOTS / unit1_height;

    // both matrices are exactly the size of the encoding unit
    test_multiply_row_matrix(laInst, unit1_width, unit1_height, unit1);

    // one or more dimensions are are multiple of the encoding unit (no padding)
    int large_width = 2 * unit1_width;
    int large_height = 2 * unit1_height;
    test_multiply_row_matrix(laInst, large_width, unit1_height, unit1);
    test_multiply_row_matrix(laInst, unit1_width, large_height, unit1);
    test_multiply_row_matrix(laInst, large_width, large_height, unit1);

    // one or more dimensions are larger than the encoding unit (padding required)
    large_width = unit1_width + 17;
    large_height = unit1_height + 11;
    test_multiply_row_matrix(laInst, large_width, unit1_height, unit1);
    test_multiply_row_matrix(laInst, unit1_width, large_height, unit1);
    test_multiply_row_matrix(laInst, large_width, large_height, unit1);

    // one or more dimensions are are fraction of the encoding unit (padding required)
    int half_width = unit1_width / 2;
    int half_height = unit1_height / 2;
    test_multiply_row_matrix(laInst, half_width, unit1_height, unit1);
    test_multiply_row_matrix(laInst, unit1_width, half_height, unit1);
    test_multiply_row_matrix(laInst, half_width, half_height, unit1);

    // some random dimensions
    test_multiply_row_matrix(laInst, 13, 78, unit1);
    test_multiply_row_matrix(laInst, 67, 17, unit1);
    test_multiply_row_matrix(laInst, 134, 134, unit1);
    test_multiply_row_matrix(laInst, 300, 27, unit1);
}

TEST(LinearAlgebraTest, MultiplyMatrixCol_InvalidCase) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    int unit2_height = 128;  // a 128x32 encoding unit
    EncodingUnit unit2 = laInst.make_unit(unit2_height);

    Vector vec1 = random_vec(79);
    Vector vec2 = random_vec(78);
    Matrix mat = random_mat(55, 78);
    EncryptedColVector ciphertext1 = laInst.encrypt_col_vector(vec1, unit1);
    EncryptedColVector ciphertext2 = laInst.encrypt_col_vector(vec1, unit2);
    EncryptedMatrix ciphertext3 = laInst.encrypt_matrix(mat, unit1);

    ASSERT_THROW(
        // Expect invalid_argument is thrown because dimensions do not match.
        (laInst.multiply(ciphertext3, ciphertext1)), invalid_argument);
    ASSERT_THROW(
        // Expect invalid_argument is thrown because encoding units do not match.
        (laInst.multiply(ciphertext3, ciphertext2)), invalid_argument);
}

void test_multiply_matrix_col(LinearAlgebra &laInst, int left_dim, int right_dim, double scalar, EncodingUnit &unit) {
    // Matrix A is left_dim x right_dim
    Vector vec = random_vec(right_dim);
    Matrix mat = random_mat(left_dim, right_dim);

    EncryptedColVector ct_vec = laInst.encrypt_col_vector(vec, unit);
    EncryptedMatrix ct_mat = laInst.encrypt_matrix(mat, unit);
    EncryptedRowVector result = laInst.multiply(ct_mat, ct_vec, scalar);
    Vector actual_output = laInst.decrypt(result);

    Vector expected_output = scalar * prec_prod(mat, vec);

    ASSERT_LT(diff2Norm(actual_output.data(), expected_output.data()), MAX_NORM);
}

// this test also covers EncryptedMatrix hadamard_multiply(const EncryptedRowVector &vec, const EncryptedMatrix &mat);
TEST(LinearAlgebraTest, MultiplyMatrixCol) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(8192, TWO_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);

    int unit1_width = 8192 / unit1_height;

    double PI = 3.14;

    // both matrices are exactly the size of the encoding unit
    test_multiply_matrix_col(laInst, unit1_width, unit1_height, 1.0, unit1);
    test_multiply_matrix_col(laInst, unit1_width, unit1_height, PI, unit1);

    // one or more dimensions are are multiple of the encoding unit (no padding)
    int large_width = 2 * unit1_width;
    int large_height = 2 * unit1_height;
    test_multiply_matrix_col(laInst, large_width, unit1_height, PI, unit1);
    test_multiply_matrix_col(laInst, unit1_width, large_height, PI, unit1);
    test_multiply_matrix_col(laInst, large_width, large_height, PI, unit1);

    // one or more dimensions are larger than the encoding unit (padding required)
    large_width = unit1_width + 17;
    large_height = unit1_height + 11;
    test_multiply_matrix_col(laInst, large_width, unit1_height, PI, unit1);
    test_multiply_matrix_col(laInst, unit1_width, large_height, PI, unit1);
    test_multiply_matrix_col(laInst, large_width, large_height, PI, unit1);

    // one or more dimensions are are fraction of the encoding unit (padding required)
    int half_width = unit1_width / 2;
    int half_height = unit1_height / 2;
    test_multiply_matrix_col(laInst, half_width, unit1_height, PI, unit1);
    test_multiply_matrix_col(laInst, unit1_width, half_height, PI, unit1);
    test_multiply_matrix_col(laInst, half_width, half_height, PI, unit1);

    // some random dimensions
    test_multiply_matrix_col(laInst, 13, 78, PI, unit1);
    test_multiply_matrix_col(laInst, 67, 17, PI, unit1);
    test_multiply_matrix_col(laInst, 134, 134, PI, unit1);
    test_multiply_matrix_col(laInst, 300, 27, PI, unit1);
}

TEST(LinearAlgebraTest, ModDownToMinMatrix) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);

    Matrix mat = random_mat(64, 64);
    EncryptedMatrix ct_mat1 = laInst.encrypt_matrix(mat, unit1);
    EncryptedMatrix ct_mat0 = laInst.encrypt_matrix(mat, unit1, 0);
    ASSERT_EQ(ct_mat1.he_level(), 1);
    ASSERT_EQ(ct_mat0.he_level(), 0);
    laInst.mod_down_to_min_inplace(ct_mat1, ct_mat0);
    ASSERT_EQ(ct_mat1.he_level(), 0);

    ct_mat1 = laInst.encrypt_matrix(mat, unit1);
    ASSERT_EQ(ct_mat1.he_level(), 1);
    ASSERT_EQ(ct_mat0.he_level(), 0);
    laInst.mod_down_to_min_inplace(ct_mat0, ct_mat1);
    ASSERT_EQ(ct_mat1.he_level(), 0);
}

TEST(LinearAlgebraTest, ModDownToMinRow) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);

    Vector vec = random_vec(64);
    EncryptedRowVector ct_vec1 = laInst.encrypt_row_vector(vec, unit1);
    EncryptedRowVector ct_vec0 = laInst.encrypt_row_vector(vec, unit1, 0);
    ASSERT_EQ(ct_vec1.he_level(), 1);
    ASSERT_EQ(ct_vec0.he_level(), 0);
    laInst.mod_down_to_min_inplace(ct_vec1, ct_vec0);
    ASSERT_EQ(ct_vec1.he_level(), 0);

    ct_vec1 = laInst.encrypt_row_vector(vec, unit1);
    ASSERT_EQ(ct_vec1.he_level(), 1);
    ASSERT_EQ(ct_vec0.he_level(), 0);
    laInst.mod_down_to_min_inplace(ct_vec0, ct_vec1);
    ASSERT_EQ(ct_vec1.he_level(), 0);
}

TEST(LinearAlgebraTest, ModDownToMinCol) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);

    Vector vec = random_vec(64);
    EncryptedColVector ct_vec1 = laInst.encrypt_col_vector(vec, unit1);
    EncryptedColVector ct_vec0 = laInst.encrypt_col_vector(vec, unit1, 0);
    ASSERT_EQ(ct_vec1.he_level(), 1);
    ASSERT_EQ(ct_vec0.he_level(), 0);
    laInst.mod_down_to_min_inplace(ct_vec1, ct_vec0);
    ASSERT_EQ(ct_vec1.he_level(), 0);

    ct_vec1 = laInst.encrypt_col_vector(vec, unit1);
    ASSERT_EQ(ct_vec1.he_level(), 1);
    ASSERT_EQ(ct_vec0.he_level(), 0);
    laInst.mod_down_to_min_inplace(ct_vec0, ct_vec1);
    ASSERT_EQ(ct_vec1.he_level(), 0);
}

TEST(LinearAlgebraTest, ModDownToLevelMatrix) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);

    Matrix mat = random_mat(64, 64);
    EncryptedMatrix ct_mat1 = laInst.encrypt_matrix(mat, unit1);
    ASSERT_EQ(ct_mat1.he_level(), 1);
    laInst.mod_down_to_level_inplace(ct_mat1, 0);
    ASSERT_EQ(ct_mat1.he_level(), 0);
}

TEST(LinearAlgebraTest, ModDownToLevelRow) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);

    Vector vec = random_vec(64);
    EncryptedRowVector ct_vec1 = laInst.encrypt_row_vector(vec, unit1);
    ASSERT_EQ(ct_vec1.he_level(), 1);
    laInst.mod_down_to_level_inplace(ct_vec1, 0);
    ASSERT_EQ(ct_vec1.he_level(), 0);
}

TEST(LinearAlgebraTest, ModDownToLevelCol) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);

    Vector vec = random_vec(64);
    EncryptedColVector ct_vec1 = laInst.encrypt_col_vector(vec, unit1);
    ASSERT_EQ(ct_vec1.he_level(), 1);
    laInst.mod_down_to_level_inplace(ct_vec1, 0);
    ASSERT_EQ(ct_vec1.he_level(), 0);
}

TEST(LinearAlgebraTest, RescaleToNextMatrix) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);

    Matrix mat = random_mat(64, 64);
    EncryptedMatrix ct_mat1 = laInst.encrypt_matrix(mat, unit1);
    EncryptedMatrix ct_mat2 = laInst.multiply(ct_mat1, 3.14);

    ASSERT_EQ(pow(2, LOG_SCALE * 2), ct_mat2.scale());
    uint64_t prime = getLastPrime(ckksInstance->context, ct_mat1.he_level());
    laInst.rescale_to_next_inplace(ct_mat2);
    ASSERT_EQ(pow(2, LOG_SCALE * 2) / prime, ct_mat2.scale());
}

TEST(LinearAlgebraTest, RescaleToNextRow) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);

    Vector vec = random_vec(64);
    EncryptedRowVector ct_vec1 = laInst.encrypt_row_vector(vec, unit1);
    EncryptedRowVector ct_vec2 = laInst.multiply(ct_vec1, 3.14);

    ASSERT_EQ(pow(2, LOG_SCALE * 2), ct_vec2.scale());
    uint64_t prime = getLastPrime(ckksInstance->context, ct_vec1.he_level());
    laInst.rescale_to_next_inplace(ct_vec2);
    ASSERT_EQ(pow(2, LOG_SCALE * 2) / prime, ct_vec2.scale());
}

TEST(LinearAlgebraTest, RescaleToNextCol) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);

    Vector vec = random_vec(64);
    EncryptedColVector ct_vec1 = laInst.encrypt_col_vector(vec, unit1);
    EncryptedColVector ct_vec2 = laInst.multiply(ct_vec1, 3.14);

    ASSERT_EQ(pow(2, LOG_SCALE * 2), ct_vec2.scale());
    uint64_t prime = getLastPrime(ckksInstance->context, ct_vec1.he_level());
    laInst.rescale_to_next_inplace(ct_vec2);
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

void test_sum_rows(LinearAlgebra &laInst, int height, int width, EncodingUnit &unit) {
    Matrix mat = random_mat(height, width);
    EncryptedMatrix ct_mat = laInst.encrypt_matrix(mat, unit);
    EncryptedColVector ct_vec = laInst.sum_rows(ct_mat);
    Vector actual_output = laInst.decrypt(ct_vec);

    Vector expected_output = sum_rows_plaintext(mat);
    ASSERT_LT(diff2Norm(actual_output.data(), expected_output.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, SumRows) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    test_sum_rows(laInst, 39, 37, unit1);
    test_sum_rows(laInst, 35, 64, unit1);
    test_sum_rows(laInst, 64, 31, unit1);
    test_sum_rows(laInst, 64, 64, unit1);
    test_sum_rows(laInst, 64, 67, unit1);
    test_sum_rows(laInst, 69, 64, unit1);
    test_sum_rows(laInst, 69, 67, unit1);
    test_sum_rows(laInst, 128, 64, unit1);
    test_sum_rows(laInst, 64, 128, unit1);
    test_sum_rows(laInst, 128, 128, unit1);
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

void test_sum_cols(LinearAlgebra &laInst, int height, int width, double scalar, EncodingUnit &unit) {
    Matrix mat = random_mat(height, width);
    EncryptedMatrix ct_mat = laInst.encrypt_matrix(mat, unit);
    EncryptedRowVector ct_vec = laInst.sum_cols(ct_mat, scalar);
    Vector actual_output = laInst.decrypt(ct_vec);

    Vector expected_output = scalar * sum_cols_plaintext(mat);
    ASSERT_LT(diff2Norm(actual_output.data(), expected_output.data()), MAX_NORM);
}

TEST(LinearAlgebraTest, SumCols) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    double PI = 3.14;
    test_sum_cols(laInst, 39, 37, PI, unit1);
    test_sum_cols(laInst, 35, 64, PI, unit1);
    test_sum_cols(laInst, 64, 64, 1, unit1);
    test_sum_cols(laInst, 64, 64, PI, unit1);
    test_sum_cols(laInst, 64, 67, PI, unit1);
    test_sum_cols(laInst, 69, 64, PI, unit1);
    test_sum_cols(laInst, 69, 67, PI, unit1);
    test_sum_cols(laInst, 128, 64, PI, unit1);
    test_sum_cols(laInst, 64, 128, PI, unit1);
    test_sum_cols(laInst, 128, 128, PI, unit1);
}

void test_hadamard_mul_matrix_matrix(LinearAlgebra &laInst, int height, int width, EncodingUnit &unit) {
    Matrix mat1 = random_mat(height, width);
    Matrix mat2 = random_mat(height, width);

    vector<double> hprod_coeffs(height * width);
    for (int i = 0; i < height * width; i++) {
        hprod_coeffs[i] = mat1.data()[i] * mat2.data()[i];
    }

    EncryptedMatrix ct_mat1 = laInst.encrypt_matrix(mat1, unit);
    EncryptedMatrix ct_mat2 = laInst.encrypt_matrix(mat2, unit);

    EncryptedMatrix ct_mat3 = laInst.hadamard_multiply(ct_mat1, ct_mat2);
    Matrix actual_output = laInst.decrypt(ct_mat3);
    ASSERT_LT(diff2Norm(actual_output.data(), hprod_coeffs), MAX_NORM);
}

TEST(LinearAlgebraTest, HadamardMulMatrixMatrix) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    test_hadamard_mul_matrix_matrix(laInst, 39, 37, unit1);
    test_hadamard_mul_matrix_matrix(laInst, 35, 64, unit1);
    test_hadamard_mul_matrix_matrix(laInst, 64, 31, unit1);
    test_hadamard_mul_matrix_matrix(laInst, 64, 64, unit1);
    test_hadamard_mul_matrix_matrix(laInst, 64, 67, unit1);
    test_hadamard_mul_matrix_matrix(laInst, 69, 64, unit1);
    test_hadamard_mul_matrix_matrix(laInst, 69, 67, unit1);
    test_hadamard_mul_matrix_matrix(laInst, 128, 64, unit1);
    test_hadamard_mul_matrix_matrix(laInst, 64, 128, unit1);
    test_hadamard_mul_matrix_matrix(laInst, 128, 128, unit1);
}

void test_hadamard_mul_row_row(LinearAlgebra &laInst, int width, EncodingUnit &unit) {
    Vector vec1 = random_vec(width);
    Vector vec2 = random_vec(width);

    vector<double> hprod_coeffs(width);
    for (int i = 0; i < width; i++) {
        hprod_coeffs[i] = vec1.data()[i] * vec2.data()[i];
    }

    EncryptedRowVector ct_vec1 = laInst.encrypt_row_vector(vec1, unit);
    EncryptedRowVector ct_vec2 = laInst.encrypt_row_vector(vec2, unit);

    EncryptedRowVector ct_vec3 = laInst.hadamard_multiply(ct_vec1, ct_vec2);
    Vector actual_output = laInst.decrypt(ct_vec3);
    ASSERT_LT(diff2Norm(actual_output.data(), hprod_coeffs), MAX_NORM);
}

TEST(LinearAlgebraTest, HadamardMulRowRow) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    test_hadamard_mul_row_row(laInst, 31, unit1);
    test_hadamard_mul_row_row(laInst, 64, unit1);
    test_hadamard_mul_row_row(laInst, 69, unit1);
    test_hadamard_mul_row_row(laInst, 128, unit1);
}

void test_hadamard_mul_col_col(LinearAlgebra &laInst, int height, EncodingUnit &unit) {
    Vector vec1 = random_vec(height);
    Vector vec2 = random_vec(height);

    vector<double> hprod_coeffs(height);
    for (int i = 0; i < height; i++) {
        hprod_coeffs[i] = vec1.data()[i] * vec2.data()[i];
    }

    EncryptedColVector ct_vec1 = laInst.encrypt_col_vector(vec1, unit);
    EncryptedColVector ct_vec2 = laInst.encrypt_col_vector(vec2, unit);

    EncryptedColVector ct_vec3 = laInst.hadamard_multiply(ct_vec1, ct_vec2);
    Vector actual_output = laInst.decrypt(ct_vec3);
    ASSERT_LT(diff2Norm(actual_output.data(), hprod_coeffs), MAX_NORM);
}

TEST(LinearAlgebraTest, HadamardMulColCol) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    test_hadamard_mul_col_col(laInst, 31, unit1);
    test_hadamard_mul_col_col(laInst, 64, unit1);
    test_hadamard_mul_col_col(laInst, 69, unit1);
    test_hadamard_mul_col_col(laInst, 128, unit1);
}

void test_hadamard_mul_matrix_square(LinearAlgebra &laInst, int height, int width, EncodingUnit &unit) {
    Matrix mat1 = random_mat(height, width);

    vector<double> hprod_coeffs(height * width);
    for (int i = 0; i < height * width; i++) {
        hprod_coeffs[i] = mat1.data()[i] * mat1.data()[i];
    }

    EncryptedMatrix ct_mat1 = laInst.encrypt_matrix(mat1, unit);
    EncryptedMatrix ct_mat3 = laInst.hadamard_square(ct_mat1);
    Matrix actual_output = laInst.decrypt(ct_mat3);
    ASSERT_LT(diff2Norm(actual_output.data(), hprod_coeffs), MAX_NORM);
}

TEST(LinearAlgebraTest, HadamardMulMatrixSquare) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    test_hadamard_mul_matrix_square(laInst, 39, 37, unit1);
    test_hadamard_mul_matrix_square(laInst, 35, 64, unit1);
    test_hadamard_mul_matrix_square(laInst, 64, 31, unit1);
    test_hadamard_mul_matrix_square(laInst, 64, 64, unit1);
    test_hadamard_mul_matrix_square(laInst, 64, 67, unit1);
    test_hadamard_mul_matrix_square(laInst, 69, 64, unit1);
    test_hadamard_mul_matrix_square(laInst, 69, 67, unit1);
    test_hadamard_mul_matrix_square(laInst, 128, 64, unit1);
    test_hadamard_mul_matrix_square(laInst, 64, 128, unit1);
    test_hadamard_mul_matrix_square(laInst, 128, 128, unit1);
}

void test_hadamard_mul_row_square(LinearAlgebra &laInst, int width, EncodingUnit &unit) {
    Vector vec1 = random_vec(width);

    vector<double> hprod_coeffs(width);
    for (int i = 0; i < width; i++) {
        hprod_coeffs[i] = vec1.data()[i] * vec1.data()[i];
    }

    EncryptedRowVector ct_vec1 = laInst.encrypt_row_vector(vec1, unit);
    EncryptedRowVector ct_vec3 = laInst.hadamard_square(ct_vec1);
    Vector actual_output = laInst.decrypt(ct_vec3);
    ASSERT_LT(diff2Norm(actual_output.data(), hprod_coeffs), MAX_NORM);
}

TEST(LinearAlgebraTest, HadamardMulRowSquare) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    test_hadamard_mul_row_square(laInst, 31, unit1);
    test_hadamard_mul_row_square(laInst, 64, unit1);
    test_hadamard_mul_row_square(laInst, 69, unit1);
    test_hadamard_mul_row_square(laInst, 128, unit1);
}

void test_hadamard_mul_col_square(LinearAlgebra &laInst, int height, EncodingUnit &unit) {
    Vector vec1 = random_vec(height);

    vector<double> hprod_coeffs(height);
    for (int i = 0; i < height; i++) {
        hprod_coeffs[i] = vec1.data()[i] * vec1.data()[i];
    }

    EncryptedColVector ct_vec1 = laInst.encrypt_col_vector(vec1, unit);

    EncryptedColVector ct_vec3 = laInst.hadamard_square(ct_vec1);
    Vector actual_output = laInst.decrypt(ct_vec3);
    ASSERT_LT(diff2Norm(actual_output.data(), hprod_coeffs), MAX_NORM);
}

TEST(LinearAlgebraTest, HadamardMulColSquare) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit1 = laInst.make_unit(unit1_height);
    test_hadamard_mul_col_square(laInst, 31, unit1);
    test_hadamard_mul_col_square(laInst, 64, unit1);
    test_hadamard_mul_col_square(laInst, 69, unit1);
    test_hadamard_mul_col_square(laInst, 128, unit1);
}

TEST(LinearAlgebraTest, ModDownToMin_Matrix) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit = laInst.make_unit(unit1_height);

    Matrix mat1 = random_mat(128, 128);

    EncryptedMatrix ct_mat1 = laInst.encrypt_matrix(mat1, unit);
    EncryptedMatrix ct_mat2 = laInst.encrypt_matrix(mat1, unit, 0);
    laInst.mod_down_to_min_inplace(ct_mat1, ct_mat2);
    ASSERT_EQ(ct_mat1.he_level(), 0);

    EncryptedMatrix ct_vec3 = laInst.encrypt_matrix(mat1, unit);
    laInst.mod_down_to_min_inplace(ct_mat2, ct_vec3);
    ASSERT_EQ(ct_vec3.he_level(), 0);
}

TEST(LinearAlgebraTest, ModDownToMin_ColVec) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit = laInst.make_unit(unit1_height);

    Vector vec1 = random_vec(128);

    EncryptedColVector ct_vec1 = laInst.encrypt_col_vector(vec1, unit);
    EncryptedColVector ct_vec2 = laInst.encrypt_col_vector(vec1, unit, 0);
    laInst.mod_down_to_min_inplace(ct_vec1, ct_vec2);
    ASSERT_EQ(ct_vec1.he_level(), 0);

    EncryptedColVector ct_vec3 = laInst.encrypt_col_vector(vec1, unit);
    laInst.mod_down_to_min_inplace(ct_vec2, ct_vec3);
    ASSERT_EQ(ct_vec3.he_level(), 0);
}

TEST(LinearAlgebraTest, ModDownToMin_RowVec) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit = laInst.make_unit(unit1_height);

    Vector vec1 = random_vec(128);

    EncryptedRowVector ct_vec1 = laInst.encrypt_row_vector(vec1, unit);
    EncryptedRowVector ct_vec2 = laInst.encrypt_row_vector(vec1, unit, 0);
    laInst.mod_down_to_min_inplace(ct_vec1, ct_vec2);
    ASSERT_EQ(ct_vec1.he_level(), 0);

    EncryptedRowVector ct_vec3 = laInst.encrypt_row_vector(vec1, unit);
    laInst.mod_down_to_min_inplace(ct_vec2, ct_vec3);
    ASSERT_EQ(ct_vec3.he_level(), 0);
}

TEST(LinearAlgebraTest, ModDownToLevel_Matrix) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit = laInst.make_unit(unit1_height);

    Matrix mat1 = random_mat(128, 128);

    EncryptedMatrix ct_mat1 = laInst.encrypt_matrix(mat1, unit);
    EncryptedMatrix ct_mat2 = laInst.mod_down_to_level(ct_mat1, 0);
    ASSERT_EQ(ct_mat2.he_level(), 0);
}

TEST(LinearAlgebraTest, ModDownToLevel_ColVec) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit = laInst.make_unit(unit1_height);

    Vector vec1 = random_vec(128);

    EncryptedColVector ct_vec1 = laInst.encrypt_col_vector(vec1, unit);
    EncryptedColVector ct_vec2 = laInst.mod_down_to_level(ct_vec1, 0);
    ASSERT_EQ(ct_vec2.he_level(), 0);
}

TEST(LinearAlgebraTest, ModDownToLevel_RowVec) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit = laInst.make_unit(unit1_height);

    Vector vec1 = random_vec(128);

    EncryptedRowVector ct_vec1 = laInst.encrypt_row_vector(vec1, unit);
    EncryptedRowVector ct_vec2 = laInst.mod_down_to_level(ct_vec1, 0);
    ASSERT_EQ(ct_vec2.he_level(), 0);
}

TEST(LinearAlgebraTest, RescaleToNext_Matrix) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit = laInst.make_unit(unit1_height);

    Matrix mat1 = random_mat(128, 128);

    EncryptedMatrix ct_mat1 = laInst.encrypt_matrix(mat1, unit);
    ASSERT_EQ(ct_mat1.scale(), pow(2, LOG_SCALE));
    laInst.multiply_inplace(ct_mat1, 2);
    ASSERT_EQ(ct_mat1.scale(), pow(2, 2 * LOG_SCALE));
    ASSERT_EQ(ct_mat1.he_level(), 1);
    laInst.rescale_to_next_inplace(ct_mat1);
    ASSERT_EQ(ct_mat1.he_level(), 0);
    uint64_t prime = getLastPrime(ckksInstance->context, 1);
    ASSERT_EQ(ct_mat1.scale(), pow(2, 2 * LOG_SCALE) / prime);
}

TEST(LinearAlgebraTest, RescaleToNext_ColVec) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit = laInst.make_unit(unit1_height);

    Vector vec1 = random_vec(128);

    EncryptedColVector ct_vec1 = laInst.encrypt_col_vector(vec1, unit);
    ASSERT_EQ(ct_vec1.scale(), pow(2, LOG_SCALE));
    laInst.multiply_inplace(ct_vec1, 2);
    ASSERT_EQ(ct_vec1.scale(), pow(2, 2 * LOG_SCALE));
    ASSERT_EQ(ct_vec1.he_level(), 1);
    laInst.rescale_to_next_inplace(ct_vec1);
    ASSERT_EQ(ct_vec1.he_level(), 0);
    uint64_t prime = getLastPrime(ckksInstance->context, 1);
    ASSERT_EQ(ct_vec1.scale(), pow(2, 2 * LOG_SCALE) / prime);
}

TEST(LinearAlgebraTest, RescaleToNext_RowVec) {
    CKKSInstance *ckksInstance = CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, ONE_MULTI_DEPTH, LOG_SCALE);
    LinearAlgebra laInst = LinearAlgebra(*ckksInstance);

    int unit1_height = 64;  // a 64x64 encoding unit
    EncodingUnit unit = laInst.make_unit(unit1_height);

    Vector vec1 = random_vec(128);

    EncryptedRowVector ct_vec1 = laInst.encrypt_row_vector(vec1, unit);
    ASSERT_EQ(ct_vec1.scale(), pow(2, LOG_SCALE));
    laInst.multiply_inplace(ct_vec1, 2);
    ASSERT_EQ(ct_vec1.scale(), pow(2, 2 * LOG_SCALE));
    ASSERT_EQ(ct_vec1.he_level(), 1);
    laInst.rescale_to_next_inplace(ct_vec1);
    ASSERT_EQ(ct_vec1.he_level(), 0);
    uint64_t prime = getLastPrime(ckksInstance->context, 1);
    ASSERT_EQ(ct_vec1.scale(), pow(2, 2 * LOG_SCALE) / prime);
}
