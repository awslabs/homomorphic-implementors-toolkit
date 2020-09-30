// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/hit.h"

using namespace std;
using namespace hit;

// defined in example_1_ckks.cpp
extern vector<double> randomVector(int dim, double maxNorm);

/* This example explores HIT's API for linear algebra operations
 * on encrypted data. This API is an implementation of <TODO link to paper>.
 * This example explains the concepts behind algorithm to encode linear algebra
 * objects (like vectors and matrices) into CKKS ciphertexts, and demonstrates
 * how to use this API.
 */
void example_4_driver() {
	int num_slots = 8192;
	int max_depth = 3;
	int log_scale = 40;

	// Start by creating one of the basic HIT instances.
	DebugEval dbg_inst = DebugEval(num_slots, max_depth, log_scale);
	// We then create a LinearAlgebra wrapper around this instance
	LinearAlgebra la_inst = LinearAlgebra(dbg_inst);

/* ******** Encoding Units ********
 * A fundamental concept for the the linear algebra toolkit proposed in [Crockett20] is
 * the *encoding unit*. An encoding unit is like a two-dimensional sliding window with which
 * we tile a linear algebra object. Each encoding unit has exactly as many coefficients as
 * a CKKS plaintext, so a  linear algebra object may be encoded as many
 * encoding units/plaintexts. HIT hides all of this complexity
 * from the user; you get to treat an encrypted matrix as a single object.
 * We will describe how to map linear algebra objects to encoding units in a moment, but
 * for now let's consider how to turn an encoding unit (a two-dimensional shape) into a
 * CKKS plaintext (a one-dimensional list).
 * Assume CKKS parameters have eight slots. We encode the encoding unit as a plaintext in
 * row-major form, so the unit
 * [ 1 2 3 4 ]
 * [ 5 6 7 8 ]
 * becomes the plaintext [1 2 3 4 5 6 7 8].
 * As the programmer, you don't have to worry about think about how the encoding works, but carefully choosing
 * an encoding unit can affect the efficiency of the implementation. The depth of all of the linear algebra
 * operations is independent of the encoding unit used to encode an object, but the number of operations
 * is not. Therefore, the encoding unit can affect the efficiency of homomorphic operations.
 * We explore this more below.
 */
	// We can create encoding units by specifying their height. Their width is
	// implied by the number of plaintext slots. The height must be a power of two.
	// Our first unit has height 64, and therefore width num_slots/64=128.
	EncodingUnit unit_64x128 = la_inst.make_unit(64);
	// We can create another unit of size 256x32=8192
	EncodingUnit unit_256x32 = la_inst.make_unit(256);

/* ******** Matrices ********
 * Matrices are encoded by tiling the matrix with the chosen encoding unit. The result is a two-dimensional
 * grid of plaintexts representing the matrix. If the matrix dimensions do not exactly divide into encoding
 * units, extra space is padded with zeros. For example, consider the plaintext matrix A where
 *
 * A = [ a b c d e ]
 *     [ f g h i j ]
 *     [ k l m n o ]
 *     [ p q r s t ]
 *
 * We can tile A with a 2x4 unit to get four plaintext units, and
 * therefore four ciphertexts:
 *
 *   cts[0][0]    cts[0][1]
 *  [ a b c d ]  [ e 0 0 0 ]
 *  [ f g h i ]  [ j 0 0 0 ]
 *
 *   cts[1][0]    cts[1][1]
 *  [ k l m n ]  [ o 0 0 0 ]
 *  [ p q r s ]  [ t 0 0 0 ]
 *
 * If we instead use a 4x2 unit, we divide A into three plaintext units,
 * and therefore three ciphertexts:
 *
 *  cts[0][0]  cts[0][1]  cts[0][2]
 *  [ a b ]    [ c d ]    [ e 0 ]
 *  [ f g ]    [ h i ]    [ j 0 ]
 *  [ k l ]    [ m n ]    [ k 0 ]
 *  [ p q ]    [ r s ]    [ t 0 ]
 */
	// Let's create a 150x300 matrix
	int plaintext_inf_norm = 10;
	int mat_height = 150;
	int mat_width = 300;
	vector<double> mat_data = randomVector(mat_height*mat_width, plaintext_inf_norm);
	Matrix mat = Matrix(mat_height, mat_width, mat_data);

	// We can now encrypt this matrix with respect to both units
	EncryptedMatrix enc_mat1 = la_inst.encrypt(mat, unit_64x128);
	// The ciphertext knows the plaintext's original height and width.
	cout << "enc_mat1 has dimension " << enc_mat1.height() << "x" << enc_mat1.width() << endl;
	// We can also see how many encoding units it took to tile this matrix in each direction
	cout << "enc_mat1 is encoded as a " << enc_mat1.num_vertical_units() << "x"
	     << enc_mat1.num_horizontal_units() << " grid of encoding units." << endl;
	// Even though an EncryptedMatrix may be composed of several ciphertexts, HIT keeps
	// these individual ciphertext properties consistent, so we ask for the ciphertext
	// properties of the encrypted matrix as a whole:
	cout << "enc_mat1 is encrypted at level " << enc_mat1.he_level()
	     << ", and has a scale of " << log2(enc_mat1.scale()) << " bits" << endl;

	// We can now repeat with the other encoding unit
	// This time, rather than encrypting at the default level (3, since it is the maximum
	// level allowed by the parameters), we will encrypt at a lower level.
	EncryptedMatrix enc_mat2 = la_inst.encrypt(mat, unit_256x32, 2);
	// Even though we used a different encoding unit, the matrix dimensions are unchanged
	cout << "enc_mat2 has dimension " << enc_mat2.height() << "x" << enc_mat2.width() << endl;
	// but the encoding unit grid has changed size.
	// We can also see how many encoding units it took to tile this matrix in each direction
	cout << "enc_mat2 is encoded as a " << enc_mat2.num_vertical_units() << "x"
	     << enc_mat2.num_horizontal_units() << " grid of encoding units." << endl;

	// Finally, because we built this LinearAlgebra instance on the debug instance type,
	// we can obtain the plaintext matrix (decoded to an object the same size as the input)
	Matrix recovered_mat = enc_mat2.plaintext();
	cout << "The plaintext inside enc_mat2 has dimension " << recovered_mat.size1() << "x"
	     << recovered_mat.size2() << endl;

/* ******** Row Vectors ********
 * We encode a row vector as *columns* of an encoding unit. First, we transpose the row
 * vector to get a column vector, then tile an encoding unit vertically, again padding any
 * leftover space with zeros. We then *replicate* the vector horizontally for each column
 * of the encoding unit, so that each column is identical. For example, consider the
 * row vector v where
 *
 * v = [ a b c d e ]
 *
 * We can tile v with a 2x4 unit to get three plaintext units, and
 * therefore three ciphertexts:
 *
 *     cts[0]
 *  [ a a a a ]
 *  [ b b b b ]
 *
 *     cts[1]
 *  [ c c c c ]
 *  [ d d d d ]
 *
 *     cts[2]
 *  [ e e e e ]
 *  [ 0 0 0 0 ]
 *
 * If we instead use a 4x2 unit, we divide v into two plaintext units,
 * and therefore two ciphertexts:
 *
 *   cts[0]
 *  [ a a ]
 *  [ b b ]
 *  [ c c ]
 *  [ d d ]
 *
 *   cts[1]
 *  [ e e ]
 *  [ 0 0 ]
 *  [ 0 0 ]
 *  [ 0 0 ]
 *
 * Rather than resulting in a grid of encoding units, row vectors are encoded as a
 * one-dimenisonal list of units.
 */
	// Let's create a 150-dimensional vector
	int rvec_size = 150;
	vector<double> rvec_data = randomVector(rvec_size, plaintext_inf_norm);
	Vector rvec = Vector(rvec_data);

	// We can now encrypt this row vector with respect to one of the units
	EncryptedRowVector enc_rvec = la_inst.encrypt<EncryptedRowVector>(rvec, unit_64x128);
	// The ciphertext knows the plaintext's original width.
	cout << "enc_rvec has dimension " << enc_rvec.width() << endl;
	// We can also see how many encoding units it took to tile this vector
	cout << "enc_rvec is encoded with " << enc_rvec.num_units() << " encoding units." << endl;
	// Even though an EncryptedRowVector may be composed of several ciphertexts, HIT keeps
	// these individual ciphertext properties consistent, so we ask for the ciphertext
	// properties of the encrypted row vector as a whole:
	cout << "enc_rvec is encrypted at level " << enc_rvec.he_level()
	     << ", and has a scale of " << log2(enc_rvec.scale()) << " bits" << endl;

	// Finally, because we built this LinearAlgebra instance on the debug instance type,
	// we can obtain the plaintext row vector (decoded to an object the same size as the input)
	Vector recovered_rvec = enc_rvec.plaintext();
	cout << "The plaintext inside enc_rvec has dimension " << recovered_rvec.size() << endl;

/* ******** Column Vectors ********
 * We encode a column vector as *rows* of an encoding unit. First, we transpose the column
 * vector to get a row vector, then tile an encoding unit horizontally, again padding any
 * leftover space with zeros. We then *replicate* the vector vertically for each row
 * of the encoding unit, so that each row is identical. For example, consider the
 * column vector v where
 *
 *     [ a ]
 *     [ b ]
 * v = [ c ]
 *     [ d ]
 *     [ e ]
 *
 * We can tile v with a 2x4 unit to get two plaintext units, and
 * therefore two ciphertexts:
 *
 *     cts[0]       cts[1]
 *  [ a b c d ]  [ e 0 0 0 ]
 *  [ a b c d ]  [ e 0 0 0 ]
 *
 * If we instead use a 4x2 unit, we divide v into three plaintext units,
 * and therefore three ciphertexts:
 *
 *   cts[0]     cts[1]     cts[2]
 *  [ a b ]    [ c d ]    [ e 0 ]
 *  [ a b ]    [ c d ]    [ e 0 ]
 *  [ a b ]    [ c d ]    [ e 0 ]
 *  [ a b ]    [ c d ]    [ e 0 ]
 *
 * Like the encoding for row vectors, column vectors are encoded as a
 * one-dimenisonal list of units.
 */
	// Let's create a 300-dimensional vector
	int cvec_size = 300;
	vector<double> cvec_data = randomVector(cvec_size, plaintext_inf_norm);
	Vector cvec = Vector(cvec_data);

	// We can now encrypt a column vector with respect to one of the units
	EncryptedColVector enc_cvec = la_inst.encrypt<EncryptedColVector>(cvec, unit_64x128);
	// The ciphertext knows the plaintext's original height.
	cout << "enc_cvec has dimension " << enc_cvec.height() << endl;
	// We can also see how many encoding units it took to tile this vector
	cout << "enc_cvec is encoded with " << enc_cvec.num_units() << " encoding units." << endl;
	// Even though an EncryptedColVector may be composed of several ciphertexts, HIT keeps
	// these individual ciphertext properties consistent, so we ask for the ciphertext
	// properties of the encrypted row vector as a whole:
	cout << "enc_cvec is encrypted at level " << enc_cvec.he_level()
	     << ", and has a scale of " << log2(enc_cvec.scale()) << " bits" << endl;

	// Finally, because we built this LinearAlgebra instance on the debug instance type,
	// we can obtain the plaintext row vector (decoded to an object the same size as the input)
	Vector recovered_cvec = enc_cvec.plaintext();
	cout << "The plaintext inside enc_cvec has dimension " << recovered_cvec.size() << endl;

/* ******** Linear Algebra Operations ********
 * HIT's linear algebra API hides the complexity of this encoding so users
 * can just think about the plaintext object. The API provides standard linear algebra
 * operations like adding two matrices or two vectors (one of which may be public),
 * multiplying by a public scalar, and matrix/vector multiplication.
 * The API also includes some functions which don't correspond to classic linear
 * algebra operations, like adding a constant to each component of a matrix or vector,
 * ciphertext maintenance operations, `sum_rows`, and `sum_cols`. We'll explore these
 * last two operations below. The ciphertext maintance operations work just like
 * the operations for ciphertexts, except the API automatically applies them to
 * each encoding unit of an encoded object.
 */

/* ******** Matrix/Vector Multiplication ********
 * HIT's linear algebra API includes the ability to multiply a matrix with a column
 * vector or a row vector and a matrix.
 */
	// Recall that `enc_mat1` encrypts a 150x300 matrix with a 64x128 encoding unit,
	// `enc_cvec` encrypts a 300-dimensional column vector with the same unit, and
	// `enc_rvec` encrypts a 150-dimensional row vector, also with the same unit.

	// First, let's use the convenience function to compute the matrix/column-vector
	// product. As described above, the output is a row vector rather than a column
	// vector.
	EncryptedRowVector mat_cvec_prod1 = la_inst.multiply(enc_mat1, enc_cvec);
	// This type of product returns "a linear ciphertext with a squared scale at level i-1."
	// Let's verify that:
	cout << "Ciphertext metadata for matrix/col-vec multiplication:" << endl;
	cout << "  Expected scale of ~" << 2*log_scale << " bits, the product has a scale of ~" << log2(mat_cvec_prod1.scale()) << " bits" << endl;
	cout << "  Expected product level to be " << enc_mat1.he_level()-1 << "; actual level is " << mat_cvec_prod1.he_level() << endl;

	// Similarly, a row-vector times a matrix results in a column vector:
	EncryptedColVector rvec_mat_prod1 = la_inst.multiply(enc_rvec, enc_mat1);
	// A linear ciphertext with a nominal scale at level i-1.
	cout << "Ciphertext metadata for row-vec/matrix multiplication:" << endl;
	cout << "  Expected scale of ~" << log_scale << " bits, the product has a scale of ~" << log2(rvec_mat_prod1.scale()) << " bits" << endl;
	cout << "  Expected product level to be " << enc_mat1.he_level()-1 << "; actual level is " << rvec_mat_prod1.he_level() << endl;

/* That was easy! However, these operations are complex enough that it is sometimes
 * advantageous to break them down into multiple homomorphic operations rather than
 * using the convenience functions. Let's dive into the homomorphic matrix/vector
 * multiplication algorithm. The first step is to compute the Hadamard product
 * between the matrix and the encoded vector. Consider the following matrix and
 * column vector:
 *
 *  A = [ a b c d ]    v = [ 2 ]
 *      [ e f g h ]        [ 3 ]
 *                         [ 4 ]
 *                         [ 5 ]
 *
 * These are encoded with a 2x4 unit as:
 *
 *  A = [ a b c d ]    v = [ 2 3 4 5 ]
 *      [ e f g h ]        [ 2 3 4 5 ]
 *
 * and their Hadamard product (denoted by ⚬) is
 *
 * A⚬v = [ 2a 3b 4c 5d ]
 *       [ 2e 3f 4g 5h ]
 *
 * The standard product A*v can be achieved by summing the columns of A⚬v.
 * However, we seek an *encoding* of the product. This turns out to be
 * difficult to do; an easier task is to find an encoding of the *transpose*
 * of the standard product. We do this with the special `sum_cols` operation,
 * which sums the columns of a matrix, and then replicates that sum in every
 * column. Thus:
 *
 *  sum_cols(A⚬v) = [ 2a+3b+4c+5d  2a+3b+4c+5d  2a+3b+4c+5d  2a+3b+4c+5d ]
 *                  [ 2e+3f+4g+5h  2e+3f+4g+5h  2e+3f+4g+5h  2e+3f+4g+5h ]
 *
 * Note that this is an encoding of the _row_ vector
 *
 * (A*v)^T = [ 2a+3b+4c+5d  2e+3f+4g+5h ]
 *
 * HIT's linear algebra API provides a simple API for easily computing products
 * (as we demonstrated above), but it also exposes these lower-level operations
 * which are useful when creating optimized linear algebra circuits.
 */

	// We can compute the same products as above, but in two steps
	// The output of a Hadamard product is always a matrix
	EncryptedMatrix mat_cvec_hprod = la_inst.hadamard_multiply(enc_mat1, enc_cvec);
	// need to relinearize and rescale after a Hadamard multiplication
	la_inst.relinearize_inplace(mat_cvec_hprod);
	la_inst.rescale_to_next_inplace(mat_cvec_hprod);
	EncryptedRowVector mat_cvec_prod2 = la_inst.sum_cols(mat_cvec_hprod);
	// This encrypts the same value as mat_cvec_prod1
	// We used a debug instance, so we can compare the plaintexts:
	cout << "Matrix/column-vector alternate computation works if "
	     << relative_error(mat_cvec_prod1.plaintext(), mat_cvec_prod2.plaintext())
	     << " is small." << endl;

	// For the row-vector/matrix product, the idea is similar, but we use `sum_rows`
	// instead:
	EncryptedMatrix rvec_mat_hprod = la_inst.hadamard_multiply(enc_rvec, enc_mat1);
	la_inst.relinearize_inplace(rvec_mat_hprod);
	la_inst.rescale_to_next_inplace(rvec_mat_hprod);
	EncryptedColVector rvec_mat_prod2 = la_inst.sum_rows(rvec_mat_hprod);
	// This encrypts the same value as rvec_mat_prod1
	// To demonstrate all of our options, we'll decrypt for this comparison
	// Note that the norm will be larger due to the error caused by homomorphic operations
	// and the CKKS encoding process.
	cout << "Row-vector/Matrix alternate computation works if "
	     << relative_error(la_inst.decrypt(rvec_mat_prod1), la_inst.decrypt(rvec_mat_prod2))
	     << " is small." << endl;

/* Why would we ever want to use this more tedious API? `sum_rows` and `sum_cols`
 * are relatively expensive operations, but we can frequently reduce the number
 * of invocations to these operations by exploiting their structure as linear maps.
 * This means that for two matrices A and B which have the same dimensions and a
 * constant c,
 *        sum_cols(A) + sum_cols(B) = sum_cols(A+B), and
 *        c*sum_cols(A) = sum_cols(c*A)
 * (and likewise for `sum_rows`). However, we can even go one step farther and
 * extend this linear map to objects which we can't directly add. Consider the
 * following two matrices:
 *
 * A = [ 1 2 3 4 ]      B = [ 1 2 ]
 *     [ 5 6 7 8 ]          [ 3 4 ]
 *
 * It makes sense to add `sum_cols(A)` and `sum_cols(B)` since both are 2-dimensional
 * row vectors (remember that `sum_cols` results in a row instead of a column).
 * However, it seems like this *requires* two invocations of `sum_cols`. But
 *       sum_cols(A) + sum_cols(B) = sum_cols(A | B)
 * where | denotes concatenation, so we can still use the linear map to reduce the
 * number of calls to `sum_cols` as long as the arguments have the same number of rows!
 * The same is true for `sum_rows`, as long as the arguments have the same number of
 * columns. This functionality is captured by `sum_rows_many` and `sum_cols_many`.
 */

/* ******** Matrix/Matrix Multiplication ********
 * Finally, we'll cover matrix-matrix multiplication. As with matrix/vector
 * multiplication, the homomorphic algorithm has a "twist": to compute the product
 * A*B, we need to provide encryptions of A^T and B. While this operation has
 * multiplicative depth 3 regardless of the matrix dimensions, the number of overall
 * multiplications involved *does* depend on the matrix dimensions. It's important
 * to consider this when choosing to use this operation, since multiplying larger
 * matrices involves many expensive operations, even on highly parallel hardware.
 */
	// Recall that `enc_mat1` encrypts a 150x300 matrix with a 64x128 encoding unit
	// Call this matrix B. Now let's make a 20x150 matrix A, and homomorphically
	// compute 2*A*B.
    vector<double> mat_data_a = randomVector(20*150, plaintext_inf_norm);
	Matrix mat_a = Matrix(20, 150, mat_data);

	// To compute the homomorphic product A*B, we actually need to encrypt A^T
	EncryptedMatrix enc_mat_a_trans = la_inst.encrypt(trans(mat_a), unit_64x128);

	// Some operations allow us to throw in a free constant multiplication,
	// so we'll do that here
	// We also need enc_mat_a_trans at level >= 3, which it is since we
	// created the evaluator with max_depth 3. However, `enc_mat1` must be at
	// level 2, so we will first reduce its level.
	la_inst.reduce_level_to_inplace(enc_mat1, enc_mat_a_trans.he_level()-1);
	EncryptedMatrix mat_prod_ab = la_inst.multiply(enc_mat_a_trans, enc_mat1, 2);
	// A linear ciphertext with a squared scale, so let's rescale:
	la_inst.rescale_to_next_inplace(mat_prod_ab);

	// Use boost to compute the plaintext matrix product
	Matrix expected_result = prec_prod(mat_a, mat);
	// Look at the plaintext product using the homomorphic algorithm
	Matrix actual_result_plaintext = mat_prod_ab.plaintext();
	// We can also decrypt the result to see what happened on ciphertexts
	Matrix actual_result_homomorphic = la_inst.decrypt(mat_prod_ab);

	cout << "Matrix/Matrix plaintext algorithm is correct if "
	     << relative_error(expected_result, actual_result_plaintext)
	     << " is small." << endl;

	cout << "Matrix/Matrix homomorphic algorithm is correct if "
	     << relative_error(expected_result, actual_result_homomorphic)
	     << " is small." << endl;
}
