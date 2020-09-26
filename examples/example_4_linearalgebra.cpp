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
	int vec_size = 150;
	vector<double> vec_data = randomVector(vec_size, plaintext_inf_norm);
	Vector vec = Vector(vec_data);

	// We can now encrypt this row vector with respect to one of the units
	EncryptedRowVector enc_rvec = la_inst.encrypt<EncryptedRowVector>(vec, unit_64x128);
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
	// We can now encrypt a column vector with respect to one of the units
	EncryptedColVector enc_cvec = la_inst.encrypt<EncryptedColVector>(vec, unit_64x128);
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
}
