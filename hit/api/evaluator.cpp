// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* This file offers default implementation for most functions in the
 * CKKSEvaluator interface.
 */

#include "evaluator.h"
#include "../common.h"

using namespace std;
using namespace seal;

CKKSEvaluator::CKKSEvaluator(const std::shared_ptr<seal::SEALContext> context, bool verbose): context(context), verbose(verbose) { }

CKKSEvaluator::~CKKSEvaluator() = default;

void CKKSEvaluator::reset() {
  reset_internal();
}

bool CKKSEvaluator::is_valid_args(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) const {
  if((ct1.encoding == ct2.encoding) ||
     (ct1.encoding == ROW_MAT && ct2.encoding == MATRIX) ||
     (ct1.encoding == MATRIX && ct2.encoding == COL_MAT)) {
    return ((ct1.encoded_height == ct2.encoded_height) &&
            (ct1.encoded_width  == ct2.encoded_width ) &&
            (ct1.height == ct2.height) &&
            (ct1.width  == ct2.width ));
  }
  else {
    return ((ct1.encoded_height == ct2.encoded_height) &&
            (ct1.encoded_width  == ct2.encoded_width ) &&
            (ct1.width == ct2.height));
  }
}

CKKSCiphertext CKKSEvaluator::rotate_vector_right(const CKKSCiphertext &encrypted, int steps) {
  if(steps < 0) {
    throw invalid_argument("ERROR: rotate_vector_right must have a positive number of steps.");
  }
  VERBOSE(cout << "Rotate rows " << abs(steps) << " steps right." << endl);
  CKKSCiphertext temp = rotate_vector_right_internal(encrypted, steps);
  return temp;
}

CKKSCiphertext CKKSEvaluator::rotate_vector_left(const CKKSCiphertext &encrypted, int steps) {
  if(steps < 0) {
    throw invalid_argument("ERROR: rotate_vector_left must have a positive number of steps.");
  }
  VERBOSE(cout << "Rotate rows " << abs(steps) << " steps left." << endl);
  CKKSCiphertext temp = rotate_vector_left_internal(encrypted, steps);
  return temp;
}

CKKSCiphertext CKKSEvaluator::add_plain_scalar(const CKKSCiphertext &encrypted, double plain) {
  VERBOSE(cout << "Add scalar " << plain << " to ciphertext" << endl);
  CKKSCiphertext temp = add_plain_scalar_internal(encrypted, plain);
  return temp;
}

CKKSCiphertext CKKSEvaluator::add(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) {
  // it's a lot easier to validate combinations of args if they are in a canonical order. These two
  // statements put row vectors in the first arg, and col vectors in the second arg, which mirrors how
  // this would look on paper.
  if(encrypted1.encoding == MATRIX && encrypted2.encoding == ROW_MAT) {
    return add(encrypted2, encrypted1);
  }
  if(encrypted1.encoding == COL_MAT && encrypted2.encoding == MATRIX) {
    return add(encrypted2, encrypted1);
  }

  VERBOSE(cout << "Add ciphertexts" << endl);

  CKKSCiphertext temp = add_internal(encrypted1, encrypted2);

  // combining a ROW_MAT and a MATRIX only makes sense in make-believe linear algebra, like the type used
  // for PPLR training. It doesn't correspond to a real linear-algebra operation because we need this
  // capability for the component-wise application of the sigmoid approximation to a vector.
  if(encrypted1.encoding == ROW_MAT && encrypted2.encoding == MATRIX && is_valid_args(encrypted1, encrypted2)) {
    temp.encoding = ROW_MAT;
    temp.width = encrypted2.width;
    temp.encoded_width = encrypted2.width;
    temp.height = encrypted2.height;
    temp.encoded_height = encrypted2.height;
  }
  else if(encrypted1.encoding == MATRIX && encrypted2.encoding == COL_MAT && is_valid_args(encrypted1, encrypted2)) {
    temp.encoding = COL_MAT;
    temp.width = encrypted1.width;
    temp.encoded_width = encrypted1.width;
    temp.height = encrypted1.height;
    temp.encoded_height = encrypted1.height;
  }
  // we can always add standard linear alegbra objects of the same type, like adding two matrices or vectors
  // in this case, the dimensions don't change
  // note that adding COL_MATs makes sense if we consider breaking a matrix into several vertical chunks,
  // and the vector into corresponding pieces. Then instead of A*b, we view A as [A_1 | A_2] and b as <b_1 | b_2>.
  // Then we can compute A*b=A_1*b_1+A_2*b_2, and similarly for ROW_MATs.
  else if(encrypted1.encoding == encrypted2.encoding && is_valid_args(encrypted1, encrypted2)) { }
  else {
    cout << "Arg 1: Encoding(" << encrypted1.encoding << "), Dimensions: " << encrypted1.height << "x" << encrypted1.width << ", Embedded dimensions: " << encrypted1.encoded_height << "x" << encrypted1.encoded_width << endl;
    cout << "Arg 2: Encoding(" << encrypted2.encoding << "), Dimensions: " << encrypted2.height << "x" << encrypted2.width << ", Embedded dimensions: " << encrypted2.encoded_height << "x" << encrypted2.encoded_width << endl;
    throw invalid_argument("PPLR ERROR: cannot add arguments.");
  }

  return temp;
}

CKKSCiphertext CKKSEvaluator::multiply_plain_scalar(const CKKSCiphertext &encrypted, double plain) {
  VERBOSE(cout << "Multiply ciphertext by scalar " << plain << endl);
  CKKSCiphertext temp = multiply_plain_scalar_internal(encrypted, plain);
  return temp;
}

CKKSCiphertext CKKSEvaluator::multiply_plain_mat(const CKKSCiphertext &encrypted, const vector<double> &plain) {
  VERBOSE(cout << "Multiply by non-scalar plaintext" << endl);
  if(encrypted.encoded_width*encrypted.encoded_height != plain.size()) {
    throw invalid_argument("CKKSEvaluator::multiply_plain_mat: encoded size does not match plaintext input");
  }
  CKKSCiphertext temp = multiply_plain_mat_internal(encrypted, plain);
  return temp;
}

CKKSCiphertext CKKSEvaluator::multiply(const CKKSCiphertext &encrypted1, const CKKSCiphertext &encrypted2) {
  // it's a lot easier to validate combinations of args if they are in a canonical order. These two
  // statements put row vectors in the first arg, and col vectors in the second arg, which mirrors how
  // this would look on paper.
  if((encrypted1.encoding == ROW_MAT || encrypted1.encoding == MATRIX) && encrypted2.encoding == ROW_VEC) {
    return multiply(encrypted2, encrypted1);
  }
  if(encrypted1.encoding == COL_VEC && (encrypted2.encoding == COL_MAT || encrypted2.encoding == MATRIX)) {
    return multiply(encrypted2, encrypted1);
  }

  VERBOSE(cout << "Multiply ciphertexts" << endl);

  CKKSCiphertext temp = multiply_internal(encrypted1, encrypted2);

  // we can multiply a row vector by either a row matrix or a pure matrix. In the first case, this is \vec(a)*(\vec(b)*C),
  // which is equivalent to (\vec(a)*\vec(b))*C, a row vector times a pure matrix. The second case is simply the first
  // step in an HE row-matrix-times-vector-product.
  // We want the output in either case to be a ROW_MAT with the same dimensions as the input matrix/row matrix
  if(encrypted1.encoding == ROW_VEC && (encrypted2.encoding == ROW_MAT || encrypted2.encoding == MATRIX) && is_valid_args(encrypted1, encrypted2)) {
    temp.encoding = ROW_MAT;
    temp.width = encrypted2.width;
    temp.encoded_width = encrypted2.width;
    temp.height = encrypted2.height;
    temp.encoded_height = encrypted2.height;
  }
  // similarly for column vectors/matrices: we can multiply a COL_MAT or a MATRIX times a column vector
  else if((encrypted1.encoding == COL_MAT || encrypted1.encoding == MATRIX) && encrypted2.encoding == COL_VEC && is_valid_args(encrypted1, encrypted2)) {
    temp.encoding = COL_MAT;
    temp.width = encrypted1.width;
    temp.encoded_width = encrypted1.width;
    temp.height = encrypted1.height;
    temp.encoded_height = encrypted1.height;
  }
  // we can always multiply vectors together (componentwise)
  else if(encrypted1.encoding == COL_VEC && encrypted2.encoding == COL_VEC && is_valid_args(encrypted1, encrypted2)) { }
  else if(encrypted1.encoding == ROW_VEC && encrypted2.encoding == ROW_VEC && is_valid_args(encrypted1, encrypted2)) { }
  else {
    cout << "Arg 1: Encoding(" << encrypted1.encoding << "), Dimensions: " << encrypted1.height << "x" << encrypted1.width << ", Embedded dimensions: " << encrypted1.encoded_height << "x" << encrypted1.encoded_width << endl;
    cout << "Arg 2: Encoding(" << encrypted2.encoding << "), Dimensions: " << encrypted2.height << "x" << encrypted2.width << ", Embedded dimensions: " << encrypted2.encoded_height << "x" << encrypted2.encoded_width << endl;
    throw invalid_argument("PPLR ERROR: cannot multiply arguments.");
  }

  return temp;
}

CKKSCiphertext CKKSEvaluator::square(const CKKSCiphertext &ciphertext) {
  VERBOSE(cout << "Square ciphertext" << endl);
  CKKSCiphertext temp = square_internal(ciphertext);
  return temp;
}

void CKKSEvaluator::modDownTo(CKKSCiphertext &x, const CKKSCiphertext &target) {
  VERBOSE(cout << "Decreasing HE level to match target" << endl);
  modDownTo_internal(x, target);
}

void CKKSEvaluator::modDownToMin(CKKSCiphertext &x, CKKSCiphertext &y) {
  VERBOSE(cout << "Equalizing HE levels" << endl);
  modDownToMin_internal(x, y);
}

CKKSCiphertext CKKSEvaluator::modDownToLevel(const CKKSCiphertext &x, int level) {
  VERBOSE(cout << "Decreasing HE level to " << level << endl);
  return modDownToLevel_internal(x, level);
}

void CKKSEvaluator::rescale_to_next_inplace(CKKSCiphertext &encrypted) {
  VERBOSE(cout << "Rescaling ciphertext" << endl);
  rescale_to_next_inplace_internal(encrypted);
}

void CKKSEvaluator::relinearize_inplace(CKKSCiphertext &encrypted) {
  VERBOSE(cout << "Relinearizing ciphertext" << endl);
  relinearize_inplace_internal(encrypted);
}

ContextDataPtr CKKSEvaluator::getContextData(const CKKSCiphertext &c) {
  // get the context_data for this ciphertext level
  // but do not use the ciphertext itself! Use the heLevel,
  // in case we are not doing ciphertext computations
  auto context_data = context->first_context_data();
  while (context_data->chain_index() > c.heLevel) {
    // Step forward in the chain.
    context_data = context_data->next_context_data();
  }
  return context_data;
}
