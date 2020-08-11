// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* This file offers default implementation for most functions in the
 * CKKSEvaluator interface.
 */

#include "evaluator.h"

#include <utility>
#include "../common.h"

CKKSEvaluator::CKKSEvaluator(std::shared_ptr<seal::SEALContext> context, bool verbose): context(std::move(context)), verbose(verbose) { }

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
  return ((ct1.encoded_height == ct2.encoded_height) &&
            (ct1.encoded_width  == ct2.encoded_width ) &&
            (ct1.width == ct2.height));
}

CKKSCiphertext CKKSEvaluator::rotate_vector_right(const CKKSCiphertext &ct, int steps) {
  if(steps < 0) {
    throw std::invalid_argument("ERROR: rotate_vector_right must have a positive number of steps.");
  }
  VERBOSE(std::cout << "Rotate rows " << abs(steps) << " steps right." << std::endl);
  CKKSCiphertext temp = rotate_vector_right_internal(ct, steps);
  return temp;
}

CKKSCiphertext CKKSEvaluator::rotate_vector_left(const CKKSCiphertext &ct, int steps) {
  if(steps < 0) {
    throw std::invalid_argument("ERROR: rotate_vector_left must have a positive number of steps.");
  }
  VERBOSE(std::cout << "Rotate rows " << abs(steps) << " steps left." << std::endl);
  CKKSCiphertext temp = rotate_vector_left_internal(ct, steps);
  return temp;
}

CKKSCiphertext CKKSEvaluator::add_plain_scalar(const CKKSCiphertext &ct, double scalar) {
  VERBOSE(std::cout << "Add scalar " << scalar << " to ciphertext" << std::endl);
  CKKSCiphertext temp = add_plain_scalar_internal(ct, scalar);
  return temp;
}

CKKSCiphertext CKKSEvaluator::add(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
  // it's a lot easier to validate combinations of args if they are in a canonical order. These two
  // statements put row vectors in the first arg, and col vectors in the second arg, which mirrors how
  // this would look on paper.
  if(ct1.encoding == MATRIX && ct2.encoding == ROW_MAT) {
    return add(ct2, ct1);
  }
  if(ct1.encoding == COL_MAT && ct2.encoding == MATRIX) {
    return add(ct2, ct1);
  }

  VERBOSE(std::cout << "Add ciphertexts" << std::endl);

  CKKSCiphertext temp = add_internal(ct1, ct2);

  // combining a ROW_MAT and a MATRIX only makes sense in make-believe linear algebra, like the type used
  // for PPLR training. It doesn't correspond to a real linear-algebra operation because we need this
  // capability for the component-wise application of the sigmoid approximation to a std::vector.
  if(ct1.encoding == ROW_MAT && ct2.encoding == MATRIX && is_valid_args(ct1, ct2)) {
    temp.encoding = ROW_MAT;
    temp.width = ct2.width;
    temp.encoded_width = ct2.width;
    temp.height = ct2.height;
    temp.encoded_height = ct2.height;
  }
  else if(ct1.encoding == MATRIX && ct2.encoding == COL_MAT && is_valid_args(ct1, ct2)) {
    temp.encoding = COL_MAT;
    temp.width = ct1.width;
    temp.encoded_width = ct1.width;
    temp.height = ct1.height;
    temp.encoded_height = ct1.height;
  }
  // we can always add standard linear alegbra objects of the same type, like adding two matrices or vectors
  // in this case, the dimensions don't change
  // note that adding COL_MATs makes sense if we consider breaking a matrix into several vertical chunks,
  // and the std::vector into corresponding pieces. Then instead of A*b, we view A as [A_1 | A_2] and b as <b_1 | b_2>.
  // Then we can compute A*b=A_1*b_1+A_2*b_2, and similarly for ROW_MATs.
  else if(ct1.encoding == ct2.encoding && is_valid_args(ct1, ct2)) { }
  else {
    std::cout << "Arg 1: Encoding(" << ct1.encoding << "), Dimensions: " << ct1.height << "x" << ct1.width << ", Embedded dimensions: " << ct1.encoded_height << "x" << ct1.encoded_width << std::endl;
    std::cout << "Arg 2: Encoding(" << ct2.encoding << "), Dimensions: " << ct2.height << "x" << ct2.width << ", Embedded dimensions: " << ct2.encoded_height << "x" << ct2.encoded_width << std::endl;
    throw std::invalid_argument("PPLR ERROR: cannot add arguments.");
  }

  return temp;
}

CKKSCiphertext CKKSEvaluator::multiply_plain_scalar(const CKKSCiphertext &ct, double scalar) {
  VERBOSE(std::cout << "Multiply ciphertext by scalar " << scalar << std::endl);
  CKKSCiphertext temp = multiply_plain_scalar_internal(ct, scalar);
  return temp;
}

CKKSCiphertext CKKSEvaluator::multiply_plain_mat(const CKKSCiphertext &ct, const std::vector<double> &plain) {
  VERBOSE(std::cout << "Multiply by non-scalar plaintext" << std::endl);
  if(ct.encoded_width*ct.encoded_height != plain.size()) {
    throw std::invalid_argument("CKKSEvaluator::multiply_plain_mat: encoded size does not match plaintext input");
  }
  CKKSCiphertext temp = multiply_plain_mat_internal(ct, plain);
  return temp;
}

CKKSCiphertext CKKSEvaluator::multiply(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
  // it's a lot easier to validate combinations of args if they are in a canonical order. These two
  // statements put row vectors in the first arg, and col vectors in the second arg, which mirrors how
  // this would look on paper.
  if((ct1.encoding == ROW_MAT || ct1.encoding == MATRIX) && ct2.encoding == ROW_VEC) {
    return multiply(ct2, ct1);
  }
  if(ct1.encoding == COL_VEC && (ct2.encoding == COL_MAT || ct2.encoding == MATRIX)) {
    return multiply(ct2, ct1);
  }

  VERBOSE(std::cout << "Multiply ciphertexts" << std::endl);

  CKKSCiphertext temp = multiply_internal(ct1, ct2);

  // we can multiply a row std::vector by either a row matrix or a pure matrix. In the first case, this is \vec(a)*(\vec(b)*C),
  // which is equivalent to (\vec(a)*\vec(b))*C, a row std::vector times a pure matrix. The second case is simply the first
  // step in an HE row-matrix-times-std::vector-product.
  // We want the output in either case to be a ROW_MAT with the same dimensions as the input matrix/row matrix
  if(ct1.encoding == ROW_VEC && (ct2.encoding == ROW_MAT || ct2.encoding == MATRIX) && is_valid_args(ct1, ct2)) {
    temp.encoding = ROW_MAT;
    temp.width = ct2.width;
    temp.encoded_width = ct2.width;
    temp.height = ct2.height;
    temp.encoded_height = ct2.height;
  }
  // similarly for column vectors/matrices: we can multiply a COL_MAT or a MATRIX times a column std::vector
  else if((ct1.encoding == COL_MAT || ct1.encoding == MATRIX) && ct2.encoding == COL_VEC && is_valid_args(ct1, ct2)) {
    temp.encoding = COL_MAT;
    temp.width = ct1.width;
    temp.encoded_width = ct1.width;
    temp.height = ct1.height;
    temp.encoded_height = ct1.height;
  }
  // we can always multiply vectors together (componentwise)
  else if(ct1.encoding == COL_VEC && ct2.encoding == COL_VEC && is_valid_args(ct1, ct2)) { }
  else if(ct1.encoding == ROW_VEC && ct2.encoding == ROW_VEC && is_valid_args(ct1, ct2)) { }
  else {
    std::cout << "Arg 1: Encoding(" << ct1.encoding << "), Dimensions: " << ct1.height << "x" << ct1.width << ", Embedded dimensions: " << ct1.encoded_height << "x" << ct1.encoded_width << std::endl;
    std::cout << "Arg 2: Encoding(" << ct2.encoding << "), Dimensions: " << ct2.height << "x" << ct2.width << ", Embedded dimensions: " << ct2.encoded_height << "x" << ct2.encoded_width << std::endl;
    throw std::invalid_argument("PPLR ERROR: cannot multiply arguments.");
  }

  return temp;
}

CKKSCiphertext CKKSEvaluator::square(const CKKSCiphertext &ct) {
  VERBOSE(std::cout << "Square ciphertext" << std::endl);
  CKKSCiphertext temp = square_internal(ct);
  return temp;
}

void CKKSEvaluator::modDownTo(CKKSCiphertext &ct, const CKKSCiphertext &target) {
  VERBOSE(std::cout << "Decreasing HE level to match target" << std::endl);
  modDownTo_internal(ct, target);
}

void CKKSEvaluator::modDownToMin(CKKSCiphertext &ct1, CKKSCiphertext &ct2) {
  VERBOSE(std::cout << "Equalizing HE levels" << std::endl);
  modDownToMin_internal(ct1, ct2);
}

CKKSCiphertext CKKSEvaluator::modDownToLevel(const CKKSCiphertext &ct, int level) {
  VERBOSE(std::cout << "Decreasing HE level to " << level << std::endl);
  return modDownToLevel_internal(ct, level);
}

void CKKSEvaluator::rescale_to_next_inplace(CKKSCiphertext &ct) {
  VERBOSE(std::cout << "Rescaling ciphertext" << std::endl);
  rescale_to_next_inplace_internal(ct);
}

void CKKSEvaluator::relinearize_inplace(CKKSCiphertext &ct) {
  VERBOSE(std::cout << "Relinearizing ciphertext" << std::endl);
  relinearize_inplace_internal(ct);
}

ContextDataPtr CKKSEvaluator::getContextData(const CKKSCiphertext &c) {
  // get the context_data for this ciphertext level
  // but do not use the ciphertext itself! Use the he_level,
  // in case we are not doing ciphertext computations
  auto context_data = context->first_context_data();
  while (context_data->chain_index() > c.he_level) {
    // Step forward in the chain.
    context_data = context_data->next_context_data();
  }
  return context_data;
}
