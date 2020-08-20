// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* This file offers default implementation for most functions in the
 * CKKSEvaluator interface.
 */

#include "evaluator.h"

#include <utility>

#include "../common.h"

using namespace std;
using namespace seal;

namespace hit {

    CKKSEvaluator::CKKSEvaluator(shared_ptr<SEALContext> context, bool verbose)
        : context(move(context)), verbose(verbose) {
    }

    CKKSEvaluator::~CKKSEvaluator() = default;

    void CKKSEvaluator::reset() {
        reset_internal();
    }

    bool is_valid_args(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        if ((ct1.encoding == ct2.encoding) || (ct1.encoding == ROW_MAT && ct2.encoding == MATRIX) ||
            (ct1.encoding == MATRIX && ct2.encoding == COL_MAT)) {
            return ((ct1.encoded_height == ct2.encoded_height) && (ct1.encoded_width == ct2.encoded_width) &&
                    (ct1.height == ct2.height) && (ct1.width == ct2.width));
        }
        return ((ct1.encoded_height == ct2.encoded_height) && (ct1.encoded_width == ct2.encoded_width) &&
<<<<<<< HEAD
                (ct1.width == ct2.height));
    }

    CKKSCiphertext CKKSEvaluator::rotate_right(const CKKSCiphertext &ct, int steps) {
        CKKSCiphertext output = ct;
        rotate_right_inplace(output, steps);
        return output;
    }

    void CKKSEvaluator::rotate_right_inplace(CKKSCiphertext &ct, int steps) {
        if (steps < 0) {
            throw invalid_argument("ERROR: rotate_right must have a positive number of steps.");
        }
        VERBOSE(cout << "Rotate " << abs(steps) << " steps right." << endl);
        rotate_right_inplace_internal(ct, steps);
    }

    CKKSCiphertext CKKSEvaluator::rotate_left(const CKKSCiphertext &ct, int steps) {
        CKKSCiphertext output = ct;
        rotate_left_inplace(output, steps);
        return output;
    }

    void CKKSEvaluator::rotate_left_inplace(CKKSCiphertext &ct, int steps) {
        if (steps < 0) {
            throw invalid_argument("ERROR: rotate_left must have a positive number of steps.");
        }
        VERBOSE(cout << "Rotate " << abs(steps) << " steps left." << endl);
        rotate_left_inplace_internal(ct, steps);
    }

    CKKSCiphertext CKKSEvaluator::negate(const CKKSCiphertext &ct) {
        CKKSCiphertext output = ct;
        negate_inplace(output);
        return output;
    }

    void CKKSEvaluator::negate_inplace(CKKSCiphertext &ct) {
        VERBOSE(cout << "Negate" << endl);
        negate_inplace_internal(ct);
    }

    CKKSCiphertext CKKSEvaluator::add(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // it's a lot easier to validate combinations of args if they are in a canonical order. These two
        // statements put row vectors in the first arg, and col vectors in the second arg, which mirrors how
        // this would look on paper.
        if (ct1.encoding == MATRIX && ct2.encoding == ROW_MAT) {
            return add(ct2, ct1);
        }
        if (ct1.encoding == COL_MAT && ct2.encoding == MATRIX) {
            return add(ct2, ct1);
        }

        VERBOSE(cout << "Add ciphertexts" << endl);

        CKKSCiphertext temp = ct1;
        add_inplace_internal(temp, ct2);

        // combining a ROW_MAT and a MATRIX only makes sense in make-believe linear algebra, like the type used
        // for PPLR training. It doesn't correspond to a real linear-algebra operation because we need this
        // capability for the component-wise application of the sigmoid approximation to a vector.
        if (ct1.encoding == ROW_MAT && ct2.encoding == MATRIX && is_valid_args(ct1, ct2)) {
            temp.encoding = ROW_MAT;
            temp.width = ct2.width;
            temp.encoded_width = ct2.width;
            temp.height = ct2.height;
            temp.encoded_height = ct2.height;
        } else if (ct1.encoding == MATRIX && ct2.encoding == COL_MAT && is_valid_args(ct1, ct2)) {
            temp.encoding = COL_MAT;
            temp.width = ct1.width;
            temp.encoded_width = ct1.width;
            temp.height = ct1.height;
            temp.encoded_height = ct1.height;
        }
        // we can always add standard linear alegbra objects of the same type, like adding two matrices or vectors
        // in this case, the dimensions don't change
        // note that adding COL_MATs makes sense if we consider breaking a matrix into several vertical chunks,
        // and the vector into corresponding pieces. Then instead of A*b, we view A as [A_1 | A_2] and b as <b_1 | b_2>.
        // Then we can compute A*b=A_1*b_1+A_2*b_2, and similarly for ROW_MATs.
        else if (ct1.encoding == ct2.encoding && is_valid_args(ct1, ct2)) {
        } else {
            cout << "Arg 1: Encoding(" << ct1.encoding << "), Dimensions: " << ct1.height << "x" << ct1.width
                 << ", Embedded dimensions: " << ct1.encoded_height << "x" << ct1.encoded_width << endl;
            cout << "Arg 2: Encoding(" << ct2.encoding << "), Dimensions: " << ct2.height << "x" << ct2.width
                 << ", Embedded dimensions: " << ct2.encoded_height << "x" << ct2.encoded_width << endl;
            throw invalid_argument("PPLR ERROR: cannot add arguments.");
        }

        return temp;
    }

    void CKKSEvaluator::add_inplace(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        ct1 = add(ct1, ct2);
    }

    CKKSCiphertext CKKSEvaluator::add_plain(const CKKSCiphertext &ct, double scalar) {
        CKKSCiphertext output = ct;
        add_plain_inplace(output, scalar);
        return output;
    }

    void CKKSEvaluator::add_plain_inplace(CKKSCiphertext &ct, double scalar) {
        VERBOSE(cout << "Add scalar " << scalar << " to ciphertext" << endl);
        add_plain_inplace_internal(ct, scalar);
    }

    CKKSCiphertext CKKSEvaluator::add_plain(const CKKSCiphertext &ct, const vector<double> &plain) {
        CKKSCiphertext output = ct;
        add_plain_inplace(output, plain);
        return output;
    }

    void CKKSEvaluator::add_plain_inplace(CKKSCiphertext &ct, const vector<double> &plain) {
        VERBOSE(cout << "Add plaintext to ciphertext" << endl);
        return add_plain_inplace_internal(ct, plain);
    }

    CKKSCiphertext CKKSEvaluator::add_many(vector<CKKSCiphertext> &cts) {
        if(cts.empty()) {
            throw invalid_argument("add_many: vector may not be empty.");
        }

        CKKSCiphertext dest = cts[0];
        for (int i = 1; i < cts.size(); i++) {
            add_inplace(dest, cts[i]);
        }
        return dest;
    }

    CKKSCiphertext CKKSEvaluator::sub(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // it's a lot easier to validate combinations of args if they are in a canonical order. These two
        // statements put row vectors in the first arg, and col vectors in the second arg, which mirrors how
        // this would look on paper.
        if (ct1.encoding == MATRIX && ct2.encoding == ROW_MAT) {
            return sub(ct2, ct1);
        }
        if (ct1.encoding == COL_MAT && ct2.encoding == MATRIX) {
            return sub(ct2, ct1);
        }

        VERBOSE(cout << "Subtract ciphertexts" << endl);

        CKKSCiphertext temp = ct1;
        sub_inplace_internal(temp, ct2);

        // combining a ROW_MAT and a MATRIX only makes sense in make-believe linear algebra, like the type used
        // for PPLR training. It doesn't correspond to a real linear-algebra operation because we need this
        // capability for the component-wise application of the sigmoid approximation to a vector.
        if (ct1.encoding == ROW_MAT && ct2.encoding == MATRIX && is_valid_args(ct1, ct2)) {
            temp.encoding = ROW_MAT;
            temp.width = ct2.width;
            temp.encoded_width = ct2.width;
            temp.height = ct2.height;
            temp.encoded_height = ct2.height;
        } else if (ct1.encoding == MATRIX && ct2.encoding == COL_MAT && is_valid_args(ct1, ct2)) {
            temp.encoding = COL_MAT;
            temp.width = ct1.width;
            temp.encoded_width = ct1.width;
            temp.height = ct1.height;
            temp.encoded_height = ct1.height;
        }
        // we can always subtract standard linear alegbra objects of the same type, like adding two matrices or vectors
        // in this case, the dimensions don't change
        // note that adding COL_MATs makes sense if we consider breaking a matrix into several vertical chunks,
        // and the vector into corresponding pieces. Then instead of A*b, we view A as [A_1 | A_2] and b as <b_1 | b_2>.
        // Then we can compute A*b=A_1*b_1+A_2*b_2, and similarly for ROW_MATs.
        else if (ct1.encoding == ct2.encoding && is_valid_args(ct1, ct2)) {
        } else {
            cout << "Arg 1: Encoding(" << ct1.encoding << "), Dimensions: " << ct1.height << "x" << ct1.width
                 << ", Embedded dimensions: " << ct1.encoded_height << "x" << ct1.encoded_width << endl;
            cout << "Arg 2: Encoding(" << ct2.encoding << "), Dimensions: " << ct2.height << "x" << ct2.width
                 << ", Embedded dimensions: " << ct2.encoded_height << "x" << ct2.encoded_width << endl;
            throw invalid_argument("PPLR ERROR: cannot subtract arguments.");
        }

        return temp;
    }

    void CKKSEvaluator::sub_inplace(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        ct1 = sub(ct1, ct2);
    }

    CKKSCiphertext CKKSEvaluator::sub_plain(const CKKSCiphertext &ct, double scalar) {
        CKKSCiphertext output = ct;
        sub_plain_inplace(output, scalar);
        return output;
    }

    void CKKSEvaluator::sub_plain_inplace(CKKSCiphertext &ct, double scalar) {
        VERBOSE(cout << "Subtract scalar " << scalar << " from ciphertext" << endl);
        sub_plain_inplace_internal(ct, scalar);
    }

    CKKSCiphertext CKKSEvaluator::sub_plain(const CKKSCiphertext &ct, const vector<double> &plain) {
        CKKSCiphertext output = ct;
        sub_plain_inplace(output, plain);
        return output;
    }

    void CKKSEvaluator::sub_plain_inplace(CKKSCiphertext &ct, const vector<double> &plain) {
        VERBOSE(cout << "Subtract plaintext from ciphertext" << endl);
        sub_plain_inplace_internal(ct, plain);
    }

    CKKSCiphertext CKKSEvaluator::multiply(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        // it's a lot easier to validate combinations of args if they are in a canonical order. These two
        // statements put row vectors in the first arg, and col vectors in the second arg, which mirrors how
        // this would look on paper.
        if ((ct1.encoding == ROW_MAT || ct1.encoding == MATRIX) && ct2.encoding == ROW_VEC) {
            return multiply(ct2, ct1);
        }
        if (ct1.encoding == COL_VEC && (ct2.encoding == COL_MAT || ct2.encoding == MATRIX)) {
            return multiply(ct2, ct1);
        }

        VERBOSE(cout << "Multiply ciphertexts" << endl);

        CKKSCiphertext temp = ct1;
        multiply_inplace_internal(temp, ct2);

        // we can multiply a row vector by either a row matrix or a pure matrix. In the first case, this is
        // \vec(a)*(\vec(b)*C), which is equivalent to (\vec(a)*\vec(b))*C, a row vector times a pure matrix. The second
        // case is simply the first step in an HE row-matrix-times-vector-product. We want the output in either case to
        // be a ROW_MAT with the same dimensions as the input matrix/row matrix
        if (ct1.encoding == ROW_VEC && (ct2.encoding == ROW_MAT || ct2.encoding == MATRIX) && is_valid_args(ct1, ct2)) {
            temp.encoding = ROW_MAT;
            temp.width = ct2.width;
            temp.encoded_width = ct2.width;
            temp.height = ct2.height;
            temp.encoded_height = ct2.height;
        }
        // similarly for column vectors/matrices: we can multiply a COL_MAT or a MATRIX times a column vector
        else if ((ct1.encoding == COL_MAT || ct1.encoding == MATRIX) && ct2.encoding == COL_VEC &&
                 is_valid_args(ct1, ct2)) {
            temp.encoding = COL_MAT;
            temp.width = ct1.width;
            temp.encoded_width = ct1.width;
            temp.height = ct1.height;
            temp.encoded_height = ct1.height;
        }
        // we can always multiply vectors together (componentwise)
        else if (ct1.encoding == COL_VEC && ct2.encoding == COL_VEC && is_valid_args(ct1, ct2)) {
        } else if (ct1.encoding == ROW_VEC && ct2.encoding == ROW_VEC && is_valid_args(ct1, ct2)) {
        } else {
            cout << "Arg 1: Encoding(" << ct1.encoding << "), Dimensions: " << ct1.height << "x" << ct1.width
                 << ", Embedded dimensions: " << ct1.encoded_height << "x" << ct1.encoded_width << endl;
            cout << "Arg 2: Encoding(" << ct2.encoding << "), Dimensions: " << ct2.height << "x" << ct2.width
                 << ", Embedded dimensions: " << ct2.encoded_height << "x" << ct2.encoded_width << endl;
            throw invalid_argument("PPLR ERROR: cannot multiply arguments.");
        }

        return temp;
    }

    void CKKSEvaluator::multiply_inplace(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        ct1 = multiply(ct1, ct2);
    }

    CKKSCiphertext CKKSEvaluator::multiply_plain(const CKKSCiphertext &ct, double scalar) {
        CKKSCiphertext output = ct;
        multiply_plain_inplace(output, scalar);
        return output;
    }

    void CKKSEvaluator::multiply_plain_inplace(CKKSCiphertext &ct, double scalar) {
        VERBOSE(cout << "Multiply ciphertext by scalar " << scalar << endl);
        multiply_plain_inplace_internal(ct, scalar);
    }

    CKKSCiphertext CKKSEvaluator::multiply_plain(const CKKSCiphertext &ct, const vector<double> &plain) {
        CKKSCiphertext output = ct;
        multiply_plain_inplace(output, plain);
        return output;
    }

    void CKKSEvaluator::multiply_plain_inplace(CKKSCiphertext &ct, const vector<double> &plain) {
        VERBOSE(cout << "Multiply by plaintext" << endl);
        if (ct.encoded_width * ct.encoded_height != plain.size()) {
            throw invalid_argument("CKKSEvaluator::multiply_plain: encoded size does not match plaintext input");
        }
        return multiply_plain_inplace_internal(ct, plain);
    }

    CKKSCiphertext CKKSEvaluator::square(const CKKSCiphertext &ct) {
        CKKSCiphertext output = ct;
        square_inplace(output);
        return output;
    }

    void CKKSEvaluator::square_inplace(CKKSCiphertext &ct) {
        VERBOSE(cout << "Square ciphertext" << endl);
        square_inplace_internal(ct);
    }

    CKKSCiphertext CKKSEvaluator::mod_down_to(const CKKSCiphertext &ct, const CKKSCiphertext &target) {
        CKKSCiphertext output = ct;
        mod_down_to_inplace(output, target);
        return output;
    }

    void CKKSEvaluator::mod_down_to_inplace(CKKSCiphertext &ct, const CKKSCiphertext &target) {
        VERBOSE(cout << "Decreasing HE level to match target" << endl);
        mod_down_to_inplace_internal(ct, target);
    }

    void CKKSEvaluator::mod_down_to_min_inplace(CKKSCiphertext &ct1, CKKSCiphertext &ct2) {
        VERBOSE(cout << "Equalizing HE levels" << endl);
        mod_down_to_min_inplace_internal(ct1, ct2);
    }

    CKKSCiphertext CKKSEvaluator::mod_down_to_level(const CKKSCiphertext &ct, int level) {
        CKKSCiphertext output = ct;
        mod_down_to_level_inplace(output, level);
        return output;
    }

    void CKKSEvaluator::mod_down_to_level_inplace(CKKSCiphertext &ct, int level) {
        VERBOSE(cout << "Decreasing HE level to " << level << endl);
        mod_down_to_level_inplace_internal(ct, level);
    }

    CKKSCiphertext CKKSEvaluator::rescale_to_next(const CKKSCiphertext &ct) {
        CKKSCiphertext output = ct;
        rescale_to_next_inplace(output);
        return output;
    }

    void CKKSEvaluator::rescale_to_next_inplace(CKKSCiphertext &ct) {
        VERBOSE(cout << "Rescaling ciphertext" << endl);
        rescale_to_next_inplace_internal(ct);
    }

    void CKKSEvaluator::relinearize_inplace(CKKSCiphertext &ct) {
        VERBOSE(cout << "Relinearizing ciphertext" << endl);
        relinearize_inplace_internal(ct);
    }

    ContextDataPtr CKKSEvaluator::getContextData(const CKKSCiphertext &ct) {
        // get the context_data for this ciphertext level
        // but do not use the ciphertext itself! Use the he_level,
        // in case we are not doing ciphertext computations
        auto context_data = context->first_context_data();
        while (context_data->chain_index() > ct.he_level) {
            // Step forward in the chain.
            context_data = context_data->next_context_data();
        }
        return context_data;
    }
}  // namespace hit
=======
                (ct1.height == ct2.height) && (ct1.width == ct2.width));
    }
    return ((ct1.encoded_height == ct2.encoded_height) && (ct1.encoded_width == ct2.encoded_width) &&
            (ct1.width == ct2.height));
}

CKKSCiphertext CKKSEvaluator::rotate_right(const CKKSCiphertext &ct, int steps) {
    if (steps < 0) {
        throw invalid_argument("ERROR: rotate_right must have a positive number of steps.");
    }
    VERBOSE(cout << "Rotate " << abs(steps) << " steps right." << endl);
    return rotate_right_internal(ct, steps);
    ;
}

void CKKSEvaluator::rotate_right_inplace(CKKSCiphertext &ct, int steps) {
    ct = rotate_right(ct, steps);
}

CKKSCiphertext CKKSEvaluator::rotate_left(const CKKSCiphertext &ct, int steps) {
    if (steps < 0) {
        throw invalid_argument("ERROR: rotate_left must have a positive number of steps.");
    }
    VERBOSE(cout << "Rotate " << abs(steps) << " steps left." << endl);
    return rotate_left_internal(ct, steps);
    ;
}

void CKKSEvaluator::rotate_left_inplace(CKKSCiphertext &ct, int steps) {
    ct = rotate_left(ct, steps);
}

CKKSCiphertext CKKSEvaluator::negate(const CKKSCiphertext &ct) {
    VERBOSE(cout << "Negate" << endl);
    return negate_internal(ct);
}

void CKKSEvaluator::negate_inplace(CKKSCiphertext &ct) {
    ct = negate(ct);
}

CKKSCiphertext CKKSEvaluator::add(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
    // it's a lot easier to validate combinations of args if they are in a canonical order. These two
    // statements put row vectors in the first arg, and col vectors in the second arg, which mirrors how
    // this would look on paper.
    if (ct1.encoding == MATRIX && ct2.encoding == ROW_MAT) {
        return add(ct2, ct1);
    }
    if (ct1.encoding == COL_MAT && ct2.encoding == MATRIX) {
        return add(ct2, ct1);
    }

    VERBOSE(cout << "Add ciphertexts" << endl);

    CKKSCiphertext temp = add_internal(ct1, ct2);

    // combining a ROW_MAT and a MATRIX only makes sense in make-believe linear algebra, like the type used
    // for PPLR training. It doesn't correspond to a real linear-algebra operation because we need this
    // capability for the component-wise application of the sigmoid approximation to a vector.
    if (ct1.encoding == ROW_MAT && ct2.encoding == MATRIX && is_valid_args(ct1, ct2)) {
        temp.encoding = ROW_MAT;
        temp.width = ct2.width;
        temp.encoded_width = ct2.width;
        temp.height = ct2.height;
        temp.encoded_height = ct2.height;
    } else if (ct1.encoding == MATRIX && ct2.encoding == COL_MAT && is_valid_args(ct1, ct2)) {
        temp.encoding = COL_MAT;
        temp.width = ct1.width;
        temp.encoded_width = ct1.width;
        temp.height = ct1.height;
        temp.encoded_height = ct1.height;
    }
    // we can always add standard linear alegbra objects of the same type, like adding two matrices or vectors
    // in this case, the dimensions don't change
    // note that adding COL_MATs makes sense if we consider breaking a matrix into several vertical chunks,
    // and the vector into corresponding pieces. Then instead of A*b, we view A as [A_1 | A_2] and b as <b_1 | b_2>.
    // Then we can compute A*b=A_1*b_1+A_2*b_2, and similarly for ROW_MATs.
    else if (ct1.encoding == ct2.encoding && is_valid_args(ct1, ct2)) {
    } else {
        cout << "Arg 1: Encoding(" << ct1.encoding << "), Dimensions: " << ct1.height << "x" << ct1.width
             << ", Embedded dimensions: " << ct1.encoded_height << "x" << ct1.encoded_width << endl;
        cout << "Arg 2: Encoding(" << ct2.encoding << "), Dimensions: " << ct2.height << "x" << ct2.width
             << ", Embedded dimensions: " << ct2.encoded_height << "x" << ct2.encoded_width << endl;
        throw invalid_argument("PPLR ERROR: cannot add arguments.");
    }

    return temp;
}

CKKSCiphertext CKKSEvaluator::add_plain(const CKKSCiphertext &ct, double scalar) {
    VERBOSE(cout << "Add scalar " << scalar << " to ciphertext" << endl);
    return add_plain_internal(ct, scalar);
}

void CKKSEvaluator::add_plain_inplace(CKKSCiphertext &ct, double scalar) {
    ct = add_plain(ct, scalar);
}

CKKSCiphertext CKKSEvaluator::add_plain(const CKKSCiphertext &ct, const vector<double> &plain) {
    VERBOSE(cout << "Add plaintext to ciphertext" << endl);
    return add_plain_internal(ct, plain);
}

void CKKSEvaluator::add_plain_inplace(CKKSCiphertext &ct, const vector<double> &plain) {
    ct = add_plain(ct, plain);
}

void CKKSEvaluator::add_inplace(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
    ct1 = add(ct1, ct2);
}

CKKSCiphertext CKKSEvaluator::add_many(vector<CKKSCiphertext> cts) {
    CKKSCiphertext dest = cts[0];
    for (int i = 1; i < cts.size(); i++) {
        add_inplace(dest, cts[i]);
    }
    return dest;
}

CKKSCiphertext CKKSEvaluator::sub(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
    // it's a lot easier to validate combinations of args if they are in a canonical order. These two
    // statements put row vectors in the first arg, and col vectors in the second arg, which mirrors how
    // this would look on paper.
    if (ct1.encoding == MATRIX && ct2.encoding == ROW_MAT) {
        return sub(ct2, ct1);
    }
    if (ct1.encoding == COL_MAT && ct2.encoding == MATRIX) {
        return sub(ct2, ct1);
    }

    VERBOSE(cout << "Subtract ciphertexts" << endl);

    CKKSCiphertext temp = sub_internal(ct1, ct2);

    // combining a ROW_MAT and a MATRIX only makes sense in make-believe linear algebra, like the type used
    // for PPLR training. It doesn't correspond to a real linear-algebra operation because we need this
    // capability for the component-wise application of the sigmoid approximation to a vector.
    if (ct1.encoding == ROW_MAT && ct2.encoding == MATRIX && is_valid_args(ct1, ct2)) {
        temp.encoding = ROW_MAT;
        temp.width = ct2.width;
        temp.encoded_width = ct2.width;
        temp.height = ct2.height;
        temp.encoded_height = ct2.height;
    } else if (ct1.encoding == MATRIX && ct2.encoding == COL_MAT && is_valid_args(ct1, ct2)) {
        temp.encoding = COL_MAT;
        temp.width = ct1.width;
        temp.encoded_width = ct1.width;
        temp.height = ct1.height;
        temp.encoded_height = ct1.height;
    }
    // we can always subtract standard linear alegbra objects of the same type, like adding two matrices or vectors
    // in this case, the dimensions don't change
    // note that adding COL_MATs makes sense if we consider breaking a matrix into several vertical chunks,
    // and the vector into corresponding pieces. Then instead of A*b, we view A as [A_1 | A_2] and b as <b_1 | b_2>.
    // Then we can compute A*b=A_1*b_1+A_2*b_2, and similarly for ROW_MATs.
    else if (ct1.encoding == ct2.encoding && is_valid_args(ct1, ct2)) {
    } else {
        cout << "Arg 1: Encoding(" << ct1.encoding << "), Dimensions: " << ct1.height << "x" << ct1.width
             << ", Embedded dimensions: " << ct1.encoded_height << "x" << ct1.encoded_width << endl;
        cout << "Arg 2: Encoding(" << ct2.encoding << "), Dimensions: " << ct2.height << "x" << ct2.width
             << ", Embedded dimensions: " << ct2.encoded_height << "x" << ct2.encoded_width << endl;
        throw invalid_argument("PPLR ERROR: cannot subtract arguments.");
    }

    return temp;
}

void CKKSEvaluator::sub_inplace(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
    ct1 = sub(ct1, ct2);
}

CKKSCiphertext CKKSEvaluator::sub_plain(const CKKSCiphertext &ct, double scalar) {
    VERBOSE(cout << "Subtract scalar " << scalar << " from ciphertext" << endl);
    return sub_plain_internal(ct, scalar);
}

void CKKSEvaluator::sub_plain_inplace(CKKSCiphertext &ct, double scalar) {
    ct = sub_plain(ct, scalar);
}

CKKSCiphertext CKKSEvaluator::sub_plain(const CKKSCiphertext &ct, const vector<double> &plain) {
    VERBOSE(cout << "Subtract plaintext from ciphertext" << endl);
    return sub_plain_internal(ct, plain);
}

void CKKSEvaluator::sub_plain_inplace(CKKSCiphertext &ct, const vector<double> &plain) {
    ct = sub_plain(ct, plain);
}

CKKSCiphertext CKKSEvaluator::multiply(const CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
    // it's a lot easier to validate combinations of args if they are in a canonical order. These two
    // statements put row vectors in the first arg, and col vectors in the second arg, which mirrors how
    // this would look on paper.
    if ((ct1.encoding == ROW_MAT || ct1.encoding == MATRIX) && ct2.encoding == ROW_VEC) {
        return multiply(ct2, ct1);
    }
    if (ct1.encoding == COL_VEC && (ct2.encoding == COL_MAT || ct2.encoding == MATRIX)) {
        return multiply(ct2, ct1);
    }

    VERBOSE(cout << "Multiply ciphertexts" << endl);

    CKKSCiphertext temp = multiply_internal(ct1, ct2);

    // we can multiply a row vector by either a row matrix or a pure matrix. In the first case, this is
    // \vec(a)*(\vec(b)*C), which is equivalent to (\vec(a)*\vec(b))*C, a row vector times a pure matrix. The second
    // case is simply the first step in an HE row-matrix-times-vector-product. We want the output in either case to be a
    // ROW_MAT with the same dimensions as the input matrix/row matrix
    if (ct1.encoding == ROW_VEC && (ct2.encoding == ROW_MAT || ct2.encoding == MATRIX) && is_valid_args(ct1, ct2)) {
        temp.encoding = ROW_MAT;
        temp.width = ct2.width;
        temp.encoded_width = ct2.width;
        temp.height = ct2.height;
        temp.encoded_height = ct2.height;
    }
    // similarly for column vectors/matrices: we can multiply a COL_MAT or a MATRIX times a column vector
    else if ((ct1.encoding == COL_MAT || ct1.encoding == MATRIX) && ct2.encoding == COL_VEC &&
             is_valid_args(ct1, ct2)) {
        temp.encoding = COL_MAT;
        temp.width = ct1.width;
        temp.encoded_width = ct1.width;
        temp.height = ct1.height;
        temp.encoded_height = ct1.height;
    }
    // we can always multiply vectors together (componentwise)
    else if (ct1.encoding == COL_VEC && ct2.encoding == COL_VEC && is_valid_args(ct1, ct2)) {
    } else if (ct1.encoding == ROW_VEC && ct2.encoding == ROW_VEC && is_valid_args(ct1, ct2)) {
    } else {
        cout << "Arg 1: Encoding(" << ct1.encoding << "), Dimensions: " << ct1.height << "x" << ct1.width
             << ", Embedded dimensions: " << ct1.encoded_height << "x" << ct1.encoded_width << endl;
        cout << "Arg 2: Encoding(" << ct2.encoding << "), Dimensions: " << ct2.height << "x" << ct2.width
             << ", Embedded dimensions: " << ct2.encoded_height << "x" << ct2.encoded_width << endl;
        throw invalid_argument("PPLR ERROR: cannot multiply arguments.");
    }

    return temp;
}

void CKKSEvaluator::multiply_inplace(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
    ct1 = multiply(ct1, ct2);
}

CKKSCiphertext CKKSEvaluator::multiply_plain(const CKKSCiphertext &ct, double scalar) {
    VERBOSE(cout << "Multiply ciphertext by scalar " << scalar << endl);
    return multiply_plain_internal(ct, scalar);
}

void CKKSEvaluator::multiply_plain_inplace(CKKSCiphertext &ct, double scalar) {
    ct = multiply_plain(ct, scalar);
}

CKKSCiphertext CKKSEvaluator::multiply_plain(const CKKSCiphertext &ct, const vector<double> &plain) {
    VERBOSE(cout << "Multiply by plaintext" << endl);
    if (ct.encoded_width * ct.encoded_height != plain.size()) {
        throw invalid_argument("CKKSEvaluator::multiply_plain: encoded size does not match plaintext input");
    }
    return multiply_plain_internal(ct, plain);
}

void CKKSEvaluator::multiply_plain_inplace(CKKSCiphertext &ct, const vector<double> &plain) {
    ct = multiply_plain(ct, plain);
}

CKKSCiphertext CKKSEvaluator::square(const CKKSCiphertext &ct) {
    VERBOSE(cout << "Square ciphertext" << endl);
    return square_internal(ct);
}

void CKKSEvaluator::square_inplace(CKKSCiphertext &ct) {
    ct = square(ct);
}

CKKSCiphertext CKKSEvaluator::mod_down_to(const CKKSCiphertext &ct, const CKKSCiphertext &target) {
    VERBOSE(cout << "Decreasing HE level to match target" << endl);
    return mod_down_to_internal(ct, target);
}

void CKKSEvaluator::mod_down_to_inplace(CKKSCiphertext &ct, const CKKSCiphertext &target) {
    ct = mod_down_to(ct, target);
}

void CKKSEvaluator::mod_down_to_min_inplace(CKKSCiphertext &ct1, CKKSCiphertext &ct2) {
    VERBOSE(cout << "Equalizing HE levels" << endl);
    mod_down_to_min_inplace_internal(ct1, ct2);
}

CKKSCiphertext CKKSEvaluator::mod_down_to_level(const CKKSCiphertext &ct, int level) {
    VERBOSE(cout << "Decreasing HE level to " << level << endl);
    return mod_down_to_level_internal(ct, level);
}

void CKKSEvaluator::mod_down_to_level_inplace(CKKSCiphertext &ct, int level) {
    ct = mod_down_to_level(ct, level);
}

CKKSCiphertext CKKSEvaluator::rescale_to_next(const CKKSCiphertext &ct) {
    VERBOSE(cout << "Rescaling ciphertext" << endl);
    return rescale_to_next_internal(ct);
}

void CKKSEvaluator::rescale_to_next_inplace(CKKSCiphertext &ct) {
    ct = rescale_to_next(ct);
}

void CKKSEvaluator::relinearize_inplace(CKKSCiphertext &ct) {
    VERBOSE(cout << "Relinearizing ciphertext" << endl);
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
>>>>>>> 6d292d7... Updated all evaluators
