// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <boost/numeric/ublas/matrix.hpp>
#include <boost/numeric/ublas/vector.hpp>

namespace ublas = boost::numeric::ublas;

namespace hit {

    typedef ublas::matrix<double, ublas::row_major, std::vector<double>> Matrix;  // NOLINT(modernize-use-using)
    typedef ublas::vector<double, std::vector<double>> Vector;                    // NOLINT(modernize-use-using)

}  // namespace hit
