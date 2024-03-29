// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <glog/logging.h>

#include <boost/numeric/ublas/matrix.hpp>
#include <boost/numeric/ublas/vector.hpp>
#include <chrono>

#define VLOG_EVAL 1
#define VLOG_VERBOSE 2

#define INVALID_PARAMETER_EXCEPTION 10

// the maximum normalized norm of the difference between the actual and expected result
#define MAX_NORM 0.02

// When computing a bound on the scale, we want the scaled plaintext to be
// less than this many bits
#define PLAINTEXT_LOG_MAX 59

#define LOG_AND_THROW_STREAM(stream_contents)            \
    {                                                    \
        std::stringstream err_stream;                    \
        /* NOLINTNEXTLINE(bugprone-macro-parentheses) */ \
        err_stream << stream_contents;                   \
        LOG(ERROR) << err_stream.str();                  \
        throw std::invalid_argument(err_stream.str());   \
    }

#define TRY_AND_THROW_STREAM(cond, stream_contents) \
    try {                                           \
        (cond);                                     \
    } catch (...) {                                 \
        LOG_AND_THROW_STREAM(stream_contents);      \
    }

namespace hit {
    using Matrix = boost::numeric::ublas::matrix<double, boost::numeric::ublas::row_major, std::vector<double>>;
    using Vector = boost::numeric::ublas::vector<double, std::vector<double>>;

    using timepoint =
        std::chrono::time_point<std::chrono::steady_clock, std::chrono::duration<int64_t, std::ratio<1, 1000000000>>>;

    enum TimeScale { TS_MS, TS_SEC, TS_MIN, TS_DYNAMIC };

    uint64_t elapsed_time_in_ms(timepoint start, timepoint end);
    std::string elapsed_time_to_str(timepoint start, timepoint end, TimeScale = TS_DYNAMIC);
    void log_elapsed_time(timepoint start, const std::string &str = "");

    // computes the |expected-actual|/|expected|, where |*| denotes the 2-norm.
    double relative_error(const std::vector<double> &expected, const std::vector<double> &actual);
    double relative_error(const Vector &expected, const Vector &actual);
    double relative_error(const Matrix &expected, const Matrix &actual);

    // tests if x is a power of two or not
    bool is_pow2(int x);

    /* For each poly_modulus_degree (a power of two between 1024 and 32768,
     * inclusive), SEAL limits the size of the total modulus. This function
     * returns that limit (in bits).
     */
    int poly_degree_to_max_mod_bits(int poly_modulus_degree);

    int modulus_to_poly_degree(int mod_bits);

    // the L-infinity norm
    double l_inf_norm(const std::vector<double> &x);

    uintmax_t stream_size(std::iostream &s);

    std::string bytes_to_str(uintmax_t size_bytes);

    void decryption_warning(int level);

}  // namespace hit
