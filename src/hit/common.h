// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>

#include "api/ciphertext.h"
#include "hit/protobuf/ciphertext.pb.h"
#include "hit/protobuf/ciphertext_vector.pb.h"
#include "seal/seal.h"
#include <boost/numeric/ublas/matrix.hpp>
#include <boost/numeric/ublas/vector.hpp>

#define VLOG_EVAL 1
#define VLOG_VERBOSE 2

#define INVALID_PARAMETER_EXCEPTION 10

// the maximum normalized norm of the difference between the actual and expected result
#define MAX_NORM 0.02

// When computing a bound on the scale, we want the scaled plaintext to be
// less than this many bits
#define PLAINTEXT_LOG_MAX 59

#define LOG_AND_THROW_STREAM(stream_contents) { \
    std::stringstream err_stream; \
    err_stream << stream_contents; \
    LOG(ERROR) << err_stream.str(); \
    throw std::invalid_argument(err_stream.str()); \
}

namespace hit {
    using Matrix = boost::numeric::ublas::matrix<double, boost::numeric::ublas::row_major, std::vector<double>>;
    using Vector = boost::numeric::ublas::vector<double, std::vector<double>>;

    using timepoint =
        std::chrono::time_point<std::chrono::steady_clock, std::chrono::duration<int64_t, std::ratio<1, 1000000000>>>;

    enum TimeScale { TS_MS, TS_SEC, TS_MIN, TS_DYNAMIC };

    uint64_t elapsed_time_in_ms(timepoint start, timepoint end);
    std::string elapsed_time_to_str(timepoint start, timepoint end, TimeScale = TS_DYNAMIC);
    void print_elapsed_time(timepoint start, const std::string &str = "");

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

    inline protobuf::CiphertextVector *serialize_vector(const std::vector<CKKSCiphertext> &ciphertext_vector) {
        auto *proto_ciphertext_vector = new protobuf::CiphertextVector();
        for (const auto &ciphertext : ciphertext_vector) {
            // https://developers.google.com/protocol-buffers/docs/reference/cpp-generated#repeatedmessage
            proto_ciphertext_vector->mutable_cts()->AddAllocated(ciphertext.serialize());
        }
        return proto_ciphertext_vector;
    }

    inline void deserialize_vector(const std::shared_ptr<seal::SEALContext> &context,
                                  const protobuf::CiphertextVector &proto_ciphertext_vector,
                                  std::vector<CKKSCiphertext> &ciphertext_vector) {
        for (int i = 0; i < proto_ciphertext_vector.cts_size(); i++) {
            const protobuf::Ciphertext &ciphertext = proto_ciphertext_vector.cts(i);
            ciphertext_vector.emplace_back(CKKSCiphertext(context, ciphertext));
        }
    }

    inline std::vector<int> gen_for_each_iters(int iters) {
        std::vector<int> iterIdxs(iters);
        for (int i = 0; i < iters; i++) {
            iterIdxs[i] = i;
        }
        return iterIdxs;
    }

    void decryption_warning(int level);

}  // namespace hit
