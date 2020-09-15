// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>

#include "CKKSInstance.h"
#include "api/ciphertext.h"
#include "seal/seal.h"
#include "hit/protobuf/ciphertext.pb.h"
#include "hit/protobuf/ciphertext_vector.pb.h"

#define LOG_VERBOSE 1

#define INVALID_PARAMETER_EXCEPTION 10

// the maximum normalized norm of the difference between the actual and expected result
#define MAX_NORM 0.02

// When computing a bound on the scale, we want the scaled plaintext to be
// less than this many bits
#define PLAINTEXT_LOG_MAX 59

namespace hit {

    using timepoint =
        std::chrono::time_point<std::chrono::steady_clock, std::chrono::duration<int64_t, std::ratio<1, 1000000000>>>;

    enum TimeScale { TS_MS, TS_SEC, TS_MIN, TS_DYNAMIC };

    uint64_t elapsedTimeMs(timepoint start, timepoint end);
    std::string elapsedTimeToStr(timepoint start, timepoint end, TimeScale = TS_DYNAMIC);
    void printElapsedTime(timepoint start);

    // computes the |expected-actual|/|expected|, where |*| denotes the 2-norm.
    double diff2Norm(const std::vector<double> &expected, const std::vector<double> &actual);

    // tests if x is a power of two or not
    bool isPow2(int x);

    /* For each poly_modulus_degree (a power of two between 1024 and 32768,
     * inclusive), SEAL limits the size of the total modulus. This function
     * returns that limit (in bits).
     */
    int polyDegreeToMaxModBits(int poly_modulus_degree);

    int modulusToPolyDegree(int modBits);

    // the L-infinity norm
    double lInfNorm(const std::vector<double> &x);

    uintmax_t streamSize(std::iostream &s);

    std::string bytesToStr(uintmax_t sizeBytes);

    inline protobuf::CiphertextVector *serializeVector(const std::vector<CKKSCiphertext> &ciphertext_vector) {
        auto *proto_ciphertext_vector = new protobuf::CiphertextVector();
        for (auto &ciphertext : ciphertext_vector) {
            // https://developers.google.com/protocol-buffers/docs/reference/cpp-generated#repeatedmessage
            proto_ciphertext_vector->mutable_cts()->AddAllocated(ciphertext.save());
        }
        return proto_ciphertext_vector;
    }

    inline void deserializeVector(const protobuf::CiphertextVector &proto_ciphertext_vector,
            std::vector<CKKSCiphertext> &ciphertext_vector) {
        for (int i = 0; i < proto_ciphertext_vector.cts_size(); i++) {
            protobuf::Ciphertext ciphertext = proto_ciphertext_vector.cts(i);
            ciphertext_vector.push_back(CKKSCiphertext(ciphertext));
        }
    }

}  // namespace hit
