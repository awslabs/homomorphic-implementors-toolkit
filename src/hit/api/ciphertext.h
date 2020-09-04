// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../matrix.h"
#include "hit/protobuf/ciphertext.pb.h"  // NOLINT
#include "seal/context.h"
#include "seal/seal.h"

namespace hit {
    /* This is a wrapper around the SEAL `Ciphertext` type.
     */
    struct CKKSCiphertext {
        // SEAL ciphertext
        seal::Ciphertext seal_ct;

        // flag indicating whether this CT has been initialized or not
        // CKKSCiphertexts are initialized upon encryption
        bool initialized;     // NOLINT(modernize-use-default-member-init)

        // The raw plaintxt. This is used during development, but not by the Homomorphic evaluator.
        // This plaintext is not CKKS-encoded.
        Vector raw_pt;

        // `scale` is used by the ScaleEstimator evaluator
        double scale;  // NOLINT(modernize-use-default-member-init)

        // A default constructor is useful since we often write, e.g, `Ciphertext &a;`
        CKKSCiphertext();

        CKKSCiphertext(const std::shared_ptr<seal::SEALContext> &context, const hit::protobuf::Ciphertext &proto_ct);

        // Copy all members except the ciphertext itself
        void copyMetadataFrom(const CKKSCiphertext &src);

        // Return the SEAL `chain_index` of this ciphertext.
        // This essentially refers to how many primes are in the modulus.
        // A ciphertext starts with many primes (corresponding to the highest chain_index/level)
        // but we remove primes to scale down the noise. A single prime (the lowest level) corresponds
        // to level 0.
        int& he_level();
        const int& he_level() const;

        // the number of plaintext slots in this ciphertext
        int num_slots() const;

        hit::protobuf::Ciphertext *save() const;
        void save(hit::protobuf::Ciphertext *proto_ct) const;

        friend class CKKSEncryptor;

    private:
        // heLevel is used by the depthFinder
        int he_level_;  // NOLINT(modernize-use-default-member-init)

        // number of plaintext slots
        size_t num_slots_;     // NOLINT(modernize-use-default-member-init)
    };
}  // namespace hit
