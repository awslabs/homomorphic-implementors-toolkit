// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

// An abstract interface for obtaining immutable ciphertext metadata

namespace hit {
    template <typename PlaintextType>
    class CiphertextMetadata {
       public:
        virtual int num_slots() const = 0;

        // Return the SEAL `chain_index` of this ciphertext.
        // This essentially refers to how many primes are in the modulus.
        // A ciphertext starts with many primes (corresponding to the highest chain_index/level)
        // but we remove primes to scale down the noise. A single prime (the lowest level) corresponds
        // to level 0.
        virtual int he_level() const = 0;

        // `scale` is used by the ScaleEstimator evaluator
        virtual double scale() const = 0;
        virtual PlaintextType plaintext() const = 0;

        virtual ~CiphertextMetadata<PlaintextType>() = default;
    };
}  // namespace hit
