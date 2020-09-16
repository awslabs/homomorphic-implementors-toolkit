// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../matrix.h"
#include "hit/protobuf/ciphertext.pb.h"  // NOLINT
#include "metadata.h"
#include "seal/context.h"
#include "seal/seal.h"

namespace hit {
    /* This is a wrapper around the SEAL `Ciphertext` type.
     */
    struct CKKSCiphertext : public CiphertextMetadata<Vector> {
        // A default constructor is useful since we often write, e.g, `Ciphertext a;`
        CKKSCiphertext() = default;

        // Deserialize a ciphertext
        CKKSCiphertext(const std::shared_ptr<seal::SEALContext> &context, const hit::protobuf::Ciphertext &proto_ct);

        // Serialize a ciphertext
        hit::protobuf::Ciphertext *save() const;
        void save(hit::protobuf::Ciphertext &proto_ct) const;

        // Ciphertext metadata
        int num_slots() const override;
        int he_level() const override;
        double scale() const override;
        Vector plaintext() const override;

        friend class CKKSEncryptor;    // needs access to all fields of seal_ct
        friend class CKKSDecryptor;    // needs access to seal_ct
        friend class DebugEval;        // needs access to seal_ct
        friend class DepthFinder;      // modifies he_level_
        friend class HomomorphicEval;  // needs access to seal_ct
        friend class PlaintextEval;    // modifies raw_pt
        friend class ScaleEstimator;   // modifies scale_

       private:
        // Copy all members except the ciphertext itself
        void copyMetadataFrom(const CKKSCiphertext &src);

        // The raw plaintxt. This is used with some of the evaluators tha track ciphertext
        // metadata (e.g., DebugEval and PlaintextEval), but not by the Homomorphic evaluator.
        // This plaintext is not CKKS-encoded; in particular it is not scaled by the scale factor.
        Vector raw_pt;

        // SEAL ciphertext
        seal::Ciphertext seal_ct;

        // `scale` is used by the ScaleEstimator evaluator
        double scale_ = 0;

        // flag indicating whether this CT has been initialized or not
        // CKKSCiphertexts are initialized upon encryption
        bool initialized = false;

        // heLevel is used by the depthFinder
        int he_level_ = 0;

        // number of plaintext slots
        size_t num_slots_ = 0;
    };
}  // namespace hit
