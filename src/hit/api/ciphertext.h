// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "hit/api/context.h"
#include "hit/protobuf/ciphertext.pb.h"
#include "hit/protobuf/ciphertext_vector.pb.h"
#include "metadata.h"

namespace hit {

    /* This is a wrapper around the SEAL `Ciphertext` type.
     */
    struct CKKSCiphertext : public CiphertextMetadata<std::vector<double>> {
        // A default constructor is useful since we often write, e.g, `Ciphertext a;`
        CKKSCiphertext() = default;

        // Deserialize a ciphertext from a protobuf object
        CKKSCiphertext(const std::shared_ptr<HEContext> &context, const protobuf::Ciphertext &proto_ct);

        // Deserialize a ciphertext from a stream containing a protobuf object
        CKKSCiphertext(const std::shared_ptr<HEContext> &context, std::istream &stream);

        // Serialize a ciphertext to a protobuf object
        // This function is typically used in protobuf serialization code for objects which
        // contain a protobuf::Ciphertext. When used directly, you are responsible for
        // calling `delete` on the pointer. When passed as an argument to a protocol buffer
        // `add_allocated` function, ownership is transferred to the protocol buffer object,
        // which is responsible for releasing the memory allocated here.
        protobuf::Ciphertext *serialize() const;
        // Serialize an ciphertext as a protobuf object to a stream.
        void save(std::ostream &stream) const;

        // Ciphertext metadata
        int num_slots() const override;
        int he_level() const override;
        double scale() const override;
        // Output true if the ciphertext has squared scale and is
        // therefore in need of a rescale, false otherwise.
        bool needs_rescale() const override;
        // Output true if the ciphertext is quadratic and is
        // therefore in need of relinearization, false otherwise.
        bool needs_relin() const override;
        // Output the plaintext included in this ciphertext, if it was encrypted with
        // the Debug evaluator. The output is not a decrypted ciphertext, rather it is
        // computed in-the-clear in parallel with the encrypted computation.
        std::vector<double> plaintext() const override;

        // all evaluators need access for encryption and decryption
        friend class DebugEval;
        friend class ExplicitDepthFinder;
        friend class ImplicitDepthFinder;
        friend class HomomorphicEval;
        friend class PlaintextEval;
        friend class OpCount;
        friend class ScaleEstimator;
        friend class RotationSet;
        friend class CKKSEvaluator;

       private:
        void read_from_proto(const std::shared_ptr<HEContext> &context, const protobuf::Ciphertext &proto_ct);

        double backend_scale() const;

        // The raw plaintext. This is used with some of the evaluators tha track ciphertext
        // metadata (e.g., DebugEval and PlaintextEval), but not by the Homomorphic evaluator.
        // This plaintext is not CKKS-encoded; in particular it is not scaled by the scale factor.
        std::vector<double> raw_pt;

        seal::Ciphertext backend_ct;

        // `scale` is used by the ScaleEstimator evaluator
        double scale_ = pow(2, 30);

        // flag indicating whether this CT has been initialized or not
        // CKKSCiphertexts are initialized upon encryption
        bool initialized = false;

        // heLevel is used by the depthFinder
        int he_level_ = 0;

        // number of plaintext slots
        size_t num_slots_ = 0;

        bool needs_relin_ = false;
        bool needs_rescale_ = false;
    };

    inline protobuf::CiphertextVector *serialize_vector(const std::vector<CKKSCiphertext> &ciphertext_vector) {
        auto *proto_ciphertext_vector = new protobuf::CiphertextVector();
        for (const auto &ciphertext : ciphertext_vector) {
            // https://developers.google.com/protocol-buffers/docs/reference/cpp-generated#repeatedmessage
            proto_ciphertext_vector->mutable_cts()->AddAllocated(ciphertext.serialize());
        }
        return proto_ciphertext_vector;
    }

    inline void deserialize_vector(const std::shared_ptr<HEContext> &context,
                                   const protobuf::CiphertextVector &proto_ciphertext_vector,
                                   std::vector<CKKSCiphertext> &ciphertext_vector) {
        for (int i = 0; i < proto_ciphertext_vector.cts_size(); i++) {
            const protobuf::Ciphertext &ciphertext = proto_ciphertext_vector.cts(i);
            ciphertext_vector.emplace_back(CKKSCiphertext(context, ciphertext));
        }
    }
}  // namespace hit
