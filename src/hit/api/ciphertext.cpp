// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ciphertext.h"

#include <glog/logging.h>

#include "../common.h"

using namespace std;
using namespace seal;

namespace hit {

    void CKKSCiphertext::read_from_proto(const shared_ptr<HEContext> &context, const protobuf::Ciphertext &proto_ct) {
        initialized = proto_ct.initialized();

        // Users cannot specify an initial scale smaller than 2^MIN_LOG_SCALE
        // If a user does specify this scale, the scale at lower levels is never
        // smaller than the initial scale: it can only get larger because of the way
        // SEAL generates modulus vectors.
        scale_ = proto_ct.scale();
        if (scale_ <= pow(2, context->min_log_scale())) {
            LOG_AND_THROW_STREAM("Error deserializing ciphertext: scale too small.");
        }

        he_level_ = proto_ct.he_level();
        if (he_level_ < 0 || he_level_ > context->max_ciphertext_level()) {
            LOG_AND_THROW_STREAM("Error deserializing ciphertext: he_level out of bounds.");
        }

        num_slots_ = context->num_slots();

        if (proto_ct.has_ct()) {
            istringstream ctstream(proto_ct.ct());
            backend_ct.load(*(context->params), ctstream);
        }
    }

    CKKSCiphertext::CKKSCiphertext(const shared_ptr<HEContext> &context, const protobuf::Ciphertext &proto_ct) {
        read_from_proto(context, proto_ct);
    }

    CKKSCiphertext::CKKSCiphertext(const shared_ptr<HEContext> &context, istream &stream) {
        protobuf::Ciphertext proto_ct;
        proto_ct.ParseFromIstream(&stream);
        read_from_proto(context, proto_ct);
    }

    protobuf::Ciphertext *CKKSCiphertext::serialize() const {
        protobuf::Ciphertext *proto_ct = new protobuf::Ciphertext();

        if (!raw_pt.empty()) {
            LOG_AND_THROW_STREAM(
                "HIT does not support serializing ciphertexts with plaintext data attached! Use the homomorphic "
                "evaluator to serialize ciphertexts.");
        }

        proto_ct->set_initialized(initialized);
        proto_ct->set_scale(scale_);
        proto_ct->set_he_level(he_level_);

        // if the backend_ct is initialized, serialize it
        if (backend_ct.parms_id() != parms_id_zero) {
            ostringstream ct_stream;
            backend_ct.save(ct_stream);
            proto_ct->set_ct(ct_stream.str());
        }

        return proto_ct;
    }

    void CKKSCiphertext::save(ostream &stream) const {
        protobuf::Ciphertext *proto_ct = serialize();
        proto_ct->SerializeToOstream(&stream);
        delete proto_ct;
    }

    // Metadata interface functions
    int CKKSCiphertext::num_slots() const {
        return num_slots_;
    }

    int CKKSCiphertext::he_level() const {
        return he_level_;
    }

    double CKKSCiphertext::scale() const {
        return scale_;
    }

    double CKKSCiphertext::backend_scale() const {
        return backend_ct.scale();
    }

    bool CKKSCiphertext::needs_rescale() const {
        return needs_rescale_;
    }

    bool CKKSCiphertext::needs_relin() const {
        return needs_relin_;
    }

    vector<double> CKKSCiphertext::plaintext() const {
        if (raw_pt.empty()) {
            LOG_AND_THROW_STREAM("Ciphertext does not contain a plaintext.");
        }
        return raw_pt;
    }
}  // namespace hit
