// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ciphertext.h"

#include <glog/logging.h>

#include "../common.h"

using namespace std;
using namespace seal;

namespace hit {

    void CKKSCiphertext::read_from_proto(const shared_ptr<SEALContext> &context, const protobuf::Ciphertext &proto_ct) {
        initialized = proto_ct.initialized();
        scale_ = proto_ct.scale();
        he_level_ = proto_ct.he_level();
        num_slots_ = context->first_context_data()->parms().poly_modulus_degree() / 2;

        if (proto_ct.has_seal_ct()) {
            istringstream ctstream(proto_ct.seal_ct());
            seal_ct.load(context, ctstream);
        }
    }

    CKKSCiphertext::CKKSCiphertext(const shared_ptr<SEALContext> &context, const protobuf::Ciphertext &proto_ct) {
        read_from_proto(context, proto_ct);
    }

    CKKSCiphertext::CKKSCiphertext(const shared_ptr<SEALContext> &context, istream &stream) {
        protobuf::Ciphertext proto_ct;
        proto_ct.ParseFromIstream(&stream);
        read_from_proto(context, proto_ct);
    }

    protobuf::Ciphertext *CKKSCiphertext::serialize() const {
        auto *proto_ct = new protobuf::Ciphertext();

        if (!raw_pt.empty()) {
            LOG_AND_THROW_STREAM("HIT does not support serializing ciphertexts with plaintext data attached! Use the homomorphic evaluator to serialize ciphertexts.");
        }

        proto_ct->set_initialized(initialized);
        proto_ct->set_scale(scale_);
        proto_ct->set_he_level(he_level_);

        // if the seal_ct is initialized, serialize it
        if (seal_ct.parms_id() != parms_id_zero) {
            ostringstream sealctBuf;
            seal_ct.save(sealctBuf);
            proto_ct->set_seal_ct(sealctBuf.str());
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
