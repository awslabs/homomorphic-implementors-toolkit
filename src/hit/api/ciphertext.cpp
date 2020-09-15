// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ciphertext.h"

#include <glog/logging.h>

#include "../common.h"

using namespace std;
using namespace seal;

namespace hit {

    void CKKSCiphertext::copyMetadataFrom(const CKKSCiphertext &src) {
        raw_pt = src.raw_pt;
        contains_seal_ct = src.contains_seal_ct;
        he_level_ = src.he_level_;
        scale_ = src.scale_;
        num_slots_ = src.num_slots_;
    }

    CKKSCiphertext::CKKSCiphertext(const shared_ptr<SEALContext> &context, const protobuf::Ciphertext &proto_ct) {
        if (proto_ct.version() != 0) {
            throw invalid_argument("CKKSCiphertext serialization: Expected version 0");
        }

        contains_seal_ct = proto_ct.contains_seal_ct();
        scale_ = proto_ct.scale();
        he_level_ = proto_ct.he_level();
        num_slots_ = context->first_context_data()->parms().poly_modulus_degree() / 2;

        if (contains_seal_ct) {
            int raw_pt_size = proto_ct.raw_pt_size();
            raw_pt = Vector(raw_pt_size);
            for (int i = 0; i < raw_pt_size; i++) {
                raw_pt[i] = proto_ct.raw_pt(i);
            }

            istringstream ctstream(proto_ct.seal_ct());
            seal_ct.load(context, ctstream);
        }
    }

    protobuf::Ciphertext *CKKSCiphertext::save() const {
        auto *proto_ct = new protobuf::Ciphertext();
        save(proto_ct);
        return proto_ct;
    }

    void CKKSCiphertext::save(protobuf::Ciphertext *proto_ct) const {
        if (!raw_pt.empty()) {
            LOG(WARNING) << "Serializing ciphertext with plaintext data attached! Use the homomorphic evaluator "
                            "instead for secure computation.";
        }

        proto_ct->set_version(0);
        proto_ct->set_contains_seal_ct(contains_seal_ct);
        proto_ct->set_scale(scale_);
        proto_ct->set_he_level(he_level_);

        if (contains_seal_ct) {
            ostringstream sealctBuf;
            seal_ct.save(sealctBuf);
            proto_ct->set_seal_ct(sealctBuf.str());

            for (double i : raw_pt) {
                proto_ct->add_raw_pt(i);
            }
        }
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

    Vector CKKSCiphertext::plaintext() const {
        return raw_pt;
    }
}  // namespace hit
