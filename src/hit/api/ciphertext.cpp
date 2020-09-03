// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ciphertext.h"

#include <glog/logging.h>

#include "../common.h"

using namespace std;
using namespace seal;

namespace hit {

    // these values will be properly initilized by the implicit
    // copy constructor or during encryption.
    CKKSCiphertext::CKKSCiphertext()
        : initialized(false), he_level(0), scale(0), num_slots_(0) {
    }

    void CKKSCiphertext::copyMetadataFrom(const CKKSCiphertext &src) {
        initialized = src.initialized;
        he_level = src.he_level;
        raw_pt = src.raw_pt;
        scale = src.scale;
        num_slots_ = src.num_slots_;
    }

    CKKSCiphertext::CKKSCiphertext(const shared_ptr<SEALContext> &context, const protobuf::Ciphertext &proto_ct) {
        if (proto_ct.version() != 0) {
            throw invalid_argument("CKKSCiphertext serialization: Expected version 0");
        }

        initialized = proto_ct.initialized();
        scale = proto_ct.scale();
        he_level = proto_ct.helevel();
        num_slots_ = context->first_context_data()->parms().poly_modulus_degree()/2;

        if (initialized) {
            int raw_pt_size = proto_ct.raw_pt_size();
            raw_pt = Vector(raw_pt_size);
            for (int i = 0; i < raw_pt_size; i++) {
                raw_pt[i] = proto_ct.raw_pt(i);
            }

            istringstream ctstream(proto_ct.sealct());
            seal_ct.load(context, ctstream);
        }
    }

    int CKKSCiphertext::getLevel(const shared_ptr<SEALContext> &context) const {
        return context->get_context_data(seal_ct.parms_id())->chain_index();
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
        proto_ct->set_initialized(initialized);
        proto_ct->set_scale(scale);
        proto_ct->set_helevel(he_level);

        if (initialized) {
            ostringstream sealctBuf;
            seal_ct.save(sealctBuf);
            proto_ct->set_sealct(sealctBuf.str());

            for (double i : raw_pt) {
                proto_ct->add_raw_pt(i);
            }
        }
    }

    int CKKSCiphertext::num_slots() const {
        return num_slots_;
    }
}  // namespace hit
