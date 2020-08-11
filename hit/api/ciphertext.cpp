// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ciphertext.h"
#include "../common.h"

// these values will be properly initilized by the implicit
// copy constructor or during encryption.
CKKSCiphertext::CKKSCiphertext():
  height(0), width(0), encoded_height(0), encoded_width(0),
  encoding(UNINITIALIZED), he_level(0), scale(0) { }


void CKKSCiphertext::copyMetadataFrom(const CKKSCiphertext &src) {
  // copy all non-debug values
  width = src.width;
  height = src.height;
  encoded_width = src.encoded_width;
  encoded_height = src.encoded_height;
  encoding = src.encoding;
  he_level = src.he_level;
  encoded_pt = src.encoded_pt;
  scale = src.scale;
}

CKKSCiphertext::CKKSCiphertext(const std::shared_ptr<seal::SEALContext> &context,
  const protobuf::hit::Ciphertext &proto_ct) {
  if(proto_ct.version() != 0) {
    throw std::invalid_argument("CKKSCiphertext serialization: Expected version 0");
  }

  height = proto_ct.height();
  width = proto_ct.width();
  encoded_height = proto_ct.encoded_height();
  encoded_width = proto_ct.encoded_width();
  encoding = static_cast<CTEncoding>(proto_ct.encoding());
  scale = proto_ct.scale();
  he_level = proto_ct.helevel();

  if(encoding != UNINITIALIZED) {
    int encoded_pt_size = proto_ct.encoded_pt_size();
    encoded_pt = Vector(encoded_pt_size);
    for(int i = 0; i < encoded_pt_size; i++) {
      encoded_pt[i] = proto_ct.encoded_pt(i);
    }

    std::istringstream ctstream(proto_ct.sealct());
    seal_ct.load(context, ctstream);
  }
}

int CKKSCiphertext::getLevel(const std::shared_ptr<seal::SEALContext> &context) const {
  return context->get_context_data(seal_ct.parms_id())->chain_index();
}

std::vector<double> CKKSCiphertext::getPlaintext() const {
  if(encoded_pt.empty()) {
    throw std::invalid_argument("This ciphertext does not contain the raw plaintext. Use a different evaluator/encryptor in order to track the plaintext computation.");
  }

  return decodePlaintext(encoded_pt.data(), encoding, height, width, encoded_height, encoded_width);
}

protobuf::hit::Ciphertext* CKKSCiphertext::save() const {
  auto *proto_ct = new protobuf::hit::Ciphertext();
  save(proto_ct);
  return proto_ct;
}

void CKKSCiphertext::save(protobuf::hit::Ciphertext *proto_ct) const {
  proto_ct->set_version(0);
  proto_ct->set_height(height);
  proto_ct->set_encoded_height(encoded_height);
  proto_ct->set_width(width);
  proto_ct->set_encoded_width(encoded_width);
  proto_ct->set_encoding(encoding);
  proto_ct->set_scale(scale);
  proto_ct->set_helevel(he_level);

  if(encoding != UNINITIALIZED) {
    std::ostringstream sealctBuf;
    seal_ct.save(sealctBuf);
    proto_ct->set_sealct(sealctBuf.str());

    for(double i : encoded_pt) {
      proto_ct->add_encoded_pt(i);
    }
  }
}
