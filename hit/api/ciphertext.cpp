// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ciphertext.h"
#include "../common.h"

// these values will be properly initilized by the implicit
// copy constructor or during encryption.
CKKSCiphertext::CKKSCiphertext():
  sealct(), height(0), width(0), encoded_height(0), encoded_width(0),
  encoding(UNINITIALIZED), heLevel(0), scale(0) { }


void CKKSCiphertext::copyMetadataFrom(const CKKSCiphertext &src) {
  // copy all non-debug values
  width = src.width;
  height = src.height;
  encoded_width = src.encoded_width;
  encoded_height = src.encoded_height;
  encoding = src.encoding;
  heLevel = src.heLevel;
  encoded_pt = src.encoded_pt;
  scale = src.scale;
}

CKKSCiphertext::CKKSCiphertext(std::shared_ptr<seal::SEALContext> &context,
  const protobuf::hit::Ciphertext &c) {
  if(c.version() != 0) {
    throw std::invalid_argument("CKKSCiphertext serialization: Expected version 0");
  }

  height = c.height();
  width = c.width();
  encoded_height = c.encoded_height();
  encoded_width = c.encoded_width();
  encoding = static_cast<CTEncoding>(c.encoding());
  scale = c.scale();
  heLevel = c.helevel();

  if(encoding != UNINITIALIZED) {
    int encoded_pt_size = c.encoded_pt_size();
    encoded_pt = Vector(encoded_pt_size);
    for(int i = 0; i < encoded_pt_size; i++) {
      encoded_pt[i] = c.encoded_pt(i);
    }

    std::istringstream ctstream(c.sealct());
    sealct.load(context, ctstream);
  }
}

int CKKSCiphertext::getLevel(const std::shared_ptr<seal::SEALContext> &context) const {
  return context->get_context_data(sealct.parms_id())->chain_index();
}

std::vector<double> CKKSCiphertext::getPlaintext() const {
  if(encoded_pt.size() == 0) {
    throw std::invalid_argument("This ciphertext does not contain the raw plaintext. Use a different evaluator/encryptor in order to track the plaintext computation.");
  }

  return decodePlaintext(encoded_pt.data(), encoding, height, width, encoded_height, encoded_width);
}

protobuf::hit::Ciphertext* CKKSCiphertext::save() const {
  auto *c = new protobuf::hit::Ciphertext();
  save(c);
  return c;
}

void CKKSCiphertext::save(protobuf::hit::Ciphertext *c) const {
  c->set_version(0);
  c->set_height(height);
  c->set_encoded_height(encoded_height);
  c->set_width(width);
  c->set_encoded_width(encoded_width);
  c->set_encoding(encoding);
  c->set_scale(scale);
  c->set_helevel(heLevel);

  if(encoding != UNINITIALIZED) {
    std::ostringstream sealctBuf;
    sealct.save(sealctBuf);
    c->set_sealct(sealctBuf.str());

    for(double i : encoded_pt) {
      c->add_encoded_pt(i);
    }
  }
}
