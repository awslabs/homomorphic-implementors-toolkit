// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "encodingunit.h"

#include "common.h"
#include <glog/logging.h>

using namespace std;

namespace hit {
    EncodingUnit::EncodingUnit(int encoding_height, int encoding_width)
        : encoding_height_(encoding_height), encoding_width_(encoding_width) {
        validate_init();
    }

    void EncodingUnit::read_from_proto(const protobuf::EncodingUnit &encoding_unit) {
        encoding_height_ = encoding_unit.encoding_height();
        encoding_width_ = encoding_unit.encoding_width();
        validate_init();
    }

    EncodingUnit::EncodingUnit(const protobuf::EncodingUnit &encoding_unit) {
        read_from_proto(encoding_unit);
    }

    EncodingUnit::EncodingUnit(istream &stream) {
        protobuf::EncodingUnit proto_unit;
        proto_unit.ParseFromIstream(&stream);
        read_from_proto(proto_unit);
    }

    bool operator==(const EncodingUnit &lhs, const EncodingUnit &rhs) {
        return lhs.encoding_width() == rhs.encoding_width() && lhs.encoding_height() == rhs.encoding_height();
    }

    bool operator!=(const EncodingUnit &lhs, const EncodingUnit &rhs) {
        return !(lhs == rhs);
    }

    int EncodingUnit::encoding_height() const {
        return encoding_height_;
    }

    int EncodingUnit::encoding_width() const {
        return encoding_width_;
    }

    protobuf::EncodingUnit *EncodingUnit::serialize() const {
        auto *encoding_unit = new protobuf::EncodingUnit();
        encoding_unit->set_encoding_height(encoding_height_);
        encoding_unit->set_encoding_width(encoding_width_);
        return encoding_unit;
    }

    void EncodingUnit::save(ostream &stream) const {
        protobuf::EncodingUnit *proto_unit = serialize();
        proto_unit->SerializeToOstream(&stream);
        delete proto_unit;
    }

    bool EncodingUnit::initialized() const {
        return encoding_height_ > 0 && encoding_width_ > 0 && is_pow2(encoding_height_) && is_pow2(encoding_width_);
    }

    void EncodingUnit::validate_init() const {
        if (!initialized()) {
            LOG(ERROR) << "Encoding unit dimensions must be a positive powers of two, got "
                       << encoding_height_ << "x" << encoding_width_;
            throw invalid_argument("An error occurred. See the log for details.");
        }
    }

    EncodingUnit EncodingUnit::transpose() const {
        return EncodingUnit(encoding_width_, encoding_height_);
    }
}  // namespace hit
