// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "encodingunit.h"

#include "common.h"

using namespace std;

namespace hit {
    EncodingUnit::EncodingUnit(int encoding_height, int encoding_width)
        : encoding_height_(encoding_height), encoding_width_(encoding_width) {
        validateInit();
    }

    EncodingUnit::EncodingUnit(const protobuf::EncodingUnit &encoding_unit) {
        encoding_height_ = encoding_unit.encoding_height();
        encoding_width_ = encoding_unit.encoding_width();
        validateInit();
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

    bool EncodingUnit::initialized() const {
        return encoding_height_ > 0 && encoding_width_ > 0 && isPow2(encoding_height_) && isPow2(encoding_width_);
    }

    void EncodingUnit::validateInit() const {
        if (!initialized()) {
            throw invalid_argument("Encoding unit dimensions must be a power of two.");
        }
    }

    EncodingUnit EncodingUnit::transpose() const {
        return EncodingUnit(encoding_width_, encoding_height_);
    }
}  // namespace hit