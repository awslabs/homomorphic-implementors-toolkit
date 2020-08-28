// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "plaintext.h"

#include <glog/logging.h>
#include <iomanip>

#include "../../common.h"

using namespace std;
using namespace seal;

namespace hit {

    // This is an approximation of -infity, since infNorm(x) >= 0 = 2^-infinity
    double initialPtMaxLog = -100;

    PlaintextEval::PlaintextEval(const shared_ptr<SEALContext> &context)
        : CKKSEvaluator(context), ptMaxLog(initialPtMaxLog) {
    }

    PlaintextEval::~PlaintextEval() = default;

    void PlaintextEval::reset_internal() {
        ptMaxLog = initialPtMaxLog;
    }

    // print some debug info
    void PlaintextEval::print_stats(       // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
        const CKKSCiphertext &ct) const {  // NOLINT(readability-convert-member-functions-to-static)
        if (!VLOG_IS_ON(LOG_VERBOSE)) {
            return;
        }
        // extract just the elements we care about from the real plaintext
        vector<double> exactPlaintext = ct.getPlaintext();
        double exactPlaintextMaxVal = lInfNorm(exactPlaintext);
        VLOG(LOG_VERBOSE) << "    + Plaintext dimension: " << ct.height << "x" << ct.width;
        VLOG(LOG_VERBOSE) << "    + Scale: " << setprecision(4) << log2(ct.scale) << " bits";
        VLOG(LOG_VERBOSE) << "    + Exact plaintext logmax: " << log2(exactPlaintextMaxVal)
                          << " bits (scaled: " << log2(ct.scale) + log2(exactPlaintextMaxVal) << " bits)";

        int maxPrintSize = 8;
        stringstream exact_plaintext_info;
        exact_plaintext_info << "    + Exact plaintext: < ";
        for (int j = 0; j < min(maxPrintSize, static_cast<int>(exactPlaintext.size())); j++) {
            exact_plaintext_info << setprecision(8) << exactPlaintext[j] << ", ";
        }
        if (exactPlaintext.size() > maxPrintSize) {
            exact_plaintext_info << "... ";
        }
        exact_plaintext_info << ">";
        VLOG(LOG_VERBOSE) << exact_plaintext_info.str();
    }

    void PlaintextEval::update_max_log_plain_val(const CKKSCiphertext &ct) {
        double exactPlaintextMaxVal = lInfNorm(ct.getPlaintext());

        ptMaxLog = max(ptMaxLog, log2(exactPlaintextMaxVal));
    }

    void PlaintextEval::update_plaintext_max_val(double x) {
        // takes the actual max value, we need to set the log of it
        ptMaxLog = max(ptMaxLog, log2(x));
    }

    void PlaintextEval::rotate_right_inplace_internal(CKKSCiphertext &ct, int steps) {
        vector<double> rot_temp;
        // reserve a full-size vector
        int pt_size = ct.encoded_pt.size();
        rot_temp.reserve(pt_size);

        // the `for` loop adds elements to the back of the vector
        // we start by adding elements from the end of `ct.encoded_pt`
        for (int i = pt_size - steps; i < pt_size; i++) {
            rot_temp.push_back(ct.encoded_pt[i]);
        }
        // next start at the front of `ct.encoded_pt` and add until full
        for (int i = 0; i < pt_size - steps; i++) {
            rot_temp.push_back(ct.encoded_pt[i]);
        }

        ct.encoded_pt = rot_temp;
        // does not change ptMaxLog
        print_stats(ct);
    }

    void PlaintextEval::rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) {
        vector<double> rot_temp;
        // reserve a full-size vector
        int pt_size = ct.encoded_pt.size();
        rot_temp.reserve(pt_size);
        // start filling from the offset
        for (int i = steps; i < pt_size; i++) {
            rot_temp.push_back(ct.encoded_pt[i]);
        }
        // next, add the remaining elements from the front of `ct.encoded_pt`
        for (int i = 0; i < steps; i++) {
            rot_temp.push_back(ct.encoded_pt[i]);
        }

        ct.encoded_pt = rot_temp;
        // does not change ptMaxLog
        print_stats(ct);
    }

    void PlaintextEval::negate_inplace_internal(CKKSCiphertext &ct) {
        for (auto &coeff : ct.encoded_pt) {
            coeff = -coeff;
        }
        print_stats(ct);
    }

    void PlaintextEval::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        ct1.encoded_pt = ct1.encoded_pt + ct2.encoded_pt;
        update_max_log_plain_val(ct1);
        print_stats(ct1);
    }

    void PlaintextEval::add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        Vector coeffVec(ct.encoded_pt.size(), scalar);
        ct.encoded_pt = ct.encoded_pt + coeffVec;
        update_max_log_plain_val(ct);
        print_stats(ct);
    }

    void PlaintextEval::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        if (plain.size() != ct.encoded_pt.size()) {
            stringstream buffer;
            buffer << "plaintext.add_plain_internal: public input has the wrong size: " << plain.size()
                   << " != " << ct.encoded_pt.size();
            throw invalid_argument(buffer.str());
        }

        Vector coeffVec(ct.encoded_pt.size(), plain);
        ct.encoded_pt = ct.encoded_pt + coeffVec;
        update_max_log_plain_val(ct);
        print_stats(ct);
    }

    void PlaintextEval::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        ct1.encoded_pt = ct1.encoded_pt - ct2.encoded_pt;
        update_max_log_plain_val(ct1);
        print_stats(ct1);
    }

    void PlaintextEval::sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        Vector coeffVec(ct.encoded_pt.size(), scalar);
        ct.encoded_pt = ct.encoded_pt - coeffVec;
        update_max_log_plain_val(ct);
        print_stats(ct);
    }

    void PlaintextEval::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        if (plain.size() != ct.encoded_pt.size()) {
            stringstream buffer;
            buffer << "plaintext.sub_plain_internal: public input has the wrong size: " << plain.size()
                   << " != " << ct.encoded_pt.size();
            throw invalid_argument(buffer.str());
        }

        Vector coeffVec(ct.encoded_pt.size(), plain);
        ct.encoded_pt = ct.encoded_pt - coeffVec;
        update_max_log_plain_val(ct);
        print_stats(ct);
    }

    void PlaintextEval::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        if (ct1.encoded_pt.size() != ct2.encoded_pt.size()) {
            throw invalid_argument("INTERNAL ERROR: Plaintext size mismatch");
        }
        for (int i = 0; i < ct1.encoded_pt.size(); i++) {
            ct1.encoded_pt[i] = ct1.encoded_pt[i] * ct2.encoded_pt[i];
        }
        update_max_log_plain_val(ct1);
        print_stats(ct1);
    }

    void PlaintextEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        ct.encoded_pt = scalar * ct.encoded_pt;
        update_max_log_plain_val(ct);
        print_stats(ct);
    }

    void PlaintextEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        if (plain.size() != ct.encoded_pt.size()) {
            stringstream buffer;
            buffer << "plaintext.multiply_plain_internal: public input has the wrong size: " << plain.size()
                   << " != " << ct.encoded_pt.size();
            throw invalid_argument(buffer.str());
        }

        for (int i = 0; i < ct.encoded_pt.size(); i++) {
            ct.encoded_pt[i] = ct.encoded_pt[i] * plain[i];
        }
        update_max_log_plain_val(ct);
        print_stats(ct);
    }

    void PlaintextEval::square_inplace_internal(CKKSCiphertext &ct) {
        for (auto &coeff : ct.encoded_pt) {
            coeff *= coeff;
        }
        update_max_log_plain_val(ct);
        print_stats(ct);
    }

    void PlaintextEval::mod_down_to_inplace_internal(CKKSCiphertext &ct, const CKKSCiphertext &) {
        // does not change ptMaxLog
        print_stats(ct);
    }

    void PlaintextEval::mod_down_to_min_inplace_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) {
        // does not change ptMaxLog
        print_stats(ct1);
        print_stats(ct2);
    }

    void PlaintextEval::mod_down_to_level_inplace_internal(CKKSCiphertext &ct, int) {
        // does not change ptMaxLog
        print_stats(ct);
    }

    void PlaintextEval::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        // does not change ptMaxLog
        print_stats(ct);
    }

    void PlaintextEval::relinearize_inplace_internal(CKKSCiphertext &ct) {
        // does not change ptMaxLog
        print_stats(ct);
    }

    double PlaintextEval::get_exact_max_log_plain_val() const {
        return ptMaxLog;
    }
}  // namespace hit
