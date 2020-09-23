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
    const double INITIAL_PLAINTEXT_MAX_LOG = -100;

    PlaintextEval::PlaintextEval(int num_slots) : num_slots_(num_slots) {
    }

    PlaintextEval::~PlaintextEval() = default;

    void PlaintextEval::reset_internal() {
        {
            scoped_lock lock(mutex_);
            plaintext_max_log_ = INITIAL_PLAINTEXT_MAX_LOG;
        }
    }

    CKKSCiphertext PlaintextEval::encrypt(const vector<double> &coeffs, int) {
        if (coeffs.size() != num_slots_) {
            // bad things can happen if you don't plan for your input to be smaller than the ciphertext
            // This forces the caller to ensure that the input has the correct size or is at least appropriately padded
            throw invalid_argument(
                "You can only encrypt vectors which have exactly as many coefficients as the number of plaintext "
                "slots: Expected " +
                to_string(num_slots_) + ", got " + to_string(coeffs.size()));
        }

        {
            scoped_lock lock(mutex_);
            // takes the actual max value, we need to set the log of it
            plaintext_max_log_ = max(plaintext_max_log_, log2(l_inf_norm(coeffs)));
        }

        CKKSCiphertext destination;
        destination.raw_pt = coeffs;
        destination.num_slots_ = num_slots_;
        destination.initialized = true;

        return destination;
    }

    // print some debug info
    void PlaintextEval::print_stats(       // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
        const CKKSCiphertext &ct) const {  // NOLINT(readability-convert-member-functions-to-static)
        if (!VLOG_IS_ON(LOG_VERBOSE)) {
            return;
        }
        // extract just the elements we care about from the real plaintext
        vector<double> exact_plaintext = ct.plaintext().data();
        // double exact_plaintext_max_val = l_inf_norm(exact_plaintext);
        // VLOG(LOG_VERBOSE) << "    + Scale: " << setprecision(4) << log2(ct.scale()) << " bits";
        // VLOG(LOG_VERBOSE) << "    + Exact plaintext logmax: " << log2(exact_plaintext_max_val)
        //                   << " bits (scaled: " << log2(ct.scale()) + log2(exact_plaintext_max_val) << " bits)";

        int max_print_size = 8;
        stringstream exact_plaintext_info;
        exact_plaintext_info << "    + Exact plaintext: < ";
        for (int j = 0; j < min(max_print_size, static_cast<int>(exact_plaintext.size())); j++) {
            exact_plaintext_info << setprecision(8) << exact_plaintext[j] << ", ";
        }
        if (exact_plaintext.size() > max_print_size) {
            exact_plaintext_info << "... ";
        }
        exact_plaintext_info << ">";
        VLOG(LOG_VERBOSE) << exact_plaintext_info.str();
    }

    void PlaintextEval::update_max_log_plain_val(const CKKSCiphertext &ct) {
        double exact_plaintext_max_val = l_inf_norm(ct.plaintext().data());
        {
            scoped_lock lock(mutex_);
            plaintext_max_log_ = max(plaintext_max_log_, log2(exact_plaintext_max_val));
        }
    }

    void PlaintextEval::rotate_right_inplace_internal(CKKSCiphertext &ct, int steps) {
        vector<double> rot_temp;
        // reserve a full-size vector
        int num_slots = ct.num_slots();
        rot_temp.reserve(num_slots);

        // the `for` loop adds elements to the back of the vector
        // we start by adding elements from the end of `ct.raw_pt`
        for (int i = num_slots - steps; i < num_slots; i++) {
            rot_temp.push_back(ct.raw_pt[i]);
        }
        // next start at the front of `ct.raw_pt` and add until full
        for (int i = 0; i < num_slots - steps; i++) {
            rot_temp.push_back(ct.raw_pt[i]);
        }

        ct.raw_pt = rot_temp;
        // does not change plaintext_max_log_
        print_stats(ct);
    }

    void PlaintextEval::rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) {
        vector<double> rot_temp;
        // reserve a full-size vector
        int num_slots = ct.num_slots();
        rot_temp.reserve(num_slots);
        // start filling from the offset
        for (int i = steps; i < num_slots; i++) {
            rot_temp.push_back(ct.raw_pt[i]);
        }
        // next, add the remaining elements from the front of `ct.raw_pt`
        for (int i = 0; i < steps; i++) {
            rot_temp.push_back(ct.raw_pt[i]);
        }

        ct.raw_pt = rot_temp;
        // does not change plaintext_max_log_
        print_stats(ct);
    }

    void PlaintextEval::negate_inplace_internal(CKKSCiphertext &ct) {
        for (auto &coeff : ct.raw_pt) {
            coeff = -coeff;
        }
        print_stats(ct);
    }

    void PlaintextEval::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        ct1.raw_pt = ct1.plaintext() + ct2.plaintext();
        update_max_log_plain_val(ct1);
        print_stats(ct1);
    }

    void PlaintextEval::add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        Vector coeffVec(ct.num_slots(), scalar);
        ct.raw_pt = ct.plaintext() + coeffVec;
        update_max_log_plain_val(ct);
        print_stats(ct);
    }

    void PlaintextEval::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        if (plain.size() != ct.num_slots()) {
            stringstream buffer;
            buffer << "plaintext.add_plain_internal: public input has the wrong size: " << plain.size()
                   << " != " << ct.num_slots();
            throw invalid_argument(buffer.str());
        }

        Vector coeffVec(ct.num_slots(), plain);
        ct.raw_pt = ct.plaintext() + coeffVec;
        update_max_log_plain_val(ct);
        print_stats(ct);
    }

    void PlaintextEval::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        ct1.raw_pt = ct1.plaintext() - ct2.plaintext();
        update_max_log_plain_val(ct1);
        print_stats(ct1);
    }

    void PlaintextEval::sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        Vector coeffVec(ct.num_slots(), scalar);
        ct.raw_pt = ct.plaintext() - coeffVec;
        update_max_log_plain_val(ct);
        print_stats(ct);
    }

    void PlaintextEval::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        if (plain.size() != ct.num_slots()) {
            stringstream buffer;
            buffer << "plaintext.sub_plain_internal: public input has the wrong size: " << plain.size()
                   << " != " << ct.num_slots();
            throw invalid_argument(buffer.str());
        }

        Vector coeffVec(ct.num_slots(), plain);
        ct.raw_pt = ct.plaintext() - coeffVec;
        update_max_log_plain_val(ct);
        print_stats(ct);
    }

    void PlaintextEval::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        if (ct1.num_slots() != ct2.num_slots()) {
            throw invalid_argument("INTERNAL ERROR: Plaintext size mismatch");
        }
        for (int i = 0; i < ct1.plaintext().size(); i++) {
            ct1.raw_pt[i] = ct1.raw_pt[i] * ct2.raw_pt[i];
        }
        update_max_log_plain_val(ct1);
        print_stats(ct1);
    }

    void PlaintextEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        ct.raw_pt = scalar * ct.plaintext();
        update_max_log_plain_val(ct);
        print_stats(ct);
    }

    void PlaintextEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        if (plain.size() != ct.num_slots()) {
            stringstream buffer;
            buffer << "plaintext.multiply_plain_internal: public input has the wrong size: " << plain.size()
                   << " != " << ct.num_slots();
            throw invalid_argument(buffer.str());
        }

        for (int i = 0; i < ct.num_slots(); i++) {
            ct.raw_pt[i] = ct.raw_pt[i] * plain[i];
        }
        // update_max_log_plain_val(ct);
        print_stats(ct);
    }

    void PlaintextEval::square_inplace_internal(CKKSCiphertext &ct) {
        for (auto &coeff : ct.raw_pt) {
            coeff *= coeff;
        }
        // update_max_log_plain_val(ct);
        print_stats(ct);
    }

    void PlaintextEval::mod_down_to_level_inplace_internal(CKKSCiphertext &ct, int) {
        // does not change plaintext_max_log_
        print_stats(ct);
    }

    void PlaintextEval::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        // does not change plaintext_max_log_
        print_stats(ct);
    }

    void PlaintextEval::relinearize_inplace_internal(CKKSCiphertext &ct) {
        // does not change plaintext_max_log_
        print_stats(ct);
    }

    double PlaintextEval::get_exact_max_log_plain_val() const {
        shared_lock lock(mutex_);
        return plaintext_max_log_;
    }
}  // namespace hit
