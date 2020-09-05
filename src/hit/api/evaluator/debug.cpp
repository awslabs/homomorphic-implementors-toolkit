// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "debug.h"

#include <glog/logging.h>

#include <iomanip>

#include "../../common.h"
#include "../evaluator.h"

using namespace std;
using namespace seal;

namespace hit {

    DebugEval::DebugEval(const shared_ptr<SEALContext> &context, CKKSEncoder &encoder, Encryptor &encryptor,
                         const GaloisKeys &galois_keys, const RelinKeys &relin_keys, double scale,
                         CKKSDecryptor &decryptor)
        : CKKSEvaluator(context), decryptor(decryptor), initScale(scale) {
        heEval = new HomomorphicEval(context, encoder, encryptor, galois_keys, relin_keys, false);
        seEval = new ScaleEstimator(context, static_cast<int>(2 * encoder.slot_count()), scale);
    }

    DebugEval::~DebugEval() {
        delete heEval;
        delete seEval;
    }

    void DebugEval::reset_internal() {
        heEval->reset_internal();
        seEval->reset_internal();
    }

    // Verify that the ciphertext is either at its expected scale (based on its level),
    // or is at the square of its expected scale.
    void DebugEval::check_scale(const CKKSCiphertext &ct) const {
        auto context_data = context->first_context_data();
        double expectedScale = initScale;
        while (context_data->chain_index() > ct.he_level()) {
            expectedScale = (expectedScale * expectedScale) /
                            static_cast<double>(context_data->parms().coeff_modulus().back().value());
            context_data = context_data->next_context_data();
        }
        if (ct.seal_ct.scale() != expectedScale && ct.seal_ct.scale() != expectedScale * expectedScale) {
            throw invalid_argument("CHECK_SCALE: Expected " + to_string(expectedScale) + "^{1,2}, got " +
                                   to_string(ct.seal_ct.scale()));
        }
        if (ct.seal_ct.scale() != ct.scale) {
            throw invalid_argument("HIT scale calculation does not match SEAL.");
        }
    }

    // print some debug info
    void DebugEval::print_stats(const CKKSCiphertext &ct) const {
        double norm = 0;

        // decrypt to compute the approximate plaintext
        vector<double> homomPlaintext = decryptor.decrypt(ct);
        vector<double> exactPlaintext = ct.raw_pt.data();

        norm = diff2Norm(exactPlaintext, homomPlaintext);
        if (abs(log2(ct.scale) - log2(ct.seal_ct.scale())) > 0.1) {
            stringstream buffer;
            buffer << "INTERNAL ERROR: SCALE COMPUTATION IS INCORRECT: " << log2(ct.scale)
                   << " != " << ct.seal_ct.scale();
            throw invalid_argument(buffer.str());
        }

        VLOG(LOG_VERBOSE) << setprecision(8) << "    + Approximation norm: " << norm;

        int maxPrintSize = 8;
        if (VLOG_IS_ON(LOG_VERBOSE)) {
            stringstream verbose_info;
            verbose_info << "    + Homom Result:   < ";
            for (int i = 0; i < min(maxPrintSize, static_cast<int>(homomPlaintext.size())); i++) {
                verbose_info << setprecision(8) << homomPlaintext[i] << ", ";
            }
            if (homomPlaintext.size() > maxPrintSize) {
                verbose_info << "... ";
            }
            verbose_info << ">";
            VLOG(LOG_VERBOSE) << verbose_info.str();
        }

        if (norm > MAX_NORM) {
            stringstream buffer;
            buffer << "DebugEvaluator: plaintext and ciphertext divergence: " << norm << " > " << MAX_NORM
                   << ". Scale is " << log2(seEval->baseScale) << ".";

            maxPrintSize = 32;
            stringstream expect_debug_result;
            expect_debug_result << "    + DEBUG Expected result: <";
            for (int i = 0; i < min(maxPrintSize, static_cast<int>(exactPlaintext.size())); i++) {
                expect_debug_result << setprecision(8) << exactPlaintext[i];
                if (i < exactPlaintext.size() - 1) {
                    expect_debug_result << ", ";
                }
            }
            if (exactPlaintext.size() > maxPrintSize) {
                expect_debug_result << "..., ";
            }
            expect_debug_result << ">";
            LOG(INFO) << expect_debug_result.str();

            stringstream actual_debug_result;
            actual_debug_result << "    + DEBUG Actual result:   <";
            for (int i = 0; i < min(maxPrintSize, static_cast<int>(homomPlaintext.size())); i++) {
                actual_debug_result << setprecision(8) << homomPlaintext[i];
                if (i < exactPlaintext.size() - 1) {
                    actual_debug_result << ", ";
                }
            }
            if (homomPlaintext.size() > maxPrintSize) {
                actual_debug_result << "..., ";
            }
            actual_debug_result << ">";
            LOG(INFO) << actual_debug_result.str();

            Plaintext encoded_plain;
            heEval->encoder.encode(ct.raw_pt.data(), seEval->baseScale, encoded_plain);

            vector<double> decoded_plain;
            heEval->encoder.decode(encoded_plain, decoded_plain);

            // the exactPlaintext and homomPlaintext should have the same length.
            // decoded_plain is full-dimensional, however. This may not match
            // the dimension of exactPlaintext if the plaintext in question is a
            // vector, so we need to truncate the decoded value.
            vector<double> truncated_decoded_plain(decoded_plain.begin(),
                                                   decoded_plain.begin() + exactPlaintext.size());
            double norm2 = diff2Norm(exactPlaintext, truncated_decoded_plain);
            double norm3 = diff2Norm(truncated_decoded_plain, homomPlaintext);

            LOG(INFO) << "Encoding norm: " << norm2;
            LOG(INFO) << "Encryption norm: " << norm3;

            throw invalid_argument(buffer.str());
        }
    }

    void DebugEval::rotate_right_inplace_internal(CKKSCiphertext &ct, int steps) {
        check_scale(ct);
        heEval->rotate_right_inplace_internal(ct, steps);
        seEval->rotate_right_inplace_internal(ct, steps);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) {
        check_scale(ct);
        heEval->rotate_left_inplace_internal(ct, steps);
        seEval->rotate_left_inplace_internal(ct, steps);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::negate_inplace_internal(CKKSCiphertext &ct) {
        check_scale(ct);
        heEval->negate_inplace_internal(ct);
        seEval->negate_inplace_internal(ct);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        check_scale(ct1);
        check_scale(ct2);
        heEval->add_inplace_internal(ct1, ct2);
        seEval->add_inplace_internal(ct1, ct2);

        print_stats(ct1);
        check_scale(ct1);
    }

    void DebugEval::add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        check_scale(ct);
        heEval->add_plain_inplace_internal(ct, scalar);
        seEval->add_plain_inplace_internal(ct, scalar);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        check_scale(ct);
        heEval->add_plain_inplace_internal(ct, plain);
        seEval->add_plain_inplace_internal(ct, plain);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        check_scale(ct1);
        check_scale(ct2);
        heEval->sub_inplace_internal(ct1, ct2);
        seEval->sub_inplace_internal(ct1, ct2);

        print_stats(ct1);
        check_scale(ct1);
    }

    void DebugEval::sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        check_scale(ct);
        heEval->sub_plain_inplace_internal(ct, scalar);
        seEval->sub_plain_inplace_internal(ct, scalar);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        check_scale(ct);
        heEval->sub_plain_inplace_internal(ct, plain);
        seEval->sub_plain_inplace_internal(ct, plain);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        check_scale(ct1);
        check_scale(ct2);
        heEval->multiply_inplace_internal(ct1, ct2);
        seEval->multiply_inplace_internal(ct1, ct2);

        print_stats(ct1);
        check_scale(ct1);
    }

    void DebugEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        check_scale(ct);
        heEval->multiply_plain_inplace_internal(ct, scalar);
        seEval->multiply_plain_inplace_internal(ct, scalar);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        check_scale(ct);
        heEval->multiply_plain_inplace_internal(ct, plain);
        seEval->multiply_plain_inplace_internal(ct, plain);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::square_inplace_internal(CKKSCiphertext &ct) {
        check_scale(ct);
        heEval->square_inplace_internal(ct);
        seEval->square_inplace_internal(ct);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::mod_down_to_inplace_internal(CKKSCiphertext &ct, const CKKSCiphertext &target) {
        check_scale(ct);
        check_scale(target);
        heEval->mod_down_to_inplace_internal(ct, target);
        seEval->mod_down_to_inplace_internal(ct, target);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::mod_down_to_min_inplace_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) {
        heEval->mod_down_to_min_inplace_internal(ct1, ct2);
        seEval->mod_down_to_min_inplace_internal(ct1, ct2);

        print_stats(ct1);
        print_stats(ct2);
    }

    void DebugEval::mod_down_to_level_inplace_internal(CKKSCiphertext &ct, int level) {
        check_scale(ct);
        heEval->mod_down_to_level_inplace_internal(ct, level);
        seEval->mod_down_to_level_inplace_internal(ct, level);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        auto context_data = getContextData(ct);
        uint64_t p = context_data->parms().coeff_modulus().back().value();
        double prime_bit_len = log2(p);

        check_scale(ct);
        heEval->rescale_to_next_inplace_internal(ct);
        seEval->rescale_to_next_inplace_internal(ct);

        // for some reason, the default is to print doubles with no decimal places.
        // To get decimal places, add `<< fixed << setprecision(2)` before printing the log.
        // Note that you'll need a lot of decimal places because these values are very close
        // to an integer.
        VLOG(LOG_VERBOSE) << "    + Scaled plaintext down by the ~" << prime_bit_len << "-bit prime " << hex << p
                          << dec;

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::relinearize_inplace_internal(CKKSCiphertext &ct) {
        check_scale(ct);
        heEval->relinearize_inplace_internal(ct);
        seEval->relinearize_inplace_internal(ct);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::update_plaintext_max_val(double x) {
        seEval->update_plaintext_max_val(x);
    }

    double DebugEval::get_exact_max_log_plain_val() const {
        return seEval->get_exact_max_log_plain_val();
    }

    double DebugEval::get_estimated_max_log_scale() const {
        return seEval->get_estimated_max_log_scale();
    }
}  // namespace hit
