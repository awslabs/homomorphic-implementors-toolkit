// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "debug.h"

#include <glog/logging.h>

#include <iomanip>

#include "../../common.h"
#include "../evaluator.h"
#include "hit/api/context.h"

using namespace std;
using namespace latticpp;

namespace hit {
    void DebugEval::constructor_common(int num_slots) {
        // use the _private_ ScaleEstimator constructor to avoid creating two sets of CKKS params
        scale_estimator = new ScaleEstimator(num_slots, *homomorphic_eval);
        print_parameters();

        post_boostrapping_level = homomorphic_eval->post_boostrapping_level;
        post_bootstrapping_scale = homomorphic_eval->post_bootstrapping_scale;
    }

    /* Based on the SEAL version of this function */
    void DebugEval::print_parameters() {
        VLOG(VLOG_VERBOSE) << "/";
        VLOG(VLOG_VERBOSE) << "| Encryption parameters :";
        VLOG(VLOG_VERBOSE) << "|   scheme: CKKS";
        VLOG(VLOG_VERBOSE) << "|   poly_modulus_degree: " << (2 * num_slots());

        /*
        Print the size of the true (product) coefficient modulus.
        */
        int total_bits = homomorphic_eval->context->total_modulus_bits();
        stringstream coeff_modulus_size_info;
        coeff_modulus_size_info << "|   coeff_modulus size: " << total_bits << " (";
        for (int i = 0; i < homomorphic_eval->context->num_qi(); i++) {
            double bits = log2(static_cast<double>(homomorphic_eval->context->get_qi(i)));
            coeff_modulus_size_info << ceil(bits) << " + ";
        }
        for (int i = 0; i < homomorphic_eval->context->num_pi(); i++) {
            double bits = log2(static_cast<double>(homomorphic_eval->context->get_pi(i)));
            coeff_modulus_size_info << ceil(bits) << " + ";
        }
        coeff_modulus_size_info << ") bits";
        VLOG(VLOG_VERBOSE) << coeff_modulus_size_info.str();

        VLOG(VLOG_VERBOSE) << "\\";

        // We iterate over the chain and print the parms_id for each set of parameters.
        VLOG(VLOG_VERBOSE) << "Print the modulus switching chain.";

        // First print the key level parameter information.
        VLOG(VLOG_VERBOSE) << "----> Level (chain index): " << homomorphic_eval->context->num_qi()
                           << " ...... key_context_data()";
        VLOG(VLOG_VERBOSE) << "      parms_id: lvl<" << homomorphic_eval->context->num_qi() << ">";
        stringstream key_level_primes;
        for (int i = 0; i < homomorphic_eval->context->num_qi(); i++) {
            key_level_primes << hex << homomorphic_eval->context->get_qi(i) << dec << " ";
        }
        for (int i = 0; i < homomorphic_eval->context->num_pi(); i++) {
            key_level_primes << hex << homomorphic_eval->context->get_pi(i) << dec << " ";
        }
        VLOG(VLOG_VERBOSE) << "      coeff_modulus primes: " << hex << key_level_primes.str() << dec;
        VLOG(VLOG_VERBOSE) << "\\";

        // Next iterate over the remaining (data) levels.
        for (int i = homomorphic_eval->context->ckks_params.max_param_level(); i >= 0; i--) {
            VLOG(VLOG_VERBOSE) << " \\--> Level (chain index): " << i;
            if (i == homomorphic_eval->context->ckks_params.max_param_level()) {
                VLOG(VLOG_VERBOSE) << " ...... first_context_data()";
            } else if (i == 0) {
                VLOG(VLOG_VERBOSE) << " ...... last_context_data()";
            }
            VLOG(VLOG_VERBOSE) << "      parms_id: lvl<" << i << ">";
            stringstream data_level_primes;
            for (int j = 0; j <= i; j++) {
                data_level_primes << hex << homomorphic_eval->context->get_qi(j) << dec << " ";
            }
            VLOG(VLOG_VERBOSE) << "      coeff_modulus primes: " << data_level_primes.str();
            VLOG(VLOG_VERBOSE) << "\\";
        }
        VLOG(VLOG_VERBOSE) << " End of chain reached";
    }

    DebugEval::DebugEval(const CKKSParams &params, const vector<int> &galois_steps) {
        homomorphic_eval = new HomomorphicEval(params, galois_steps);
        constructor_common(params.num_slots());
    }

    DebugEval::DebugEval(int num_slots, int multiplicative_depth, int log_scale, const vector<int> &galois_steps) {
        homomorphic_eval = new HomomorphicEval(num_slots, multiplicative_depth, log_scale, galois_steps);
        constructor_common(num_slots);
    }

    DebugEval::DebugEval(istream &params_stream, istream &galois_key_stream, istream &relin_key_stream,
                         istream &secret_key_stream) {
        homomorphic_eval = new HomomorphicEval(params_stream, galois_key_stream, relin_key_stream, secret_key_stream);
        constructor_common(homomorphic_eval->num_slots());
    }

    DebugEval::~DebugEval() {
        delete homomorphic_eval;
        delete scale_estimator;
    }

    void DebugEval::save(ostream &params_stream, ostream &galois_key_stream, ostream &relin_key_stream,
                         ostream &secret_key_stream) {
        homomorphic_eval->save(params_stream, galois_key_stream, relin_key_stream, &secret_key_stream);
    }

    CKKSCiphertext DebugEval::encrypt(const vector<double> &coeffs) {
        return encrypt(coeffs, homomorphic_eval->context->max_ciphertext_level());
    }

    CKKSCiphertext DebugEval::encrypt(const vector<double> &coeffs, int level) {
        if (level < 0) {
            LOG_AND_THROW_STREAM("Explicit encryption level must be non-negative, got " << level);
        }

        scale_estimator->update_plaintext_max_val(coeffs);
        CKKSCiphertext destination = homomorphic_eval->encrypt(coeffs, level);
        destination.raw_pt = coeffs;
        return destination;
    }

    vector<double> DebugEval::decrypt(const CKKSCiphertext &encrypted) {
        return decrypt(encrypted, false);
    }

    vector<double> DebugEval::decrypt(const CKKSCiphertext &encrypted, bool suppress_warnings) {
        return homomorphic_eval->decrypt(encrypted, suppress_warnings);
    }

    int DebugEval::num_slots() const {
        return homomorphic_eval->num_slots();
    }

    uint64_t DebugEval::get_last_prime_internal(const CKKSCiphertext &ct) const {
        return homomorphic_eval->get_last_prime_internal(ct);
    }

    // print some debug info
    void DebugEval::print_stats(const CKKSCiphertext &ct) {
        homomorphic_eval->print_stats(ct);
        scale_estimator->print_stats(ct);

        double norm = 0;

        // decrypt to compute the approximate plaintext
        vector<double> homom_plaintext = decrypt(ct, true);
        vector<double> exact_plaintext = ct.raw_pt;

        norm = relative_error(exact_plaintext, homom_plaintext);
        if (abs(log2(ct.scale()) - log2(ct.backend_scale())) > 0.1) {
            LOG_AND_THROW_STREAM("Internal error: HIT scale does not match SEAL scale: " << log2(ct.scale()) << " != "
                                                                                         << ct.backend_scale());
        }

        VLOG(VLOG_EVAL) << setprecision(8) << "    + Approximation norm: " << norm;

        int max_print_size = 8;
        stringstream verbose_info;
        verbose_info << "    + Homom Result:   < ";
        for (int i = 0; i < min(max_print_size, static_cast<int>(homom_plaintext.size())); i++) {
            verbose_info << setprecision(8) << homom_plaintext[i] << ", ";
        }
        if (homom_plaintext.size() > max_print_size) {
            verbose_info << "... ";
        }
        verbose_info << ">";
        VLOG(VLOG_EVAL) << verbose_info.str();

        if (norm > MAX_NORM) {
            max_print_size = 32;
            stringstream expect_debug_result;
            expect_debug_result << "    + DEBUG Expected result: <";
            for (int i = 0; i < min(max_print_size, static_cast<int>(exact_plaintext.size())); i++) {
                expect_debug_result << setprecision(8) << exact_plaintext[i];
                if (i < exact_plaintext.size() - 1) {
                    expect_debug_result << ", ";
                }
            }
            if (exact_plaintext.size() > max_print_size) {
                expect_debug_result << "..., ";
            }
            expect_debug_result << ">";
            LOG(ERROR) << expect_debug_result.str();

            stringstream actual_debug_result;
            actual_debug_result << "    + DEBUG Actual result:   <";
            for (int i = 0; i < min(max_print_size, static_cast<int>(homom_plaintext.size())); i++) {
                actual_debug_result << setprecision(8) << homom_plaintext[i];
                if (i < exact_plaintext.size() - 1) {
                    actual_debug_result << ", ";
                }
            }
            if (homom_plaintext.size() > max_print_size) {
                actual_debug_result << "..., ";
            }
            actual_debug_result << ">";
            LOG(ERROR) << actual_debug_result.str();

            HomomorphicEval::PoolObject<Encoder> e = homomorphic_eval->get_encoder();
            Plaintext encoded_plain = encodeNTTAtLvlNew(homomorphic_eval->context->ckks_params.lattigo_params, e.ref(),
                                                        ct.raw_pt, ct.he_level(), ct.scale());
            vector<double> decoded_plain = ::decode(e.ref(), encoded_plain, log2(num_slots()));

            // the exact_plaintext and homom_plaintext should have the same length.
            // decoded_plain is full-dimensional, however. This may not match
            // the dimension of exact_plaintext if the plaintext in question is a
            // vector, so we need to truncate the decoded value.
            vector<double> truncated_decoded_plain(decoded_plain.begin(),
                                                   decoded_plain.begin() + exact_plaintext.size());
            double norm2 = relative_error(exact_plaintext, truncated_decoded_plain);
            double norm3 = relative_error(truncated_decoded_plain, homom_plaintext);

            LOG(ERROR) << "Encoding norm: " << norm2;
            LOG(ERROR) << "Encryption norm: " << norm3;

            LOG_AND_THROW_STREAM("Plaintext and ciphertext divergence: " << norm << " > " << MAX_NORM << ". Scale is "
                                                                         << homomorphic_eval->context->log_scale()
                                                                         << " bits. See error log for more details.");
        }
    }

    void DebugEval::rotate_right_inplace_internal(CKKSCiphertext &ct, int steps) {
        homomorphic_eval->rotate_right_inplace_internal(ct, steps);
        scale_estimator->rotate_right_inplace_internal(ct, steps);
    }

    void DebugEval::rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) {
        homomorphic_eval->rotate_left_inplace_internal(ct, steps);
        scale_estimator->rotate_left_inplace_internal(ct, steps);
    }

    void DebugEval::negate_inplace_internal(CKKSCiphertext &ct) {
        homomorphic_eval->negate_inplace_internal(ct);
        scale_estimator->negate_inplace_internal(ct);
    }

    void DebugEval::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        homomorphic_eval->add_inplace_internal(ct1, ct2);
        scale_estimator->add_inplace_internal(ct1, ct2);
    }

    void DebugEval::add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        homomorphic_eval->add_plain_inplace_internal(ct, scalar);
        scale_estimator->add_plain_inplace_internal(ct, scalar);
    }

    void DebugEval::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        homomorphic_eval->add_plain_inplace_internal(ct, plain);
        scale_estimator->add_plain_inplace_internal(ct, plain);
    }

    void DebugEval::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        homomorphic_eval->sub_inplace_internal(ct1, ct2);
        scale_estimator->sub_inplace_internal(ct1, ct2);
    }

    void DebugEval::sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        homomorphic_eval->sub_plain_inplace_internal(ct, scalar);
        scale_estimator->sub_plain_inplace_internal(ct, scalar);
    }

    void DebugEval::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        homomorphic_eval->sub_plain_inplace_internal(ct, plain);
        scale_estimator->sub_plain_inplace_internal(ct, plain);
    }

    void DebugEval::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        homomorphic_eval->multiply_inplace_internal(ct1, ct2);
        scale_estimator->multiply_inplace_internal(ct1, ct2);
    }

    void DebugEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        homomorphic_eval->multiply_plain_inplace_internal(ct, scalar);
        scale_estimator->multiply_plain_inplace_internal(ct, scalar);
    }

    void DebugEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        homomorphic_eval->multiply_plain_inplace_internal(ct, plain);
        scale_estimator->multiply_plain_inplace_internal(ct, plain);
    }

    void DebugEval::square_inplace_internal(CKKSCiphertext &ct) {
        homomorphic_eval->square_inplace_internal(ct);
        scale_estimator->square_inplace_internal(ct);
    }

    void DebugEval::reduce_level_to_inplace_internal(CKKSCiphertext &ct, int level) {
        homomorphic_eval->reduce_level_to_inplace_internal(ct, level);
        scale_estimator->reduce_level_to_inplace_internal(ct, level);
    }

    void DebugEval::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        uint64_t p = homomorphic_eval->context->get_qi(ct.he_level());
        double prime_bit_len = log2(p);

        homomorphic_eval->rescale_to_next_inplace_internal(ct);
        scale_estimator->rescale_to_next_inplace_internal(ct);

        // for some reason, the default is to print doubles with no decimal places.
        // To get decimal places, add `<< fixed << setprecision(2)` before printing the log.
        // Note that you'll need a lot of decimal places because these values are very close
        // to an integer.
        VLOG(VLOG_EVAL) << "    + Scaled plaintext down by the ~" << prime_bit_len << "-bit prime " << hex << p << dec;
    }

    void DebugEval::relinearize_inplace_internal(CKKSCiphertext &ct) {
        homomorphic_eval->relinearize_inplace_internal(ct);
        scale_estimator->relinearize_inplace_internal(ct);
    }

    void DebugEval::bootstrap_inplace_internal(CKKSCiphertext &ct, bool rescale_for_bootstrapping) {
        homomorphic_eval->bootstrap_inplace_internal(ct, rescale_for_bootstrapping);
        scale_estimator->bootstrap_inplace_internal(ct, rescale_for_bootstrapping);
    }
}  // namespace hit
