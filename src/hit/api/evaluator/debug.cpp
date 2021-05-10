// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "debug.h"

#include <glog/logging.h>

#include <iomanip>

#include "../../common.h"
#include "../../latticpputils.h"
#include "../evaluator.h"

using namespace std;

namespace hit {
    void DebugEval::constructor_common(int num_slots) {
        /*
        // use the _private_ ScaleEstimator constructor to avoid creating two sets of CKKS params
        scale_estimator = new ScaleEstimator(num_slots, *homomorphic_eval);
        log_scale_ = homomorphic_eval->log_scale_;

        print_parameters(homomorphic_eval->context);

        // There are convenience method for accessing the SEALContext::ContextData for
        // some of the most important levels:

        //     SEALContext::key_context_data(): access to key level ContextData
        //     SEALContext::first_context_data(): access to highest data level ContextData
        //     SEALContext::last_context_data(): access to lowest level ContextData

        // We iterate over the chain and print the parms_id for each set of parameters.
        VLOG(VLOG_VERBOSE) << "Print the modulus switching chain.";

        // First print the key level parameter information.
        auto context_data = homomorphic_eval->context->key_context_data();
        VLOG(VLOG_VERBOSE) << "----> Level (chain index): " << context_data->chain_index()
                           << " ...... key_context_data()";
        VLOG(VLOG_VERBOSE) << "      parms_id: " << context_data->parms_id();
        stringstream key_level_primes;
        for (const auto &prime : context_data->parms().coeff_modulus()) {
            key_level_primes << prime.value() << " ";
        }
        VLOG(VLOG_VERBOSE) << "      coeff_modulus primes: " << hex << key_level_primes.str() << dec;
        VLOG(VLOG_VERBOSE) << "\\";

        // Next iterate over the remaining (data) levels.
        context_data = homomorphic_eval->context->first_context_data();
        while (context_data) {
            VLOG(VLOG_VERBOSE) << " \\--> Level (chain index): " << context_data->chain_index();
            if (context_data->parms_id() == homomorphic_eval->context->first_parms_id()) {
                VLOG(VLOG_VERBOSE) << " ...... first_context_data()";
            } else if (context_data->parms_id() == homomorphic_eval->context->last_parms_id()) {
                VLOG(VLOG_VERBOSE) << " ...... last_context_data()";
            }
            VLOG(VLOG_VERBOSE) << "      parms_id: " << context_data->parms_id();
            stringstream data_level_primes;
            for (const auto &prime : context_data->parms().coeff_modulus()) {
                data_level_primes << prime.value() << " ";
            }
            VLOG(VLOG_VERBOSE) << "      coeff_modulus primes: " << hex << data_level_primes.str() << dec;
            VLOG(VLOG_VERBOSE) << "\\";

            // Step forward in the chain.
            context_data = context_data->next_context_data();
        }
        VLOG(VLOG_VERBOSE) << " End of chain reached";
        */
    }

    DebugEval::DebugEval(int num_slots, int multiplicative_depth, int log_scale, bool use_seal_params,
                         const vector<int> &galois_steps) {
        homomorphic_eval =
            new HomomorphicEval(num_slots, multiplicative_depth, log_scale, use_seal_params, galois_steps);
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
        return encrypt(coeffs, -1);
    }

    CKKSCiphertext DebugEval::encrypt(const vector<double> &coeffs, int level) {
        scale_estimator->update_plaintext_max_val(coeffs);
        CKKSCiphertext destination = homomorphic_eval->encrypt(coeffs, level);
        destination.raw_pt = coeffs;
        return destination;
    }

    vector<double> DebugEval::decrypt(const CKKSCiphertext &encrypted) const {
        return decrypt(encrypted, false);
    }

    vector<double> DebugEval::decrypt(const CKKSCiphertext &encrypted, bool suppress_warnings) const {
        return homomorphic_eval->decrypt(encrypted, suppress_warnings);
    }

    int DebugEval::num_slots() const {
        return homomorphic_eval->num_slots();
    }

    uint64_t DebugEval::get_last_prime_internal(const CKKSCiphertext &ct) const {
        return homomorphic_eval->get_last_prime_internal(ct);
    }

    // print some debug info
    void DebugEval::print_stats(const CKKSCiphertext &ct) const {
        // homomorphic_eval->print_stats(ct);
        // scale_estimator->print_stats(ct);

        // double norm = 0;

        // // decrypt to compute the approximate plaintext
        // vector<double> homom_plaintext = decrypt(ct, true);
        // vector<double> exact_plaintext = ct.raw_pt;

        // norm = relative_error(exact_plaintext, homom_plaintext);
        // if (abs(log2(ct.scale()) - log2(ct.seal_ct.scale())) > 0.1) {
        //     LOG_AND_THROW_STREAM("Internal error: HIT scale does not match SEAL scale: " << log2(ct.scale()) << " != "
        //                                                                                  << ct.seal_ct.scale());
        // }

        // VLOG(VLOG_EVAL) << setprecision(8) << "    + Approximation norm: " << norm;

        // int max_print_size = 8;
        // stringstream verbose_info;
        // verbose_info << "    + Homom Result:   < ";
        // for (int i = 0; i < min(max_print_size, static_cast<int>(homom_plaintext.size())); i++) {
        //     verbose_info << setprecision(8) << homom_plaintext[i] << ", ";
        // }
        // if (homom_plaintext.size() > max_print_size) {
        //     verbose_info << "... ";
        // }
        // verbose_info << ">";
        // VLOG(VLOG_EVAL) << verbose_info.str();

        // if (norm > MAX_NORM) {
        //     max_print_size = 32;
        //     stringstream expect_debug_result;
        //     expect_debug_result << "    + DEBUG Expected result: <";
        //     for (int i = 0; i < min(max_print_size, static_cast<int>(exact_plaintext.size())); i++) {
        //         expect_debug_result << setprecision(8) << exact_plaintext[i];
        //         if (i < exact_plaintext.size() - 1) {
        //             expect_debug_result << ", ";
        //         }
        //     }
        //     if (exact_plaintext.size() > max_print_size) {
        //         expect_debug_result << "..., ";
        //     }
        //     expect_debug_result << ">";
        //     LOG(ERROR) << expect_debug_result.str();

        //     stringstream actual_debug_result;
        //     actual_debug_result << "    + DEBUG Actual result:   <";
        //     for (int i = 0; i < min(max_print_size, static_cast<int>(homom_plaintext.size())); i++) {
        //         actual_debug_result << setprecision(8) << homom_plaintext[i];
        //         if (i < exact_plaintext.size() - 1) {
        //             actual_debug_result << ", ";
        //         }
        //     }
        //     if (homom_plaintext.size() > max_print_size) {
        //         actual_debug_result << "..., ";
        //     }
        //     actual_debug_result << ">";
        //     LOG(ERROR) << actual_debug_result.str();

        //     Plaintext encoded_plain;
        //     homomorphic_eval->encoder->encode(ct.raw_pt, pow(2, log_scale_), encoded_plain);

        //     vector<double> decoded_plain;
        //     homomorphic_eval->encoder->decode(encoded_plain, decoded_plain);

        //     // the exact_plaintext and homom_plaintext should have the same length.
        //     // decoded_plain is full-dimensional, however. This may not match
        //     // the dimension of exact_plaintext if the plaintext in question is a
        //     // vector, so we need to truncate the decoded value.
        //     vector<double> truncated_decoded_plain(decoded_plain.begin(),
        //                                            decoded_plain.begin() + exact_plaintext.size());
        //     double norm2 = relative_error(exact_plaintext, truncated_decoded_plain);
        //     double norm3 = relative_error(truncated_decoded_plain, homom_plaintext);

        //     LOG(ERROR) << "Encoding norm: " << norm2;
        //     LOG(ERROR) << "Encryption norm: " << norm3;

        //     LOG_AND_THROW_STREAM("Plaintext and ciphertext divergence: " << norm << " > " << MAX_NORM << ". Scale is "
        //                                                                  << log_scale_
        //                                                                  << " bits. See error log for more details.");
        // }
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
        uint64_t p = homomorphic_eval->context->last_prime(ct.he_level());
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
}  // namespace hit
