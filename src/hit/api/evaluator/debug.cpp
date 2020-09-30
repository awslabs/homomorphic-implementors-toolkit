// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "debug.h"
#include "../../sealutils.h"

#include <glog/logging.h>

#include <iomanip>

#include "../../common.h"
#include "../evaluator.h"

using namespace std;
using namespace seal;

namespace hit {

    void DebugEval::constructor_common(int num_slots, int multiplicative_depth) {
        // use the _private_ ScaleEstimator constructor to avoid creating two sets of CKKS params
        scale_estimator = new ScaleEstimator(num_slots, multiplicative_depth, *homomorphic_eval);
        context = homomorphic_eval->context;
        log_scale_ = homomorphic_eval->log_scale_;
        encoder = homomorphic_eval->encoder;
        seal_encryptor = homomorphic_eval->seal_encryptor;

        if (VLOG_IS_ON(LOG_VERBOSE)) {
            print_parameters(context);

            // There are convenience method for accessing the SEALContext::ContextData for
            // some of the most important levels:

            //     SEALContext::key_context_data(): access to key level ContextData
            //     SEALContext::first_context_data(): access to highest data level ContextData
            //     SEALContext::last_context_data(): access to lowest level ContextData

            // We iterate over the chain and print the parms_id for each set of parameters.
            LOG(INFO) << "Print the modulus switching chain.";

            // First print the key level parameter information.
            auto context_data = context->key_context_data();
            LOG(INFO) << "----> Level (chain index): " << context_data->chain_index() << " ...... key_context_data()";
            LOG(INFO) << "      parms_id: " << context_data->parms_id();
            stringstream key_level_primes;
            for (const auto &prime : context_data->parms().coeff_modulus()) {
                key_level_primes << prime.value() << " ";
            }
            LOG(INFO) << "      coeff_modulus primes: " << hex << key_level_primes.str() << dec;
            LOG(INFO) << "\\";

            // Next iterate over the remaining (data) levels.
            context_data = context->first_context_data();
            while (context_data) {
                LOG(INFO) << " \\--> Level (chain index): " << context_data->chain_index();
                if (context_data->parms_id() == context->first_parms_id()) {
                    LOG(INFO) << " ...... first_context_data()";
                } else if (context_data->parms_id() == context->last_parms_id()) {
                    LOG(INFO) << " ...... last_context_data()";
                }
                LOG(INFO) << "      parms_id: " << context_data->parms_id() << endl;
                stringstream data_level_primes;
                for (const auto &prime : context_data->parms().coeff_modulus()) {
                    data_level_primes << prime.value() << " ";
                }
                LOG(INFO) << "      coeff_modulus primes: " << hex << data_level_primes.str() << dec;
                LOG(INFO) << "\\";

                // Step forward in the chain.
                context_data = context_data->next_context_data();
            }
            LOG(INFO) << " End of chain reached" << endl;
        }
    }

    DebugEval::DebugEval(int num_slots, int multiplicative_depth, int log_scale, bool use_seal_params,
                         const vector<int> &galois_steps) {
        homomorphic_eval = new HomomorphicEval(num_slots, multiplicative_depth, log_scale, use_seal_params, galois_steps);
        homomorphic_eval->update_metadata_ = false;
        constructor_common(num_slots, multiplicative_depth);
    }

    DebugEval::DebugEval(istream &params_stream, istream &galois_key_stream,
                         istream &relin_key_stream, istream &secret_key_stream) {
        homomorphic_eval = new HomomorphicEval(params_stream, galois_key_stream, relin_key_stream, secret_key_stream);
        homomorphic_eval->update_metadata_ = false;
        constructor_common(homomorphic_eval->encoder->slot_count(), homomorphic_eval->context->first_context_data()->chain_index());
    }

    DebugEval::~DebugEval() {
        delete homomorphic_eval;
        delete scale_estimator;
    }

    void DebugEval::save(ostream &params_stream, ostream &galois_key_stream, ostream &relin_key_stream,
                         ostream &secret_key_stream) {
        homomorphic_eval->save(params_stream, galois_key_stream, relin_key_stream, &secret_key_stream);
    }

    CKKSCiphertext DebugEval::encrypt(const vector<double> &coeffs, int level) {
        scale_estimator->update_plaintext_max_val(coeffs);

        int num_slots_ = encoder->slot_count();
        if (coeffs.size() != num_slots_) {
            // bad things can happen if you don't plan for your input to be smaller than the ciphertext
            // This forces the caller to ensure that the input has the correct size or is at least appropriately padded
            throw invalid_argument(
                "You can only encrypt vectors which have exactly as many coefficients as the number of plaintext "
                "slots: Expected " +
                to_string(num_slots_) + ", got " + to_string(coeffs.size()));
        }

        if (level == -1) {
            level = context->first_context_data()->chain_index();
        }

        auto context_data = context->first_context_data();
        double scale = pow(2, log_scale_);
        while (context_data->chain_index() > level) {
            // order of operations is very important: floating point arithmetic is not associative
            scale = (scale * scale) / static_cast<double>(context_data->parms().coeff_modulus().back().value());
            context_data = context_data->next_context_data();
        }

        CKKSCiphertext destination;
        destination.he_level_ = level;
        destination.scale_ = scale;
        destination.raw_pt = coeffs;

        Plaintext temp;
        encoder->encode(coeffs, context_data->parms_id(), scale, temp);
        seal_encryptor->encrypt(temp, destination.seal_ct);

        destination.num_slots_ = num_slots_;
        destination.initialized = true;

        return destination;
    }

    vector<double> DebugEval::decrypt(const CKKSCiphertext &encrypted) const {
        return homomorphic_eval->decrypt(encrypted);
    }

    void DebugEval::reset() {
        homomorphic_eval->reset();
        scale_estimator->reset();
    }

    // Verify that the ciphertext is either at its expected scale (based on its level),
    // or is at the square of its expected scale.
    void DebugEval::check_scale(const CKKSCiphertext &ct) const {
        auto context_data = context->first_context_data();
        double expected_scale = pow(2,log_scale_);
        while (context_data->chain_index() > ct.he_level()) {
            expected_scale = (expected_scale * expected_scale) /
                            static_cast<double>(context_data->parms().coeff_modulus().back().value());
            context_data = context_data->next_context_data();
        }
        if (ct.seal_ct.scale() != expected_scale && ct.seal_ct.scale() != expected_scale * expected_scale) {
            throw invalid_argument("CHECK_SCALE: Expected " + to_string(expected_scale) + "^{1,2}, got " +
                                   to_string(ct.seal_ct.scale()));
        }
        if (ct.seal_ct.scale() != ct.scale()) {
            throw invalid_argument("HIT scale calculation does not match SEAL.");
        }
    }

    // print some debug info
    void DebugEval::print_stats(const CKKSCiphertext &ct) const {
        double norm = 0;

        // decrypt to compute the approximate plaintext
        vector<double> homom_plaintext = decrypt(ct);
        vector<double> exact_plaintext = ct.raw_pt;

        norm = diff2_norm(exact_plaintext, homom_plaintext);
        if (abs(log2(ct.scale()) - log2(ct.seal_ct.scale())) > 0.1) {
            stringstream buffer;
            buffer << "INTERNAL ERROR: SCALE COMPUTATION IS INCORRECT: " << log2(ct.scale())
                   << " != " << ct.seal_ct.scale();
            throw invalid_argument(buffer.str());
        }

        VLOG(LOG_VERBOSE) << setprecision(8) << "    + Approximation norm: " << norm;

        int max_print_size = 8;
        if (VLOG_IS_ON(LOG_VERBOSE)) {
            stringstream verbose_info;
            verbose_info << "    + Homom Result:   < ";
            for (int i = 0; i < min(max_print_size, static_cast<int>(homom_plaintext.size())); i++) {
                verbose_info << setprecision(8) << homom_plaintext[i] << ", ";
            }
            if (homom_plaintext.size() > max_print_size) {
                verbose_info << "... ";
            }
            verbose_info << ">";
            VLOG(LOG_VERBOSE) << verbose_info.str();
        }

        if (norm > MAX_NORM) {
            stringstream buffer;
            buffer << "DebugEvaluator: plaintext and ciphertext divergence: " << norm << " > " << MAX_NORM
                   << ". Scale is " << log_scale_ << " bits.";

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
            LOG(INFO) << expect_debug_result.str();

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
            LOG(INFO) << actual_debug_result.str();

            Plaintext encoded_plain;
            homomorphic_eval->encoder->encode(ct.raw_pt, pow(2,log_scale_), encoded_plain);

            vector<double> decoded_plain;
            homomorphic_eval->encoder->decode(encoded_plain, decoded_plain);

            // the exact_plaintext and homom_plaintext should have the same length.
            // decoded_plain is full-dimensional, however. This may not match
            // the dimension of exact_plaintext if the plaintext in question is a
            // vector, so we need to truncate the decoded value.
            vector<double> truncated_decoded_plain(decoded_plain.begin(),
                                                   decoded_plain.begin() + exact_plaintext.size());
            double norm2 = diff2_norm(exact_plaintext, truncated_decoded_plain);
            double norm3 = diff2_norm(truncated_decoded_plain, homom_plaintext);

            LOG(INFO) << "Encoding norm: " << norm2;
            LOG(INFO) << "Encryption norm: " << norm3;

            throw invalid_argument(buffer.str());
        }
    }

    void DebugEval::rotate_right_inplace_internal(CKKSCiphertext &ct, int steps) {
        check_scale(ct);
        homomorphic_eval->rotate_right_inplace_internal(ct, steps);
        scale_estimator->rotate_right_inplace_internal(ct, steps);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) {
        check_scale(ct);
        homomorphic_eval->rotate_left_inplace_internal(ct, steps);
        scale_estimator->rotate_left_inplace_internal(ct, steps);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::negate_inplace_internal(CKKSCiphertext &ct) {
        check_scale(ct);
        homomorphic_eval->negate_inplace_internal(ct);
        scale_estimator->negate_inplace_internal(ct);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        check_scale(ct1);
        check_scale(ct2);
        homomorphic_eval->add_inplace_internal(ct1, ct2);
        scale_estimator->add_inplace_internal(ct1, ct2);

        print_stats(ct1);
        check_scale(ct1);
    }

    void DebugEval::add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        check_scale(ct);
        homomorphic_eval->add_plain_inplace_internal(ct, scalar);
        scale_estimator->add_plain_inplace_internal(ct, scalar);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        check_scale(ct);
        homomorphic_eval->add_plain_inplace_internal(ct, plain);
        scale_estimator->add_plain_inplace_internal(ct, plain);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        check_scale(ct1);
        check_scale(ct2);
        homomorphic_eval->sub_inplace_internal(ct1, ct2);
        scale_estimator->sub_inplace_internal(ct1, ct2);

        print_stats(ct1);
        check_scale(ct1);
    }

    void DebugEval::sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        check_scale(ct);
        homomorphic_eval->sub_plain_inplace_internal(ct, scalar);
        scale_estimator->sub_plain_inplace_internal(ct, scalar);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        check_scale(ct);
        homomorphic_eval->sub_plain_inplace_internal(ct, plain);
        scale_estimator->sub_plain_inplace_internal(ct, plain);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        check_scale(ct1);
        check_scale(ct2);
        homomorphic_eval->multiply_inplace_internal(ct1, ct2);
        scale_estimator->multiply_inplace_internal(ct1, ct2);

        print_stats(ct1);
        check_scale(ct1);
    }

    void DebugEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        check_scale(ct);
        homomorphic_eval->multiply_plain_inplace_internal(ct, scalar);
        scale_estimator->multiply_plain_inplace_internal(ct, scalar);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        check_scale(ct);
        homomorphic_eval->multiply_plain_inplace_internal(ct, plain);
        scale_estimator->multiply_plain_inplace_internal(ct, plain);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::square_inplace_internal(CKKSCiphertext &ct) {
        check_scale(ct);
        homomorphic_eval->square_inplace_internal(ct);
        scale_estimator->square_inplace_internal(ct);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::reduce_level_to_inplace_internal(CKKSCiphertext &ct, int level) {
        check_scale(ct);
        homomorphic_eval->reduce_level_to_inplace_internal(ct, level);
        scale_estimator->reduce_level_to_inplace_internal(ct, level);

        print_stats(ct);
        check_scale(ct);
    }

    void DebugEval::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        auto context_data = getContextData(ct);
        uint64_t p = context_data->parms().coeff_modulus().back().value();
        double prime_bit_len = log2(p);

        check_scale(ct);
        homomorphic_eval->rescale_to_next_inplace_internal(ct);
        scale_estimator->rescale_to_next_inplace_internal(ct);

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
        homomorphic_eval->relinearize_inplace_internal(ct);
        scale_estimator->relinearize_inplace_internal(ct);

        print_stats(ct);
        check_scale(ct);
    }
}  // namespace hit
