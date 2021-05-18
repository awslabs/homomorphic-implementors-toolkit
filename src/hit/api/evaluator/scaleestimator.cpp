// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "scaleestimator.h"

#include <glog/logging.h>

#include <iomanip>

#include "../../common.h"

using namespace std;

namespace hit {

    // it turns out that the lossiness of encoding/decoding strongly depends on
    // this value. For evaluators that don't really use SEAL, but do use CKKS
    // encoding/decoding, this should be set to as high as possible.
    int default_scale_bits = 30;

    ScaleEstimator::ScaleEstimator(int num_slots, int multiplicative_depth) {
        plaintext_eval = new PlaintextEval(num_slots);

        context = make_shared<HEContext>(HEContext(num_slots, multiplicative_depth, default_scale_bits));

        // if scale is too close to 60, SEAL throws the error "encoded values are too large" during encoding.
        estimated_max_log_scale_ = PLAINTEXT_LOG_MAX - 60;
        for (int i = 0; i < context->num_qi(); i++) {
            estimated_max_log_scale_ += log2(context->get_qi(i));
        }
    }

    ScaleEstimator::ScaleEstimator(int num_slots, const HomomorphicEval &homom_eval) {
        plaintext_eval = new PlaintextEval(num_slots);

        // instead of creating a new instance, use the instance provided
        context = homom_eval.context;

        // if scale is too close to 60, SEAL throws the error "encoded values are too large" during encoding.
        estimated_max_log_scale_ = PLAINTEXT_LOG_MAX - 60;
        for (int i = 0; i < context->num_qi(); i++) {
            estimated_max_log_scale_ += log2(context->get_qi(i));
        }
    }

    ScaleEstimator::~ScaleEstimator() {
        delete plaintext_eval;
    }

    CKKSCiphertext ScaleEstimator::encrypt(const vector<double> &coeffs) {
        return encrypt(coeffs, -1);
    }

    CKKSCiphertext ScaleEstimator::encrypt(const vector<double> &coeffs, int level) {
        update_plaintext_max_val(coeffs);

        if (coeffs.size() != context->num_slots()) {
            // bad things can happen if you don't plan for your input to be smaller than the ciphertext
            // This forces the caller to ensure that the input has the correct size or is at least appropriately padded
            LOG_AND_THROW_STREAM("You can only encrypt vectors which have exactly as many "
                                 << " coefficients as the number of plaintext slots: Expected " << context->num_slots()
                                 << " coefficients, but " << coeffs.size() << " were provided");
        }

        if (level == -1) {
            level = context->max_ciphertext_level();
        }

        double scale = pow(2, context->log_scale());
        // order of operations is very important: floating point arithmetic is not associative
        for (int i = context->max_ciphertext_level(); i > level; i--) {
            scale = (scale * scale) / static_cast<double>(context->get_qi(i));
        }

        CKKSCiphertext destination;
        destination.he_level_ = level;
        destination.scale_ = scale;
        destination.raw_pt = coeffs;
        destination.num_slots_ = context->num_slots();
        destination.initialized = true;

        return destination;
    }

    void ScaleEstimator::update_plaintext_max_val(const vector<double> &coeffs) {
        double x = l_inf_norm(coeffs);
        // account for a freshly-encrypted ciphertext
        // if this is a depth-0 computation *AND* the parameters are such that it is a no-op,
        // this is the only way we can account for the values in the input. We have to encrypt them,
        // and if the scale is ~2^60, encoding will (rightly) fail
        int top_he_level = context->max_ciphertext_level();
        if (top_he_level == 0) {
            scoped_lock lock(mutex_);
            estimated_max_log_scale_ = min(estimated_max_log_scale_, PLAINTEXT_LOG_MAX - log2(x));
        }
    }

    uint64_t ScaleEstimator::get_last_prime_internal(const CKKSCiphertext &ct) const {
        return context->get_qi(ct.he_level());
    }

    int ScaleEstimator::num_slots() const {
        return context->num_slots();
    }

    // print some debug info
    void ScaleEstimator::print_stats(const CKKSCiphertext &ct) {
        double exact_plaintext_max_val = l_inf_norm(ct.raw_pt);
        double log_modulus = 0;
        for (int i = 0; i <= ct.he_level(); i++) {
            log_modulus += log2(context->get_qi(i));
        }
        plaintext_eval->print_stats(ct);
        VLOG(VLOG_EVAL) << "    + Level: " << ct.he_level();
        VLOG(VLOG_EVAL) << "    + Plaintext logmax: " << log2(exact_plaintext_max_val)
                        << " bits (scaled: " << log2(ct.scale()) + log2(exact_plaintext_max_val) << " bits)";
        VLOG(VLOG_EVAL) << "    + Total modulus size: " << setprecision(4) << log_modulus << " bits";
        VLOG(VLOG_EVAL) << "    + Theoretical max log scale: " << get_estimated_max_log_scale() << " bits";
    }

    // At all times, we need ct.scale*l_inf_norm(ct.getPlaintext()) <~ q/4
    // Define ct.scale = pow(2, log_scale_ * i) for i \in {1,2}
    // If(i > ct.he_level): estimated_max_log_scale_ \le
    //      (PLAINTEXT_LOG_MAX-log2(l_inf_norm(ct.getPlaintext()))/(i-ct.he_level))
    // Else if (i == ct.he_level):
    //      log2(l_inf_norm(ct.getPlaintext())) <= 58
    // Else [i < ct.he_level]:
    //      In this case, the constraint becomes estimated_max_log_scale_ > (something less than 0).
    //      this is bogus, so nothing to do.
    void ScaleEstimator::update_max_log_scale(const CKKSCiphertext &ct) {
        // update the estimated_max_log_scale_
        auto scale_exp = static_cast<int>(round(log2(ct.scale()) / context->log_scale()));
        if (scale_exp != 1 && scale_exp != 2) {
            LOG_AND_THROW_STREAM("Internal error: scale_exp is not 1 or 2: got "
                                 << scale_exp << ". "
                                 << "HIT ciphertext scale is " << log2(ct.scale()) << " bits, and nominal scale is "
                                 << context->log_scale() << " bits");
        }
        if (scale_exp > ct.he_level()) {
            auto estimated_scale = (PLAINTEXT_LOG_MAX - log2(l_inf_norm(ct.raw_pt))) / (scale_exp - ct.he_level());
            {
                scoped_lock lock(mutex_);
                estimated_max_log_scale_ = min(estimated_max_log_scale_, estimated_scale);
            }
        } else if (scale_exp == ct.he_level() && log2(l_inf_norm(ct.raw_pt)) > PLAINTEXT_LOG_MAX) {
            LOG_AND_THROW_STREAM("The maximum value in the plaintext is "
                                 << log2(l_inf_norm(ct.raw_pt)) << " bits which exceeds SEAL's capacity of "
                                 << PLAINTEXT_LOG_MAX << " bits. Overflow is imminent.");
        }
    }

    void ScaleEstimator::rotate_right_inplace_internal(CKKSCiphertext &ct, int steps) {
        plaintext_eval->rotate_right_inplace_internal(ct, steps);
    }

    void ScaleEstimator::rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) {
        plaintext_eval->rotate_left_inplace_internal(ct, steps);
    }

    void ScaleEstimator::negate_inplace_internal(CKKSCiphertext &ct) {
        plaintext_eval->negate_inplace_internal(ct);
    }

    void ScaleEstimator::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        plaintext_eval->add_inplace_internal(ct1, ct2);
        update_max_log_scale(ct1);
    }

    void ScaleEstimator::add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        plaintext_eval->add_plain_inplace_internal(ct, scalar);
        update_max_log_scale(ct);
    }

    void ScaleEstimator::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        plaintext_eval->add_plain_inplace_internal(ct, plain);
        update_max_log_scale(ct);
    }

    void ScaleEstimator::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        plaintext_eval->sub_inplace_internal(ct1, ct2);
        update_max_log_scale(ct1);
    }

    void ScaleEstimator::sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        plaintext_eval->sub_plain_inplace_internal(ct, scalar);
        update_max_log_scale(ct);
    }

    void ScaleEstimator::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        plaintext_eval->sub_plain_inplace_internal(ct, plain);
        update_max_log_scale(ct);
    }

    void ScaleEstimator::temp_square_scale(CKKSCiphertext &ct) {
        double input_scale = ct.scale();
        ct.scale_ *= ct.scale();
        update_max_log_scale(ct);
        ct.scale_ = input_scale;
    }

    void ScaleEstimator::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        plaintext_eval->multiply_inplace_internal(ct1, ct2);
        temp_square_scale(ct1);
    }

    void ScaleEstimator::multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        plaintext_eval->multiply_plain_inplace_internal(ct, scalar);
        temp_square_scale(ct);
    }

    void ScaleEstimator::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        plaintext_eval->multiply_plain_inplace_internal(ct, plain);
        temp_square_scale(ct);
    }

    void ScaleEstimator::square_inplace_internal(CKKSCiphertext &ct) {
        plaintext_eval->square_inplace_internal(ct);
        temp_square_scale(ct);
    }

    void ScaleEstimator::reduce_level_to_inplace_internal(CKKSCiphertext &ct, int level) {
        if (level < 0) {
            LOG_AND_THROW_STREAM("Target level for level reduction must be non-negative, got " << level);
        }

        plaintext_eval->reduce_level_to_inplace_internal(ct, level);

        int input_level = ct.he_level();
        double input_scale = ct.scale();

        // update the metadata so that we can update the max_log_scale
        reduce_metadata_to_level(ct, level);
        update_max_log_scale(ct);

        // internal functions should not update the ciphertext metadata
        ct.he_level_ = input_level;
        ct.scale_ = input_scale;
    }

    void ScaleEstimator::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        plaintext_eval->rescale_to_next_inplace_internal(ct);

        int input_level = ct.he_level();
        double input_scale = ct.scale();

        // update the metadata so that we can update the max_log_scale
        rescale_metata_to_next(ct);
        update_max_log_scale(ct);

        // internal functions should not update the ciphertext metadata
        ct.he_level_ = input_level;
        ct.scale_ = input_scale;
    }

    double ScaleEstimator::get_estimated_max_log_scale() const {
        /* During the evaluation, update_max_log_scale computed the maximum scale
         * implied by the "correctness" constraint (to prevent the computation
         * from overflowing). But there is another constraint: SEAL limits the
         * maximum size of the modulus (in bits) based on the poly_modulus_degree.
         * We take that constraint into account when reporting the maximum log(scale).
         *
         * Specifically, a SEAL modulus is the product of k primes p_i, where
         * log2(p_1)=log2(p_k)=60 and log2(p_i)=s=log(scale). Thus s must be less
         * than (maxModBits-120)/(k-2)
         */
        auto estimated_log_scale = static_cast<double>(PLAINTEXT_LOG_MAX);
        {
            shared_lock lock(mutex_);
            estimated_log_scale = min(estimated_log_scale, estimated_max_log_scale_);
        }
        int top_he_level = context->max_ciphertext_level();
        if (top_he_level > 0) {
            int max_mod_bits = poly_degree_to_max_mod_bits(2 * context->num_slots());
            return min(estimated_log_scale, (max_mod_bits - 120) / static_cast<double>(top_he_level));
        }
        return estimated_log_scale;
    }
}  // namespace hit
