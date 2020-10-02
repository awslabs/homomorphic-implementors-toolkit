// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "scaleestimator.h"

#include <glog/logging.h>

#include <iomanip>

#include "../../common.h"
#include "../../sealutils.h"

using namespace std;
using namespace seal;

namespace hit {

    // it turns out that the lossiness of encoding/decoding strongly depends on
    // this value. For evaluators that don't really use SEAL, but do use CKKS
    // encoding/decoding, this should be set to as high as possible.
    int defaultScaleBits = 30;

    ScaleEstimator::ScaleEstimator(int num_slots, int multiplicative_depth): log_scale_(defaultScaleBits), num_slots_(num_slots) {
        plaintext_eval = new PlaintextEval(num_slots);

        if (!is_pow2(num_slots) || num_slots < 4096) {
            LOG(FATAL) << "Invalid parameters when creating HomomorphicEval instance: "
                       << "num_slots must be a power of 2, and at least 4096. Got " << num_slots;
        }

        int num_primes = multiplicative_depth + 2;
        vector<int> modulusVector = gen_modulus_vec(num_primes, log_scale_);

        int modBits = 0;
        for(const auto &bits : modulusVector) {
            modBits += bits;
        }
        int min_poly_degree = modulus_to_poly_degree(modBits);
        int poly_modulus_degree = num_slots * 2;
        if (poly_modulus_degree < min_poly_degree) {
            LOG(FATAL) << "Invalid parameters when creating ScaleEstimator instance: "
                       << "Parameters for depth " << multiplicative_depth << " circuits and scale "
                       << log_scale_ << " bits require more than " << num_slots << " plaintext slots.";
        }

        EncryptionParameters params = EncryptionParameters(scheme_type::CKKS);
        params.set_poly_modulus_degree(poly_modulus_degree);
        params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, modulusVector));

        // for large parameter sets, see https://github.com/microsoft/SEAL/issues/84
        context = SEALContext::Create(params, true, sec_level_type::none);

        // if scale is too close to 60, SEAL throws the error "encoded values are too large" during encoding.
        estimated_max_log_scale_ = PLAINTEXT_LOG_MAX - 60;
        auto context_data = context->first_context_data();
        for (const auto &prime : context_data->parms().coeff_modulus()) {
            estimated_max_log_scale_ += log2(prime.value());
        }
    }

    ScaleEstimator::ScaleEstimator(int num_slots, const HomomorphicEval &homom_eval): log_scale_(homom_eval.log_scale_), num_slots_(num_slots),  has_shared_params_(true) {
        plaintext_eval = new PlaintextEval(num_slots);

        // instead of creating a new instance, use the instance provided
        context = homom_eval.context;

        // if scale is too close to 60, SEAL throws the error "encoded values are too large" during encoding.
        estimated_max_log_scale_ = PLAINTEXT_LOG_MAX - 60;
        auto context_data = context->first_context_data();
        for (const auto &prime : context_data->parms().coeff_modulus()) {
            estimated_max_log_scale_ += log2(prime.value());
        }
    }

    ScaleEstimator::~ScaleEstimator() {
        delete plaintext_eval;
    }

    CKKSCiphertext ScaleEstimator::encrypt(const vector<double> &coeffs, int level) {
        update_plaintext_max_val(coeffs);

        if (coeffs.size() != num_slots_) {
            // bad things can happen if you don't plan for your input to be smaller than the ciphertext
            // This forces the caller to ensure that the input has the correct size or is at least appropriately padded
            LOG(FATAL) << "You can only encrypt vectors which have exactly as many "
                       << " coefficients as the number of plaintext slots: Expected "
                       << num_slots_ << " coefficients, but " + << coeffs.size()
                       << " were provided";
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
        destination.num_slots_ = num_slots_;
        destination.initialized = true;

        return destination;
    }

    uint64_t ScaleEstimator::get_last_prime_internal(const CKKSCiphertext &ct) const {
        return get_last_prime(context, ct.he_level());
    }

    int ScaleEstimator::num_slots() const {
        return num_slots_;
    }

    // print some debug info
    void ScaleEstimator::print_stats(const CKKSCiphertext &ct) const {
        double exact_plaintext_max_val = l_inf_norm(ct.raw_pt);
        double log_modulus = 0;
        auto context_data = get_context_data(context, ct.he_level());
        for (const auto &prime : context_data->parms().coeff_modulus()) {
            log_modulus += log2(prime.value());
        }
        plaintext_eval->print_stats(ct);
        VLOG(VLOG_EVAL) << "    + Level: " << ct.he_level();
        VLOG(VLOG_EVAL) << "    + Plaintext logmax: " << log2(exact_plaintext_max_val)
                          << " bits (scaled: " << log2(ct.scale()) + log2(exact_plaintext_max_val) << " bits)";
        VLOG(VLOG_EVAL) << "    + Total modulus size: " << setprecision(4) << log_modulus << " bits";
        VLOG(VLOG_EVAL) << "    + Theoretical max log scale: " << get_estimated_max_log_scale() << " bits";
    }

    // At all times, we need ct.scale*l_inf_norm(ct.getPlaintext()) <~ q/4
    // Define ct.scale = i*pow(2,log_scale_) for i \in {1,2}
    // If(i > ct.he_level): estimated_max_log_scale_ \le
    //      (PLAINTEXT_LOG_MAX-log2(l_inf_norm(ct.getPlaintext()))/(i-ct.he_level))
    // Else if (i == ct.he_level):
    //      log2(l_inf_norm(ct.getPlaintext())) <= 58
    // Else [i < ct.he_level]:
    //      In this case, the constraint becomes estimated_max_log_scale_ > (something less than 0).
    //      this is bogus, so nothing to do.
    void ScaleEstimator::update_max_log_scale(const CKKSCiphertext &ct) {
        // update the estimated_max_log_scale_
        auto scale_exp = static_cast<int>(round(log2(ct.scale()) / log2(pow(2,log_scale_))));
        if (scale_exp != 1 && scale_exp != 2) {
            LOG(FATAL) << "Internal error: scale_exp is not 1 or 2: got " << scale_exp << ". "
                       << "HIT ciphertext scale is " << log2(ct.scale())
                       << " bits, and nominal scale is " << log_scale_ << " bits";
        }
        if (scale_exp > ct.he_level()) {
            auto estimated_scale = (PLAINTEXT_LOG_MAX - log2(l_inf_norm(ct.raw_pt))) / (scale_exp - ct.he_level());
            {
                scoped_lock lock(mutex_);
                estimated_max_log_scale_ = min(estimated_max_log_scale_, estimated_scale);
            }
        } else if (scale_exp == ct.he_level() && log2(l_inf_norm(ct.raw_pt)) > PLAINTEXT_LOG_MAX) {
            LOG(FATAL) << "The maximum value in the plaintext is " << log2(l_inf_norm(ct.raw_pt))
                       << " bits which exceeds SEAL's capacity of " << PLAINTEXT_LOG_MAX
                       << " bits. Overflow is imminent.";
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
            LOG(FATAL) << "Target level for level reduction must be non-negative, got " << level;
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

    void ScaleEstimator::update_plaintext_max_val(const vector<double> &coeffs) {
        double x = l_inf_norm(coeffs);
        // account for a freshly-encrypted ciphertext
        // if this is a depth-0 computation *AND* the parameters are such that it is a no-op,
        // this is the only way we can account for the values in the input. We have to encrypt them,
        // and if the scale is ~2^60, encoding will (rightly) fail
        int top_he_level = context->first_context_data()->chain_index();
        if (top_he_level == 0) {
            scoped_lock lock(mutex_);
            estimated_max_log_scale_ = min(estimated_max_log_scale_, PLAINTEXT_LOG_MAX - log2(x));
        }
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
        int max_mod_bits = poly_degree_to_max_mod_bits(2*num_slots_);
        auto estimated_log_scale = static_cast<double>(PLAINTEXT_LOG_MAX);
        {
            shared_lock lock(mutex_);
            estimated_log_scale = min(estimated_log_scale, estimated_max_log_scale_);
        }
        int top_he_level = context->first_context_data()->chain_index();
        if (top_he_level > 0) {
            return min(estimated_log_scale, (max_mod_bits - 120) / static_cast<double>(top_he_level));
        }
        return estimated_log_scale;
    }
}  // namespace hit
