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

    ScaleEstimator::ScaleEstimator(int num_slots, int multiplicative_depth): base_scale_(defaultScaleBits) {
        plaintext_eval = new PlaintextEval(num_slots);
        depth_finder = new DepthFinder();
        depth_finder->top_he_level_ = multiplicative_depth;

        shared_param_init(num_slots, multiplicative_depth, defaultScaleBits, false);

        // if scale is too close to 60, SEAL throws the error "encoded values are too large" during encoding.
        estimated_max_log_scale_ = PLAINTEXT_LOG_MAX - 60;
        auto context_data = context->first_context_data();
        for (const auto &prime : context_data->parms().coeff_modulus()) {
            estimated_max_log_scale_ += log2(prime.value());
        }
    }

    ScaleEstimator::ScaleEstimator(int num_slots, int multiplicative_depth, const HomomorphicEval &homom_eval): base_scale_(defaultScaleBits) {
        plaintext_eval = new PlaintextEval(num_slots);
        depth_finder = new DepthFinder();
        depth_finder->top_he_level_ = multiplicative_depth;

        // instead of calling shared_param_init to create a new instance, use the instance provided
        params = homom_eval.params;
        encoder = homom_eval.encoder;
        context = homom_eval.context;
        log_scale_ = homom_eval.log_scale_;

        // if scale is too close to 60, SEAL throws the error "encoded values are too large" during encoding.
        estimated_max_log_scale_ = PLAINTEXT_LOG_MAX - 60;
        auto context_data = context->first_context_data();
        for (const auto &prime : context_data->parms().coeff_modulus()) {
            estimated_max_log_scale_ += log2(prime.value());
        }
    }

    ScaleEstimator::~ScaleEstimator() {
        delete depth_finder;
        delete plaintext_eval;
        delete params;
        delete encoder;
    }

    CKKSCiphertext ScaleEstimator::encrypt(const vector<double> &coeffs, int level) {
        update_plaintext_max_val(coeffs);

        int num_slots_ = encoder->slot_count();
        // in ENC_META, CKKSInstance sets num_slots_ to 4096 and doesn't actually attempt to calcuate the correct value.
        // We have to ignore that case here. Otherwise, input size should exactly equal the number of slots.
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
        double scale = pow(2, base_scale_);
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

    void ScaleEstimator::reset_internal() {
        {
            scoped_lock lock(mutex_);
            estimated_max_log_scale_ = PLAINTEXT_LOG_MAX - 60;
            auto context_data = context->first_context_data();
            for (const auto &prime : context_data->parms().coeff_modulus()) {
                estimated_max_log_scale_ += log2(prime.value());
            }
        }
        plaintext_eval->reset_internal();
        depth_finder->reset_internal();
    }

    // print some debug info
    void ScaleEstimator::print_stats(const CKKSCiphertext &ct) {
        if (!VLOG_IS_ON(LOG_VERBOSE)) {
            return;
        }
        double exact_plaintext_max_val = l_inf_norm(ct.raw_pt.data());
        double log_modulus = 0;
        auto context_data = getContextData(ct);
        for (const auto &prime : context_data->parms().coeff_modulus()) {
            log_modulus += log2(prime.value());
        }
        VLOG(LOG_VERBOSE) << "    + Plaintext logmax: " << log2(exact_plaintext_max_val)
                          << " bits (scaled: " << log2(ct.scale()) + log2(exact_plaintext_max_val) << " bits)";
        VLOG(LOG_VERBOSE) << "    + Total modulus size: " << setprecision(4) << log_modulus << " bits";
        VLOG(LOG_VERBOSE) << "    + Theoretical max log scale: " << get_estimated_max_log_scale() << " bits";
    }

    // At all times, we need ct.scale*l_inf_norm(ct.getPlaintext()) <~ q/4
    // Define ct.scale = i*base_scale_ for i \in {1,2}
    // If(i > ct.he_level): estimated_max_log_scale_ \le
    //      (PLAINTEXT_LOG_MAX-log2(l_inf_norm(ct.getPlaintext()))/(i-ct.he_level))
    // Else if (i == ct.he_level):
    //      log2(l_inf_norm(ct.getPlaintext())) <= 58
    // Else [i < ct.he_level]:
    //      In this case, the constraint becomes estimated_max_log_scale_ > (something less than 0).
    //      this is bogus, so nothing to do.
    void ScaleEstimator::update_max_log_scale(const CKKSCiphertext &ct) {
        // update the estimated_max_log_scale_
        auto scale_exp = static_cast<int>(round(log2(ct.scale()) / log2(base_scale_)));
        if (scale_exp != 1 && scale_exp != 2) {
            stringstream buffer;
            buffer << "INTERNAL ERROR: scale_exp is not 1 or 2: got " << scale_exp << "\t" << log2(ct.scale()) << "\t"
                   << log2(base_scale_);
            throw invalid_argument(buffer.str());
        }
        if (scale_exp > ct.he_level()) {
            auto estimated_scale = (PLAINTEXT_LOG_MAX - log2(l_inf_norm(ct.raw_pt.data()))) / (scale_exp - ct.he_level());
            {
                scoped_lock lock(mutex_);
                estimated_max_log_scale_ = min(estimated_max_log_scale_, estimated_scale);
            }
        } else if (scale_exp == ct.he_level() && log2(l_inf_norm(ct.raw_pt.data())) > PLAINTEXT_LOG_MAX) {
            stringstream buffer;
            buffer << "Plaintext exceeded " << PLAINTEXT_LOG_MAX
                   << " bits, which exceeds SEAL's capacity. Overflow is imminent.";
            throw invalid_argument(buffer.str());
        }
    }

    void ScaleEstimator::rotate_right_inplace_internal(CKKSCiphertext &ct, int steps) {
        depth_finder->rotate_right_inplace_internal(ct, steps);
        plaintext_eval->rotate_right_inplace_internal(ct, steps);
        print_stats(ct);
    }

    void ScaleEstimator::rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) {
        depth_finder->rotate_left_inplace_internal(ct, steps);
        plaintext_eval->rotate_left_inplace_internal(ct, steps);
        print_stats(ct);
    }

    void ScaleEstimator::negate_inplace_internal(CKKSCiphertext &ct) {
        depth_finder->negate_inplace_internal(ct);
        plaintext_eval->negate_inplace_internal(ct);
        print_stats(ct);
    }

    void ScaleEstimator::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        depth_finder->add_inplace_internal(ct1, ct2);
        plaintext_eval->add_inplace_internal(ct1, ct2);

        update_max_log_scale(ct1);
        print_stats(ct1);
    }

    void ScaleEstimator::add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        depth_finder->add_plain_inplace_internal(ct, scalar);
        plaintext_eval->add_plain_inplace_internal(ct, scalar);

        update_max_log_scale(ct);
        print_stats(ct);
    }

    void ScaleEstimator::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        depth_finder->add_plain_inplace_internal(ct, plain);
        plaintext_eval->add_plain_inplace_internal(ct, plain);

        update_max_log_scale(ct);
        print_stats(ct);
    }

    void ScaleEstimator::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        depth_finder->sub_inplace_internal(ct1, ct2);
        plaintext_eval->sub_inplace_internal(ct1, ct2);

        update_max_log_scale(ct1);
        print_stats(ct1);
    }

    void ScaleEstimator::sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        depth_finder->sub_plain_inplace_internal(ct, scalar);
        plaintext_eval->sub_plain_inplace_internal(ct, scalar);

        update_max_log_scale(ct);
        print_stats(ct);
    }

    void ScaleEstimator::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        depth_finder->sub_plain_inplace_internal(ct, plain);
        plaintext_eval->sub_plain_inplace_internal(ct, plain);

        update_max_log_scale(ct);
        print_stats(ct);
    }

    void ScaleEstimator::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        depth_finder->multiply_inplace_internal(ct1, ct2);
        plaintext_eval->multiply_inplace_internal(ct1, ct2);

        ct1.scale_ *= ct2.scale();
        update_max_log_scale(ct1);

        print_stats(ct1);
    }

    void ScaleEstimator::multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        depth_finder->multiply_plain_inplace_internal(ct, scalar);
        plaintext_eval->multiply_plain_inplace_internal(ct, scalar);

        ct.scale_ *= ct.scale();
        update_max_log_scale(ct);
        print_stats(ct);
    }

    void ScaleEstimator::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        depth_finder->multiply_plain_inplace_internal(ct, plain);
        plaintext_eval->multiply_plain_inplace_internal(ct, plain);

        double plain_max = 0;
        for (int i = 0; i < ct.num_slots(); i++) {
            plain_max = max(plain_max, abs(plain[i]));
        }
        ct.scale_ *= ct.scale();
        update_max_log_scale(ct);
        print_stats(ct);
    }

    void ScaleEstimator::square_inplace_internal(CKKSCiphertext &ct) {
        depth_finder->square_inplace_internal(ct);
        plaintext_eval->square_inplace_internal(ct);

        ct.scale_ *= ct.scale();
        update_max_log_scale(ct);
        print_stats(ct);
    }

    void ScaleEstimator::mod_down_to_level_inplace_internal(CKKSCiphertext &ct, int level) {
        int level_diff = ct.he_level() - level;

        if (level < 0) {
            throw invalid_argument("modDownToLevel: level must be >= 0.");
        }

        depth_finder->mod_down_to_level_inplace_internal(ct, level);
        plaintext_eval->mod_down_to_level_inplace_internal(ct, level);

        // reset he_level for dest
        ct.he_level_ += level_diff;
        while (ct.he_level() > level) {
            uint64_t prime = get_last_prime(context, ct.he_level());
            ct.he_level_--;
            ct.scale_ = (ct.scale() * ct.scale()) / prime;
        }
        // ct's level is now reset to level

        // recursive call updated he_level, so we need to update maxLogScale
        update_max_log_scale(ct);
        print_stats(ct);
    }

    void ScaleEstimator::rescale_to_next_inplace_internal(CKKSCiphertext &ct) {
        // get the last prime *before* making any recursive calls.
        // in particular, the DepthFinder call will change the he_level
        // of the ciphertext, causing `getContextData` to get the wrong
        // prime, resulting in mayhem.
        auto context_data = getContextData(ct);
        uint64_t prime = context_data->parms().coeff_modulus().back().value();

        depth_finder->rescale_to_next_inplace_internal(ct);
        plaintext_eval->rescale_to_next_inplace_internal(ct);

        ct.scale_ /= prime;
        update_max_log_scale(ct);
        print_stats(ct);
    }

    void ScaleEstimator::relinearize_inplace_internal(CKKSCiphertext &) {
    }

    void ScaleEstimator::update_plaintext_max_val(const vector<double> &coeffs) {
        double x = l_inf_norm(coeffs);
        // account for a freshly-encrypted ciphertext
        // if this is a depth-0 computation *AND* the parameters are such that it is a no-op,
        // this is the only way we can account for the values in the input. We have to encrypt them,
        // and if the scale is ~2^60, encoding will (rightly) fail
        int top_he_level = context->first_context_data()->chain_index();
        if (top_he_level == 0) {
            {
                scoped_lock lock(mutex_);
                estimated_max_log_scale_ = min(estimated_max_log_scale_, PLAINTEXT_LOG_MAX - log2(x));
            }
        }
    }

    // double ScaleEstimator::get_exact_max_log_plain_val() const {
    //     return plaintext_eval->get_exact_max_log_plain_val();
    // }

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
        int max_mod_bits = poly_degree_to_max_mod_bits(2*encoder->slot_count());
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
