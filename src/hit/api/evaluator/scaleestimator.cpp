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

    ScaleEstimator::ScaleEstimator(const shared_ptr<SEALContext> &context, int poly_deg, double baseScale)
        : CKKSEvaluator(context), baseScale(baseScale), poly_deg(poly_deg) {
        ptEval = new PlaintextEval(context);
        dfEval = new DepthFinder(context);

        // if scale is too close to 60, SEAL throws the error "encoded values are too large" during encoding.
        estimatedMaxLogScale = PLAINTEXT_LOG_MAX - 60;
        auto context_data = context->first_context_data();
        for (const auto &prime : context_data->parms().coeff_modulus()) {
            estimatedMaxLogScale += log2(prime.value());
        }
    }

    ScaleEstimator::~ScaleEstimator() {
        delete dfEval;
        delete ptEval;
    }

    void ScaleEstimator::reset_internal() {
        estimatedMaxLogScale = PLAINTEXT_LOG_MAX - 60;
        auto context_data = context->first_context_data();
        for (const auto &prime : context_data->parms().coeff_modulus()) {
            estimatedMaxLogScale += log2(prime.value());
        }
        ptEval->reset_internal();
        dfEval->reset_internal();
    }

    // print some debug info
    void ScaleEstimator::print_stats(const CKKSCiphertext &ct) {
        if (!VLOG_IS_ON(LOG_VERBOSE)) {
            return;
        }
        double exactPlaintextMaxVal = lInfNorm(ct.raw_pt.data());
        double logModulus = 0;
        auto context_data = getContextData(ct);
        for (const auto &prime : context_data->parms().coeff_modulus()) {
            logModulus += log2(prime.value());
        }
        VLOG(LOG_VERBOSE) << "    + Plaintext logmax: " << log2(exactPlaintextMaxVal)
                          << " bits (scaled: " << log2(ct.scale()) + log2(exactPlaintextMaxVal) << " bits)";
        VLOG(LOG_VERBOSE) << "    + Total modulus size: " << setprecision(4) << logModulus << " bits";
        VLOG(LOG_VERBOSE) << "    + Theoretical max log scale: " << get_estimated_max_log_scale() << " bits";
    }

    // At all times, we need ct.scale*lInfNorm(ct.getPlaintext()) <~ q/4
    // Define ct.scale = i*baseScale for i \in {1,2}
    // If(i > ct.he_level): estimatedMaxLogScale \le
    //      (PLAINTEXT_LOG_MAX-log2(lInfNorm(ct.getPlaintext()))/(i-ct.he_level))
    // Else if (i == ct.he_level):
    //      log2(lInfNorm(ct.getPlaintext())) <= 58
    // Else [i < ct.he_level]:
    //      In this case, the constraint becomes estimatedMaxLogScale > (something less than 0).
    //      this is bogus, so nothing to do.

    void ScaleEstimator::update_max_log_scale(const CKKSCiphertext &ct) {
        // update the estimatedMaxLogScale
        auto scaleExp = static_cast<int>(round(log2(ct.scale()) / log2(baseScale)));
        if (scaleExp != 1 && scaleExp != 2) {
            stringstream buffer;
            buffer << "INTERNAL ERROR: scaleExp is not 1 or 2: got " << scaleExp << "\t" << log2(ct.scale()) << "\t"
                   << log2(baseScale);
            throw invalid_argument(buffer.str());
        }
        if (scaleExp > ct.he_level()) {
            auto estimated_scale = (PLAINTEXT_LOG_MAX - log2(lInfNorm(ct.raw_pt.data()))) / (scaleExp - ct.he_level());
            estimatedMaxLogScale = min(estimatedMaxLogScale, estimated_scale);
        } else if (scaleExp == ct.he_level() && log2(lInfNorm(ct.raw_pt.data())) > PLAINTEXT_LOG_MAX) {
            stringstream buffer;
            buffer << "Plaintext exceeded " << PLAINTEXT_LOG_MAX
                   << " bits, which exceeds SEAL's capacity. Overflow is imminent.";
            throw invalid_argument(buffer.str());
        }
    }

    void ScaleEstimator::rotate_right_inplace_internal(CKKSCiphertext &ct, int steps) {
        dfEval->rotate_right_inplace_internal(ct, steps);
        ptEval->rotate_right_inplace_internal(ct, steps);
        print_stats(ct);
    }

    void ScaleEstimator::rotate_left_inplace_internal(CKKSCiphertext &ct, int steps) {
        dfEval->rotate_left_inplace_internal(ct, steps);
        ptEval->rotate_left_inplace_internal(ct, steps);
        print_stats(ct);
    }

    void ScaleEstimator::negate_inplace_internal(CKKSCiphertext &ct) {
        dfEval->negate_inplace_internal(ct);
        ptEval->negate_inplace_internal(ct);
        print_stats(ct);
    }

    void ScaleEstimator::add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        dfEval->add_inplace_internal(ct1, ct2);
        ptEval->add_inplace_internal(ct1, ct2);

        update_max_log_scale(ct1);
        print_stats(ct1);
    }

    void ScaleEstimator::add_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        dfEval->add_plain_inplace_internal(ct, scalar);
        ptEval->add_plain_inplace_internal(ct, scalar);

        update_max_log_scale(ct);
        print_stats(ct);
    }

    void ScaleEstimator::add_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        dfEval->add_plain_inplace_internal(ct, plain);
        ptEval->add_plain_inplace_internal(ct, plain);

        update_max_log_scale(ct);
        print_stats(ct);
    }

    void ScaleEstimator::sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        dfEval->sub_inplace_internal(ct1, ct2);
        ptEval->sub_inplace_internal(ct1, ct2);

        update_max_log_scale(ct1);
        print_stats(ct1);
    }

    void ScaleEstimator::sub_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        dfEval->sub_plain_inplace_internal(ct, scalar);
        ptEval->sub_plain_inplace_internal(ct, scalar);

        update_max_log_scale(ct);
        print_stats(ct);
    }

    void ScaleEstimator::sub_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        dfEval->sub_plain_inplace_internal(ct, plain);
        ptEval->sub_plain_inplace_internal(ct, plain);

        update_max_log_scale(ct);
        print_stats(ct);
    }

    void ScaleEstimator::multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) {
        dfEval->multiply_inplace_internal(ct1, ct2);
        ptEval->multiply_inplace_internal(ct1, ct2);

        ct1.scale_ *= ct2.scale();
        update_max_log_scale(ct1);

        print_stats(ct1);
    }

    void ScaleEstimator::multiply_plain_inplace_internal(CKKSCiphertext &ct, double scalar) {
        dfEval->multiply_plain_inplace_internal(ct, scalar);
        ptEval->multiply_plain_inplace_internal(ct, scalar);

        ct.scale_ *= ct.scale();
        update_max_log_scale(ct);
        print_stats(ct);
    }

    void ScaleEstimator::multiply_plain_inplace_internal(CKKSCiphertext &ct, const vector<double> &plain) {
        dfEval->multiply_plain_inplace_internal(ct, plain);
        ptEval->multiply_plain_inplace_internal(ct, plain);

        double plain_max = 0;
        for (int i = 0; i < ct.num_slots(); i++) {
            plain_max = max(plain_max, abs(plain[i]));
        }
        ct.scale_ *= ct.scale();
        update_max_log_scale(ct);
        print_stats(ct);
    }

    void ScaleEstimator::square_inplace_internal(CKKSCiphertext &ct) {
        dfEval->square_inplace_internal(ct);
        ptEval->square_inplace_internal(ct);

        ct.scale_ *= ct.scale();
        update_max_log_scale(ct);
        print_stats(ct);
    }

    void ScaleEstimator::mod_down_to_inplace_internal(CKKSCiphertext &ct, const CKKSCiphertext &target) {
        if (ct.he_level() == target.he_level() && ct.scale() != target.scale()) {
            throw invalid_argument("modDownTo: levels match, but scales do not.");
        }

        dfEval->mod_down_to_inplace_internal(ct, target);
        ptEval->mod_down_to_inplace_internal(ct, target);

        ct.scale_ = target.scale();

        // recursive call updated he_level, so we need to update maxLogScale
        update_max_log_scale(ct);
        print_stats(ct);
    }

    void ScaleEstimator::mod_down_to_min_inplace_internal(CKKSCiphertext &ct1, CKKSCiphertext &ct2) {
        if (ct1.he_level() == ct2.he_level() && ct1.scale() != ct2.scale()) {
            throw invalid_argument("modDownToMin: levels match, but scales do not.");
        }

        if (ct1.he_level() > ct2.he_level()) {
            ct1.scale_ = ct2.scale();
        } else {
            ct2.scale_ = ct1.scale();
        }

        dfEval->mod_down_to_min_inplace_internal(ct1, ct2);
        ptEval->mod_down_to_min_inplace_internal(ct1, ct2);

        // recursive call updated he_level, so we need to update maxLogScale
        update_max_log_scale(ct1);
        update_max_log_scale(ct2);
        print_stats(ct1);
        print_stats(ct2);
    }

    void ScaleEstimator::mod_down_to_level_inplace_internal(CKKSCiphertext &ct, int level) {
        int lvlDiff = ct.he_level() - level;

        if (level < 0) {
            throw invalid_argument("modDownToLevel: level must be >= 0.");
        }

        dfEval->mod_down_to_level_inplace_internal(ct, level);
        ptEval->mod_down_to_level_inplace_internal(ct, level);

        // reset he_level for dest
        ct.he_level_ += lvlDiff;
        while (ct.he_level() > level) {
            uint64_t p = getLastPrime(context, ct.he_level());
            ct.he_level_--;
            ct.scale_ = (ct.scale() * ct.scale()) / p;
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

        dfEval->rescale_to_next_inplace_internal(ct);
        ptEval->rescale_to_next_inplace_internal(ct);

        ct.scale_ /= prime;
        update_max_log_scale(ct);
        print_stats(ct);
    }

    void ScaleEstimator::relinearize_inplace_internal(CKKSCiphertext &) {
    }

    void ScaleEstimator::update_plaintext_max_val(double x) {
        // account for a freshly-ct ciphertext
        // if this is a depth-0 computation *AND* the parameters are such that it is a no-op,
        // this is the only way we can account for the values in the input. We have to encrypt them,
        // and if the scale is ~2^60, encoding will (rightly) fail
        int topHELevel = context->first_context_data()->chain_index();
        if (topHELevel == 0) {
            estimatedMaxLogScale = min(estimatedMaxLogScale, PLAINTEXT_LOG_MAX - log2(x));
        }
    }

    double ScaleEstimator::get_exact_max_log_plain_val() const {
        return ptEval->get_exact_max_log_plain_val();
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
        int maxModBits = polyDegreeToMaxModBits(poly_deg);
        int topHELevel = context->first_context_data()->chain_index();

        double estimated_log_scale = min(static_cast<double>(PLAINTEXT_LOG_MAX), estimatedMaxLogScale);
        if (topHELevel > 0) {
            return min(estimated_log_scale, (maxModBits - 120) / static_cast<double>(topHELevel));
        }
        return estimated_log_scale;
    }
}  // namespace hit
