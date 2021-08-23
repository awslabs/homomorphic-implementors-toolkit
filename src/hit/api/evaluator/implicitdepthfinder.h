// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../../common.h"
#include "../ciphertext.h"
#include "../evaluator.h"

namespace hit {
    /* HE parameters include a chain of moduli, which can be divided into
     * several categories depending on their intended use. At the bottom of
     * the chain are the "evaluation" moduli, which are used to evaluate
     * the target circuit. Above these are moduli dedicated to evaluating
     * the bootstrapping circuit. Fresh ciphertexts can (with care) repurpose
     * these moduli for circuit evaluation prior to bootstrapping the first time,
     * but generally, these moduli are only used for bootstrapping. Finally,
     * additional moduli are used for key switching. Most circuits require at
     * least one key switching modulus, but more may be added for efficiency.
     *
     * This evaluator's purpose is to help determine how many evaluation and
     * bootstrapping moduli are needed to evaluate a circuit *when inputs are
     * encrypted at an implicit (maximum) ciphertext level*. The explicit-level
     * encryption API throws a runtime error.
     *
     * There is an implicit assumption that the multiplicative depth
     * does not depend on the homomorphic parameters. When using this
     * evaluator, either all calls to encrypt must supply an explicit
     * encryption level, or all calls to encrypt must *not* supply
     * an encryption level. Having some calls which specify a level
     * and some which do not is not permitted.
     */
    class ImplicitDepthFinder : public CKKSEvaluator {
       public:
        ImplicitDepthFinder() = default;

        /* For documentation on the API, see ../evaluator.h */
        ~ImplicitDepthFinder() override = default;

        ImplicitDepthFinder(const ImplicitDepthFinder &) = delete;
        ImplicitDepthFinder &operator=(const ImplicitDepthFinder &) = delete;
        ImplicitDepthFinder(ImplicitDepthFinder &&) = delete;
        ImplicitDepthFinder &operator=(ImplicitDepthFinder &&) = delete;

        CKKSCiphertext encrypt(const std::vector<double> &coeffs) override;
        CKKSCiphertext encrypt(const std::vector<double> &coeffs, int level) override;  // throws an error

        /* Return the the minimum number of parameter levels which should
         * be dedicated to bootstrapping. This is based on how many levels
         * are consumed in the deepest part of the computation versus how
         * many levels are consumed *after* a ciphertext has been bootstrapped.
         * Must be called after performing the target computation. Returns 0
         * if bootstrapping is not used.
         */
        int get_param_bootstrap_depth() const;

        /* Return the the "evaluation depth" of the circuit. For circuits which do not
         * use bootstrapping, this corresponds to the depth of the circuit. For circuits
         * which do use bootstrapping, this is the maximum circuit depth evaluated
         * after a ciphertext has been bootstrapped.
         * Must be called after performing the target computation.
         */
        int get_param_eval_depth() const;

        int num_slots() const override;

       protected:
        void add_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) override;

        void sub_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) override;

        void multiply_inplace_internal(CKKSCiphertext &ct1, const CKKSCiphertext &ct2) override;

        void rescale_to_next_inplace_internal(CKKSCiphertext &ct) override;

        void bootstrap_inplace_internal(CKKSCiphertext &ct, bool rescale_for_bootstrapping) override;

       private:
        const int num_slots_ = 4096;
        int bootstrap_depth_ = -1;
        int post_bootstrap_depth_ = 0;
        int max_contiguous_depth = 0;
        bool uses_bootstrapping = false;

        void print_stats(const CKKSCiphertext &ct) override;
        void set_bootstrap_depth(CKKSCiphertext &ct1, const CKKSCiphertext &ct2);

        friend class ScaleEstimator;
        friend class OpCount;
    };
}  // namespace hit
