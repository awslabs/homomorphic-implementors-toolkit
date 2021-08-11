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
     * the target circuit. Above these, additional moduli are used for key
     * switching. Most circuits require at least one key switching modulus,
     * and SEAL supports at most one.
     *
     * This evaluator's purpose is to help determine how many evaluation
     * moduli are needed to evaluate a circuit *when inputs are
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

        /* Return the the "evaluation depth" of the circuit.
         * Must be called after performing the target computation.
         */
        int get_multiplicative_depth() const;

        int num_slots() const override;

       protected:
        void rescale_to_next_inplace_internal(CKKSCiphertext &ct) override;

       private:
        const int num_slots_ = 4096;
        int max_contiguous_depth = 0;

        void print_stats(const CKKSCiphertext &ct) override;

        friend class ScaleEstimator;
        friend class OpCount;
    };
}  // namespace hit
