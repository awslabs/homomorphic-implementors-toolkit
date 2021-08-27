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
     * the bootstrapping circuit. Finally, additional moduli are used for
     * key switching. Most circuits require at least one key switching
     * modulus, but more may be added for efficiency.
     *
     * This evaluator's purpose is to determine the total circuit depth,
     * not counting the depth required for bootstrapping.
     *
     * There is an implicit assumption that the multiplicative depth
     * does not depend on the homomorphic parameters.
     */
    class DepthFinder : public CKKSEvaluator {
       public:
        explicit DepthFinder(int post_btp_lvl = -1);

        /* For documentation on the API, see ../evaluator.h */
        ~DepthFinder() override = default;

        DepthFinder(const DepthFinder &) = delete;
        DepthFinder &operator=(const DepthFinder &) = delete;
        DepthFinder(DepthFinder &&) = delete;
        DepthFinder &operator=(DepthFinder &&) = delete;

        CKKSCiphertext encrypt(const std::vector<double> &coeffs) override;
        CKKSCiphertext encrypt(const std::vector<double> &coeffs, int level) override;

        /* Return the the "evaluation depth" of the circuit, which is the number of levels
         * consumed (excluding levels used for bootstrapping, since this depends on the parameters).
         * Must be called after performing the target computation.
         */
        int get_multiplicative_depth() const;

        int num_slots() const override;

       protected:
        void rescale_to_next_inplace_internal(CKKSCiphertext &ct) override;

        void bootstrap_inplace_internal(CKKSCiphertext &ct, bool rescale_for_bootstrapping) override;

       private:
        const int num_slots_ = 4096;
        int circuit_depth = 0;

        void print_stats(const CKKSCiphertext &ct) override;
    };
}  // namespace hit
