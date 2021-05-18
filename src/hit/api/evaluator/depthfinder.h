// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../ciphertext.h"
#include "../evaluator.h"

namespace hit {

    /* This evaluator's sole purpose is to compute the
     * multiplicative depth of a computation.
     *
     * There is an implicit assumption that the multiplicative depth
     * does not depend on the homomorphic parameters. When using this
     * evaluator, either all calls to encrypt must supply an explicit
     * encryption level, or all calls to encrypt must *not* supply
     * an encryption level. Having some calls which specify a level
     * and some which do not is not permitted.
     */
    class DepthFinder : public CKKSEvaluator {
       public:
        DepthFinder() = default;

        /* For documentation on the API, see ../evaluator.h */
        ~DepthFinder() override = default;

        DepthFinder(const DepthFinder &) = delete;
        DepthFinder &operator=(const DepthFinder &) = delete;
        DepthFinder(DepthFinder &&) = delete;
        DepthFinder &operator=(DepthFinder &&) = delete;

        CKKSCiphertext encrypt(const std::vector<double> &coeffs) override;
        CKKSCiphertext encrypt(const std::vector<double> &coeffs, int level) override;

        /* Return the multiplicative depth of this computation.
         * Must be called after performing the target computation.
         * Not available for all concrete evaluators.
         */
        int get_multiplicative_depth() const;

        int num_slots() const override;

       protected:
        void rescale_to_next_inplace_internal(CKKSCiphertext &ct) override;

       private:
        // encryption_mode_ starts as FIRST_ENCRYPT.
        // The first call to `encrypt` sets the mode for future calls to
        // `encrypt`, which only allows implicit levels or explicit levels.
        enum EncryptionMode { FIRST_ENCRYPT, IMPLICIT_LEVEL, EXPLICIT_LEVEL };
        EncryptionMode encryption_mode_ = FIRST_ENCRYPT;
        const int num_slots_ = 4096;
        int multiplicative_depth_ = 0;
        // We can't make this value `const` even though DepthFinder
        // doesn't update it. The reason is that DepthFinder works when
        // top_he_level_ is 0, but other evaluators which depend on
        // DepthFinder (like ScaleEstimator) have to update this value
        // to work correctly.
        int top_he_level_ = 0;

        void print_stats(const CKKSCiphertext &ct) override;

        friend class ScaleEstimator;
        friend class OpCount;
    };
}  // namespace hit
