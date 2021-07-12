// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <iostream>
#include <optional>
#include <variant>
#include <vector>

#include "../common.h"
#include "latticpp/latticpp.h"

/* There are many ways to "bootstrap" a CKKS ciphertext because there are many ways to approximate
 * the necessary function. A key step in all bootstrapping approximations to date is to approximate
 * (1/2pi)*sin(2pi*x). There are at least three ways to do this:
 *  1) BootstrappingApprox.Sin: directly, by using a Chebyshev interpolant over the range [-K, K]
 *  2) BootstrappingApprox.Cos1: Use a shifted cosine over the range [-K/2^r, K/2^r], followed by r
 *     iterations of the double angle formula with a special-purpose Chebyshev interpolant
 *  3) BootstrappingApprox.Cos2: A slightly different cosine approximation over the range [-K/2^r, K/2^r],
 *     followed by r iterations of the double angle formula with a standard Chebyshev interpolant
 *
 * The direct sine approximation is inferior to the cosine + double-angle approaches because the reduced
 * approximation range of the cosine approaches permits a lower-degree approximation. The tradeoff is that
 * each double-angle application consumes one level.
 *
 * ************************************ Bootstrapping Parameters ************************************
 *
 * - Key density (H): We will only support non-sparse keys. It seems like this isn't *completely*
 *   well-defined, but, e.g., it excludes choosing a ternary key with Hamming weight 64 in a ring of
 *   dimension 2^16, but Lattigo chose keys with ternary Hamming weight H=32768=2^15 in a ring of
 *   dimension 2^16, which is also not fully dense. We will adopt Lattigo's choice.
 *
 * - Approximation range (K): The Hamming weight of the key determines the maximum input to the
 *   approximation the moduluar reduction/sin function. Lattigo authors determined that setting K=257
 *   with H=32768 gives a (correctness) failure probability of ~2^-40.
 *
 * - Double-angle iterations (r): Larger values of `r` reduce the approximation degree required for
 *   accuracy, but increase the number of levels consumed. For H=32768, the Lattigo authors chose r=3.
 *   It's possible we could change this to explore some tradeoffs, but it would also affect the
 *   approximation degree below.
 *
 * - Approximation degree (d): The degree of the polynomial for the sin/cos approximation. The Lattigo
 *   authors set to 250 for K=257. This value was empirically determined to provide adequate precision
 *   over the entire approximation range.
 *
 * - Cosine approximation: As discussed above, there are three main ways to compute the sine approximation,
 *   with the cosine approaches being preferable to the direct approach. The Lattigo authors show that when
 *   d<2K-1, Cos2 is best, and Cos1 is best otherwise. For the non-sparse-key parameters discussed so far,
 *   d=250 < 2K-1 = 513, so we will use the Cos2 approximation.
 *
 *  - CoeffsToSlots Factorization: The first step in CKKS bootstrapping is to map the coefficients of the
 *
 * ************************************ Bootstrapping Process ************************************
 * Recall that a ciphertext ct = (c0, c1) mod Q encrypts a _ring element_ m(X) under a secret key s
 * such that [c0 + c1 * s]_Q (where the [*]_Q means coefficient-wise modular reduction by Q). It
 * turns out that (c0 + c1 * s) (no reduction by Q) is t(X) = m(X) + I(X)*Q for some polynomial I where
 * the coefficients of I are bounded w.h.p. by O(\sqrt(H)) (where H is the trinary Hamming weight
 * of the secret key s). The first step of bootstrapping is to view ct as an encryption of t(X)
 * (rather than [t(X)]_Q) *under a larger modulus* Q'. That is, rather than
 *     [c0 + c1 * s]_Q = m(X)
 * we have
 *     [c0 + c1 * s]_Q' = t(X) = m(X) + I(X)*Q
 * So by raising the modulus of the ciphertext from Q to Q', we change the encrypted plaintext from
 * m(X) to t(X). This is the first step of bootstrapping.
 *
 * The rest of the bootstrapping process is dedicated to homomorphically reducing each plaintext coeffient
 * of t(x) by Q, thereby removing the I(X)*Q term and producing an encryption of m(X) with a modulus Q''
 * where Q < Q'' < Q'. In CKKS, we typically encode the elements of pt \in \C^n as the slots of a ring
 * element, which enables efficient component-wise operations. In short, decode(m(X)) = pt. At this point
 * in bootstrapping, however, we want to perform component-wise operations on the 2n coefficients of t(X).
 * Thus, the first step is to move the 2n *coefficients* of the plaintext t(X) into the slots of *two*
 * ciphertexts (each of which has n slots). This is accomplished by homomorphically evaluating the encoding
 * algorithm on each half of the plaintext coeffients.
 *
 * Having converted the coefficients of t(X) into slots, we can now homomorphically round each coefficient
 * mod Q. This is accomplished via a scaled sin() function. See above for various approaches to evaluating
 * and approximating the scaled sine.
 *
 * Now that each of the coefficients are reduced mod Q, we need to map them from slots back into a
 * single plaintext polynomial. This is accomplished by homomorphically evaluating the decoding algorithm.
 *
 * ************************************ CoeffsToSlots and SlotsToCoeffs ************************************
 * The encoding and decoding algorithms are achieved by (homomorphically) multiplying the plaintext vector
 * by the DFT matrix (or its inverse). The DFT has a well-known decomposition into sparse matrices (e.g.,
 * the Cooley-Tukey decomposition), and the best bootstrapping procedures take advantage of this decomposition.
 * The Cooley-Tukey decomposition splits the DFT matrix into log(n) pieces. The more components the DFT is
 * decomposed into, the fewer expensive rotations are needed. However, each DFT component costs one level,
 * so there is a tradeoff.
 *
 * TODO: Finish.
 */

namespace hit {
    enum BootstrappingApprox {
        Sin,   // Standard Chebyshev approximation of (1/2pi) * sin(2pix)
        Cos1,  // Special approximation (Han and Ki) of pow((1/2pi), 1/2^r) * cos(2pi(x-0.25)/2^r)
        Cos2   // Standard Chebyshev approximation   of pow((1/2pi), 1/2^r) * cos(2pi(x-0.25)/2^r)
    };

    class BootstrappingParams {
       public:
        // BootstrappingParams(uint64_t secret_hamming_weight, uint64_t approx_range, uint64_t approx_degree,
        //                     uint64_t double_angle_applications, std::vector<uint8_t> CtSLevels,
        //                     std::vector<uint8_t> StCLevels, double maxN1N2Ratio = 16.0);

        explicit BootstrappingParams(latticpp::BootstrappingParameters btp_params);

        int bootstrapping_depth() const;

        // BootstrappingApprox trig_approx;
        // uint64_t secret_hamming_weight;
        // uint64_t approx_range;
        // uint64_t approx_degree;
        // uint64_t double_angle_applications;
        // std::vector<uint8_t> CtSLevels;
        // std::vector<uint8_t> StCLevels;
        // double maxN1N2Ratio;

        latticpp::BootstrappingParameters lattigo_btp_params;
    };

    class CKKSParams {
       public:
        explicit CKKSParams(latticpp::Parameters params);

        CKKSParams(int num_slots, int log_scale, int max_ct_level, int num_ks_primes = 1,
                   std::optional<BootstrappingParams> btp_params = std::optional<BootstrappingParams>());

        int num_slots() const;
        int log_scale() const;
        int max_ct_level() const;

        latticpp::Parameters lattigo_params;
        std::optional<BootstrappingParams> btp_params;
    };
}  // namespace hit
