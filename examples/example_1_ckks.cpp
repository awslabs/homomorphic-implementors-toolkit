// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* This example explains the basics of CKKS homomorphic encryption,
 * as implemented in the Microsoft SEAL homomorphic encryption library
 * on which HIT is based.
 *
 *
 * ******** About CKKS Homomorphic Encryption ********
 * CKKS is based on the "ring learning with errors" (RLWE) problem, a well-studied
 * problem on which many cryptosystems are based. This problem is believed
 * to be hard even using a quantum computer, so CKKS homomorphic encryption
 * is believed to be quantum-secure. By default, HIT ensures that cryptosystem
 * parameters achieve 128-bit security as standardized in
 * http://homomorphicencryption.org/white_papers/security_homomorphic_encryption_white_paper.pdf
 * CKKS comes in symmetric and asymmetric variants; HIT currently only supports
 * the asymmetric version.
 *
 *
 * ******** Circuit Depth ********
 * Homomorphic functions are implemented as circuits using "gates" provided by
 * the homomorphic encryption (HE) API such as `add` and `multiply`. These gates
 * are chained together to form a circuit which can be evaluated by a homomorphic
 * encryption scheme. An important property of the circuit is it's
 * *multiplicative depth*, which is the number of multiplications along the path
 * through the circuit with the _most_ multiplications.
 * As an example, consider the following two
 * circuits consisting of only addition (+) and multiplication (*) gates and the
 * inputs x, y, and z:
 *
 *        Circuit 1                      Circuit 2
 *
 *      x     x                        x     x
 *       \   /                          \   /
 *        (*)    y                       (+)    y
 *         |    /                         |    /
 *         \   /                          \   /
 *          (+)     y                      (+)     z
 *           |     /                        |     /
 *            \   /                          \   /
 *             (*)                            (+)
 *              |                              |
 *           y(x^2+y)                       2x+y+z
 *
 * Circuit 1 has multiplicative depth 2 (even though the multiplications are not adjacent)
 * and Circuit 2 has multiplicative depth 0, since there are no multiplications. HIT helps
 * developers compute their circuit's depth; future examples explore this functionality.
 *
 *
 * ******** Leveled HE ********
 * Most homomorphic encrpytion schemes are "leveled" HE schemes, which means that
 * the user selects cryptosystem parameters corresponding to the maximum circuit depth
 * they wish to evaluate. To evaluate circuits of depth <= d, the user selects parameters
 * such that the maximum ciphertext modulus is a product of d+1 (small) primes. [NOTE: The
 * SEAL examples also refer to an additional "special" prime, making d+2 primes. HIT users
 * need not worry about this prime, so we ignore it here.] The "level" of a ciphertext
 * is one less than the number of primes in the ciphertext modulus, so a ciphertext with
 * two primes is at level one, etc.
 * Fully homomorphic encryption allows a user to evaluate circuits of arbitrary depth,
 * even when that depth is not known when the cryptosystem parameters were chosen. This
 * functionality requires a process called bootstrapping, but neither HIT nor SEAL support
 * bootstrapping for CKKS.
 *
 *
 * ******** CKKS Plaintext Space ********
 * The plaintext space for the CKKS HE scheme is a list of real numbers. The length of
 * this list is determined by the main cryptosystem parameters, the number of plaintext
 * "slots". SEAL (and therefore HIT) only supports a number of slots which is a power of two.
 * Although not needed to use HIT, readers familiar with lattice cryptography may note that
 * the number of plaintext slots (#slots) is directly related to the polynomial ring used in the
 * underlying RLWE instance: the polynomial modulus has degree 2*(#slots), and this polynomial
 * is the 4*(#slots)^th cylcotomic polynomial.
 *
 *
 * ******** CKKS Scale Parameter ********
 * CKKS is an approximate homomorphic encryption scheme because all operations incur a small
 * amount of noise which cannot be removed from the result. This is true even of encryption:
 * decrypt(encrypt(x)) is close to, but not identically, x. The precision of the result is
 * controlled by a "scale parameter". In short, we scale the plaintext so that the noise
 * incurred while performing operations only affects the least-significant bits of the
 * computation, which can mostly be removed by scaling down upon decryption.
 *
 *
 * ******** CKKS Parameter Relationships ********
 * The main cryptosystem parameters are:
 * - the number of plaintext slots
 * - the CKKS scale parameter
 * - the maximum circuit depth able to be evaluated by the scheme
 * These parameters are not independent, however. SEAL recommends choosing a ciphertext
 * modulus where the first prime (level 0) has 60 bits,
 * and the remaining d primes are log_2(scale parameter) bits. This means that for
 * parameters corresponding to depth d, the full modulus will have 60+d*log_2(scale)
 * bits. In order to achieve a target security level, the size of the ciphertext
 * modulus is bounded above by a function of the number of plaintext slots. For 128-bit
 * security, this corresponds to:
 *
 *           num_slots      max modulus bits
 *             4096              158
 *             8192              378
 *            16384              821
 *
 * Thus the number of slots bounds the size of the ciphertext modulus, which in turn
 * bounds d*log_2(scale).
 *
 *
 * ******** CKKS Ciphertexts ********
 * A ciphertext is a list of cyclotomic ring elements corresponding to the coefficients
 * of a polynomial in the secret key. A freshly encrypted ciphertext always has two ring elements,
 * corresponding to a linear polynomial encrypt_pk(x) = [ct_0, ct_1], and x ~ ct_1*sk + ct_0.
 * Multiplying two linear ciphertexts multiplies their linear polynomials to create a quadratic polynomial.
 * Many homomorphic operations only work on linear ciphertexts, however, so we need a special "maintenance"
 * operation called relinearization to convert a quadratic ciphertext encrypting a plaintext x into a linear
 * ciphertext encrypting the same value.
 *
 * Multiplying two ciphertexts also multiplies their scale parameters. Usually, both arguments have
 * the same scale parameter, so the output has a scale which is the square of the input scales. If the
 * ciphertext scale parameter becomes too large, the plaintext will wrap around the modulus, and the
 * plaintext inside will become random noise. To avoid this problem, we use a second maintenance operation
 * called `rescale`. This operation reduces the level of the ciphertext by one (by dropping the last prime
 * in the modulus) and simultaneously dividing the ciphertext scale by this this prime. Since all but the
 * first prime is chosen to be the same number of bits as the scale, this has the effect of restoring
 * the ciphertext scale to apprximately the same as the input scale. More concretely, consider two
 * ciphertexts ct1 and ct2, both with scale `s` and ciphertext modulus p_1*p_2*p_3. The product
 * ct1*ct2 is a quadratic ciphertext with scale s^2 and modulus p_1*p_2*p_3. First we relinearize
 * to get a linear ciphertext with scale s^2 and modulus p_1*p_2*p_3, then we can rescale to get
 * a linear ciphertext with scale s^2/p_3 ~ s and modulus p_1*p_2. These maintenance operations
 * are not shown in Circuit 1 and Circuit 2 above, but they would go after each multiplication.
 *
 *
 * ******** CKKS Basic with HIT  ********
 * The following code demonstrates how to use HIT to create a CKKS instance, and to
 * use it for encryption and decryption.
 */
#include "hit/hit.h"
#include <glog/logging.h>

using namespace std;
using namespace hit;

// generate a random vector of the given dimension, where each value is in the range [-maxNorm, maxNorm].
vector<double> random_vector(int dim, double maxNorm) {
    vector<double> x;
    x.reserve(dim);

    srand(time(nullptr));
    for (int i = 0; i < dim; i++) {
        // generate a random double between -maxNorm and maxNorm
        double a = -maxNorm + ((static_cast<double>(random())) / (static_cast<double>(RAND_MAX))) * (2 * maxNorm);
        x.push_back(a);
    }
    return x;
}

void example_1_driver() {
	// Select CKKS parameters
	// Other examples will explore parameter selection futher
	int num_slots = 4096;
	int max_depth = 1;
	int log_scale = 40;

	// Create a CKKS instance corresponding to the parameters chosen above.
	// Set up the cryptosystem and generate keys.
	HomomorphicEval inst(num_slots, max_depth, log_scale);

	// Generate a plaintext with `num_slots` random coefficients, each with absolute value < `plaintext_inf_norm`
	int plaintext_inf_norm = 10;
	vector<double> plaintext = random_vector(num_slots, plaintext_inf_norm);

	// Encrypt the plaintext. By default, the ciphertext is created at the maximum
	// level allowed by the parameters, which is `max_depth`.
	CKKSCiphertext ciphertext1 = inst.encrypt(plaintext);

	// We can verify the number of plaintext coefficients in the ciphertext
	LOG(INFO) << "Ciphertext1 encrypts " << ciphertext1.num_slots() << " coefficients; expected " << num_slots;

	// At any point, we can check the level of a ciphertext
	LOG(INFO) << "Ciphertext1 is at level " << ciphertext1.he_level() << "; expected " << max_depth;

	// We can also check the scale of the ciphertext
	LOG(INFO) << "Ciphertext1 has a scale of " << log2(ciphertext1.scale()) << " bits; expected " << log_scale;

	// Finally, we can decrypt a ciphertext to recover a plaintext which is close to the input
	vector<double> recovered_pt1 = inst.decrypt(ciphertext1);

	// Compute the |expected-actual|/|expected|, where |*| denotes the 2-norm.
	// If the decrypted value was identical to the input plaintext, this would be exactly;
	// instead we see that the 2-norm of the difference is small but non-zero.
	LOG(INFO) << "Relative difference between input and decrypted output: " << relative_error(plaintext, recovered_pt1);

	// Decryption issues a log message because `ciphertext1` is not at level 0, which is where
	// we expect most decryption to happen since we usually decrypt only at the end of a computation.
	// If a ciphertext is not at level 0 at that point, then we could have started the entire computation
	// one level lower, which would have resulted in better performance.
	// This brings up an optimization: sometimes it is beneficial to encrypt a ciphertext at a level
	// other than the highest possible level (which is the default). Instead, we can specifiy the desired
	// level at encryption:
	CKKSCiphertext ciphertext2 = inst.encrypt(plaintext, 0);

	// Instead of being encrypted at level 1, which is the highest possible level for these parameters,
	// ciphertext2 is encrypted at level 0.
	LOG(INFO) << "Ciphertext2 is at level " << ciphertext2.he_level() << " rather than the default, level " << max_depth;

	// No log message is generated here since the input is at level 0.
	vector<double> recovered_pt2 = inst.decrypt(ciphertext2);

	LOG(INFO) << "Decryption level doesn't affect noise, the relative difference is similar: " << relative_error(plaintext, recovered_pt2);
}
