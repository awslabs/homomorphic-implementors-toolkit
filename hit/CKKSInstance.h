// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "seal/seal.h"
#include "seal/context.h"
#include "api/encryptor.h"
#include "api/evaluator.h"
#include "api/decryptor.h"
#include "protobuf/ckksparams.pb.h" // NOLINT

/* Wraps SEAL boilerplate into a single object that
 * holds keys, encoders, encryptors, decryptors,
 * and other SEAL objects.
 * The intention is to use this API for encryption
 * and decryption, and to use the CKKSEvaluator
 * for evaluation.
 */

enum Mode {OPCOUNT, DEPTH, PLAINTEXT, SCALE, NORMAL, DEBUG, EVALUATION, NONEVALUATION};

class CKKSInstance {
public:
  // only for finding the depth of a computation
  static CKKSInstance* getNewDepthFinderInstance(bool verbose=false);

  // only for counting the number of operations in the computation
  static CKKSInstance* getNewOpCountInstance(bool verbose=false);

  /* only for doing plaintext computation
   * The number of slots is a proxy for the dimension of the underlying cyclotomic ring.
   * This limits the maximum size of the plaintext vector to `numSlots`, and also limits
   * the maximum size of the modulus. For a fixed multiplicative depth, this imposes a
   * corresponding limit on the scale, and thus the precision, of the computation.
   * There's no good way to know what value to use here without generating some parameters
   * first. Reasonable values include 4096, 8192, or 16384.
   * The `useSEALParams` flag allows you to restrict to SEAL parameters, or to use larger
   * rings. The SEAL paramters are designed to achieve 128-bits of security, while setting
   * `useSEALParams` to false allows you to set parameters which may not achieve 128-bits
   * of security.
   */
  static CKKSInstance* getNewPlaintextInstance(
    int numSlots, bool verbose=false, bool useSEALParams=true);

  /* only for scale estimation
   * See the previous constuctor for an explanation of `numSlots`.
   * `multDepth` should be the output of `getMultiplicativeDepth`
   * using the DepthFinder evaluator.
   * See `getNewPlaintextInstance` for description of `useSEALParams`.
   */
  static CKKSInstance* getNewScaleEstimatorInstance(
    int numSlots, int multDepth, bool verbose=false, bool useSEALParams=true);

  /* Generate a CKKSInstance targeting the desired number of slots, multiplicative
   * depth and log(scale) value.
   * See `getNewPlaintextInstance` for description of `useSEALParams`.
   */
  static CKKSInstance* getNewHomomorphicInstance(
    int numSlots, int multDepth, int logScale, bool verbose=false,
    bool useSEALParams=true, std::vector<int> galois_steps=std::vector<int>());

  static CKKSInstance* loadHomomorphicInstance(
    std::istream &paramsStream, std::istream &galoisKeyStream,
    std::istream &relinKeyStream, std::istream &secretKeyStream,
    bool verbose=false);

  void save(std::ostream *paramsStream, std::ostream *galoisKeyStream,
            std::ostream *relinKeyStream, std::ostream *secretKeyStream);

  /* Same as `getNewHomomorphicInstance`, except with verbose meta-data output and internal
   * tracking of relevant values to the computation
   * See `getNewPlaintextInstance` for description of `useSEALParams`.
   */
  static CKKSInstance* getNewDebugInstance(
    int numSlots, int multDepth, int logScale, bool verbose=false,
    bool useSEALParams=true, std::vector<int> galois_steps=std::vector<int>());

  /* Create a new debug instance from the provided parameters and keys */
  static CKKSInstance* loadDebugInstance(
    std::istream &paramsStream, std::istream &galoisKeyStream,
    std::istream &relinKeyStream, std::istream &secretKeyStream,
    bool verbose=false);

  /* For evaluation only. Decryption is not available. */
  static CKKSInstance* loadEvalInstance(
    std::istream &paramsStream, std::istream &galoisKeyStream,
    std::istream &relinKeyStream, bool verbose=false);

  /* For encryption and decryption only. Evaluation is not available. */
  static CKKSInstance* loadNonEvalInstance(
    std::istream &paramsStream, std::istream &secretKeyStream,
    bool verbose=false);

  ~CKKSInstance();

  void encryptMatrix(const Matrix&, CKKSCiphertext &destination, int level = -1);

  /* Encrypt a C++ vector representing a linear algebra column vector.
   * We first encode the vector as a matrix
   * where each row is `plain`; see pplr.cpp for details.
   * This requires the target matrix height as a parameter.
   */
  void encryptColVec(const std::vector<double> &plain, const int matHeight,
                     CKKSCiphertext &destination, int level = -1);

  /* Encrypt a C++ vector representing a linear algebra row vector.
   * We first encode the vector as a matrix
   * where each column is `plain`; see pplr.cpp for details.
   * This requires the target matrix width as a parameter.
   */
  void encryptRowVec(const std::vector<double> &plain, const int matWidth,
                     CKKSCiphertext &destination, int level = -1);

  // verbose flag enables a warning if you decrypt when the ciphertext is not at level 0
  // Usually, decrypting a ciphertext not at level 0 indicates you are doing something
  // inefficient. However for testing purposes, it may be useful, so you will want to
  // suppress the warning.
  std::vector<double> decrypt(const CKKSCiphertext &encrypted, bool verbose=true);

  int plaintextDim() const;

  CKKSEvaluator *evaluator;
  std::shared_ptr<seal::SEALContext> context;

  double getEstimatedMaxLogScale() const;

  int getMultiplicativeDepth() const;

  double getExactMaxLogPlainVal() const;

  void printOpCount() const;

  // reuse this instance for another computation
  void reset();

  CKKSInstance(const CKKSInstance &) = delete;
  CKKSInstance& operator=(const CKKSInstance&) = delete;
  CKKSInstance(CKKSInstance&&) = delete;
  CKKSInstance& operator=(CKKSInstance&&) = delete;

private:
  // instances without keys
  CKKSInstance(Mode m, int numSlots, int multDepth, int logScale,
               bool verbose, bool useSEALParams);

  // generate all keys
  CKKSInstance(int numSlots, int multDepth, int logScale, bool verbose,
               bool useSEALParams, bool debug, std::vector<int> &galois_steps);

  // loading an instance from streams
  CKKSInstance(std::istream &paramsStream, std::istream *galoisKeyStream,
               std::istream *relinKeyStream, std::istream *secretKeyStream,
               bool verbose, Mode m);

  int genModulusVec(int levels, std::vector<int> &modulusVector);
  void setMaxVal(const std::vector<double> &plain);
  void sharedParamInit(int numSlots, int multDepth, int logScaleIn, bool useSEALParams, bool verbose);
  protobuf::hit::CKKSParams saveCKKSParams();

  seal::Encryptor *sealEncryptor;
  seal::CKKSEncoder *encoder;
  CKKSEncryptor *encryptor;
  CKKSDecryptor *decryptor;
  seal::PublicKey pk;
  seal::SecretKey sk;
  seal::GaloisKeys gk;
  seal::RelinKeys rk;
  seal::EncryptionParameters *params;
  int logScale;
  int encryptionCount = 0;
  bool standardParams;
  Mode mode;
};

uint64_t estimateKeySize(int numGaloisShift, int ptslots, int depth);

// This function tries to load a prevously-generated instance from disk. Instances are parameterized by
// the number of plaintext slots (numSlots), the multiplicative depth (multDepth), and the CKKS scale parameter (logScale).
// `mode` can be `NORMAL`, `DEBUG`, or `NONEVALUATION`. `NORMAL` results in a standard homomorphic evaluator, while `DEBUG` loads a debug evaluator.
// `NONEVALUATION` is useful for cliend-side computation which don't need to perform any evaluation. A `NONEVALUATION` instance can
// *ONLY* be used for encryption and decryption.
CKKSInstance* tryLoadInstance(int numSlots, int multDepth, int logScale, Mode mode, const std::vector<int> &galois_steps=std::vector<int>());
