// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "CKKSInstance.h"
#include "SEAL/native/examples/examples.h"
#include "api/evaluator/homomorphic.h"
#include "api/evaluator/depthfinder.h"
#include "api/evaluator/plaintext.h"
#include "api/evaluator/scaleestimator.h"
#include "api/evaluator/debug.h"
#include "api/evaluator/opcount.h"
#include "common.h"
#include <experimental/filesystem>

using namespace std;
using namespace seal;
namespace fs = experimental::filesystem;

// SEAL throws an error for 21, but allows 22
#define MIN_LOG_SCALE 22

// it turns out that the lossiness of encoding/decoding strongly depends on
// this value. For evaluators that don't really use SEAL, but do use CKKS
// encoding/decoding, this should be set to as high as possible.
int defaultScaleBits = 30;

CKKSInstance* CKKSInstance::getNewDepthFinderInstance(bool verbose) {
  return new CKKSInstance(DEPTH, 4096, 0, defaultScaleBits, verbose, true);
}
CKKSInstance* CKKSInstance::getNewOpCountInstance(bool verbose) {
  return new CKKSInstance(OPCOUNT, 4096, 0, defaultScaleBits, verbose, true);
}
CKKSInstance* CKKSInstance::getNewPlaintextInstance(int numSlots, bool verbose, bool useSEALParams) {
  return new CKKSInstance(PLAINTEXT, numSlots, 0, defaultScaleBits, verbose, useSEALParams);
}
CKKSInstance* CKKSInstance::getNewScaleEstimatorInstance(int numSlots, int multDepth, bool verbose, bool useSEALParams) {
  return new CKKSInstance(SCALE, numSlots, multDepth, defaultScaleBits, verbose, useSEALParams);
}
CKKSInstance* CKKSInstance::getNewHomomorphicInstance(int numSlots, int multDepth, int logScale, bool verbose, bool useSEALParams, vector<int> galois_steps) {
  return new CKKSInstance(numSlots, multDepth, logScale, verbose,
                          useSEALParams, false, galois_steps);
}
CKKSInstance* CKKSInstance::loadHomomorphicInstance(
    istream &paramsStream, istream &galoisKeyStream,
    istream &relinKeyStream, istream &secretKeyStream,
    bool verbose) {
  return new CKKSInstance(paramsStream, &galoisKeyStream, &relinKeyStream, &secretKeyStream, verbose, NORMAL);
}
CKKSInstance* CKKSInstance::getNewDebugInstance(int numSlots, int multDepth, int logScale, bool verbose, bool useSEALParams, vector<int> galois_steps) {
  securityWarningBox("CREATING AN INSECURE DEBUG EVALUATOR. DO NOT USE IN PRODUCTION.");
  return new CKKSInstance(numSlots, multDepth, logScale, verbose,
                          useSEALParams, true, galois_steps);
}
CKKSInstance* CKKSInstance::loadDebugInstance(
    istream &paramsStream, istream &galoisKeyStream,
    istream &relinKeyStream, istream &secretKeyStream,
    bool verbose) {
  return new CKKSInstance(paramsStream, &galoisKeyStream, &relinKeyStream, &secretKeyStream, verbose, DEBUG);
}
CKKSInstance* CKKSInstance::loadEvalInstance(istream &paramsStream,
    istream &galoisKeyStream, istream &relinKeyStream, bool verbose) {
  return new CKKSInstance(paramsStream, &galoisKeyStream, &relinKeyStream, nullptr, verbose, EVALUATION);
}

CKKSInstance* CKKSInstance::loadNonEvalInstance(istream &paramsStream, istream &secretKeyStream, bool verbose) {
  return new CKKSInstance(paramsStream, nullptr, nullptr, &secretKeyStream, verbose, NONEVALUATION);
}

protobuf::helib::CKKSParams CKKSInstance::saveCKKSParams() {
  protobuf::helib::CKKSParams p;

  p.set_version(0);
  auto context_data = context->key_context_data();
  p.set_numslots(context_data->parms().poly_modulus_degree()/2);
  p.set_logscale(logScale);
  p.set_standardparams(standardParams);

  ostringstream sealpkBuf;
  pk.save(sealpkBuf);
  p.set_pubkey(sealpkBuf.str());

  for(const auto &prime : context_data->parms().coeff_modulus()) {
    p.add_modulusvec(prime.value());
  }

  return p;
}

CKKSInstance::CKKSInstance(Mode m, int numSlots, int multDepth, int logScale, bool verbose, bool useSEALParams): sealEncryptor(nullptr), decryptor(nullptr), mode(m) {
  sharedParamInit(numSlots, multDepth, logScale, useSEALParams, false);

  switch(mode) {
    case DEPTH:
      encryptor = new CKKSEncryptor(context, numSlots, false);
      evaluator = new DepthFinder(context, verbose);
      break;
    case OPCOUNT:
      encryptor = new CKKSEncryptor(context, numSlots, false);
      evaluator = new OpCount(context, verbose);
      break;
    case PLAINTEXT:
      encryptor = new CKKSEncryptor(context, numSlots, true);
      evaluator = new PlaintextEval(context, verbose);
      break;
    case SCALE:
      encryptor = new CKKSEncryptor(context, numSlots, true);
      evaluator = new ScaleEstimator(context, 2*numSlots, pow(2.0, logScale), verbose);
      break;
    default:
      throw invalid_argument("CKKSInstance: Unsupported mode");
  }
}

void CKKSInstance::sharedParamInit(int numSlots, int multDepth, int logScaleIn, bool useSEALParams, bool verbose) {
  logScale = logScaleIn;
  if(!isPow2(numSlots) || numSlots < 4096) {
    stringstream buffer;
    buffer << "Invalid parameters: numSlots must be a power of 2, and at least 4096. Got " << numSlots;
    throw invalid_argument(buffer.str());
  }

  int poly_modulus_degree = numSlots*2;
  if(logScale < MIN_LOG_SCALE) {
    stringstream buffer;
    buffer << "Invalid parameters: Implied logScale is " << logScale << ", which is less than the minimum, " << MIN_LOG_SCALE <<
            ". Either increase the number of slots or decrease the number of primes." << endl;
    buffer << "poly_modulus_degree is " << poly_modulus_degree << ", which limits the modulus to " << polyDegreeToMaxModBits(poly_modulus_degree) << " bits";
    throw invalid_argument(buffer.str());
  }
  vector<int> modulusVector;
  int numPrimes = multDepth+2;
  int modBits = genModulusVec(numPrimes, modulusVector);
  int min_poly_degree = modulusToPolyDegree(modBits);
  if(poly_modulus_degree < min_poly_degree) {
    stringstream buffer;
    buffer << "Invalid parameters: Ciphertexts for this combination of numPrimes and logScale have more than " << numSlots << " plaintext slots.";
    throw invalid_argument(buffer.str());
  }
  params = new EncryptionParameters(scheme_type::CKKS);
  params->set_poly_modulus_degree(poly_modulus_degree);
  params->set_coeff_modulus(CoeffModulus::Create(
      poly_modulus_degree, modulusVector));
  timepoint start = chrono::steady_clock::now();
  if(useSEALParams) {
    if(verbose) {cout << "Creating encryption context..." << flush;}
    context = SEALContext::Create(*params);
    if(verbose) {printElapsedTime(start);}
    standardParams = true;
  }
  else {
    securityWarningBox("YOU ARE NOT USING SEAL PARAMETERS. Encryption parameters may not achieve 128-bit security. DO NOT USE IN PRODUCTION.");
    // for large parameter sets, see https://github.com/microsoft/SEAL/issues/84
    if(verbose) {cout << "Creating encryption context..." << flush;}
    context = SEALContext::Create(*params, true, sec_level_type::none);
    if(verbose) {printElapsedTime(start);}
    standardParams = false;
  }
  encoder = new CKKSEncoder(context);
}

void CKKSInstance::reset() {
  evaluator->reset();
  encryptionCount = 0;
}

uint64_t estimateKeySize(int numGaloisShift, int ptslots, int depth) {
  int coefficientSizeBytes = 8;
  // size of a single polynomial with one modulus
  // each coefficient is 64 bits, and there are ptslots*2 coefficients.
  uint64_t poly_size_bytes = 2 * coefficientSizeBytes * ptslots;
  // size of a single ciphertext with one modulus
  // a (fresh) ciphertext is a pair of polynomials
  uint64_t ct_size_bytes = 2 * poly_size_bytes;
  // size of the secret key in bytes
  // a secret key is a single polynomial with (depth+2) moduli
  // The reason is that the biggest ciphertext for a depth d computation
  // has d+1 moduli, and SEAL requires an extra modulus for keys.
  uint64_t sk_bytes = (depth + 2) * poly_size_bytes;
  // size of the public key in bytes
  // a public key just a ciphertext with the (depth+2) moduli
  uint64_t pk_bytes = (depth + 2) * ct_size_bytes;
  // size of relinearization keys
  // each relinearization key is a vector of (depth+1) ciphertexts where each has (depth+2) moduli
  uint64_t rk_bytes = (depth + 1) * pk_bytes;
  // size of Galois keys
  // Galois keys are a vector of relinearization keys
  // there are at most 2*lg(ptslots)+1 keys, but there may be fewer if you have addional
  // information about what shifts are needed during a computation.
  uint64_t gk_bytes = numGaloisShift * rk_bytes;

  return sk_bytes + pk_bytes + rk_bytes + gk_bytes;
}

CKKSInstance::CKKSInstance(istream &paramsStream, istream *galoisKeyStream,
                           istream *relinKeyStream, istream *secretKeyStream, bool verbose,
                           Mode m) {

  mode = m;
  protobuf::helib::CKKSParams ckksParams;
  ckksParams.ParseFromIstream(&paramsStream);
  logScale = ckksParams.logscale();
  int numSlots = ckksParams.numslots();
  int poly_modulus_degree = numSlots*2;
  vector<Modulus> modulusVector;
  int numPrimes = ckksParams.modulusvec_size();
  for(int i = 0; i < numPrimes; i++) {
    modulusVector.push_back(Modulus(ckksParams.modulusvec(i)));
  }

  params = new EncryptionParameters(scheme_type::CKKS);
  params->set_poly_modulus_degree(poly_modulus_degree);
  params->set_coeff_modulus(modulusVector);

  standardParams = ckksParams.standardparams();
  timepoint start = chrono::steady_clock::now();
  if(standardParams) {
    if(verbose) {cout << "Creating encryption context..." << flush;}
    context = SEALContext::Create(*params);
    if(verbose) {printElapsedTime(start);}
  }
  else {
    securityWarningBox("YOU ARE NOT USING SEAL PARAMETERS. Encryption parameters may not achieve 128-bit security. DO NOT USE IN PRODUCTION.");
    // for large parameter sets, see https://github.com/microsoft/SEAL/issues/84
    if(verbose) {cout << "Creating encryption context..." << flush;}
    context = SEALContext::Create(*params, true, sec_level_type::none);
    if(verbose) {printElapsedTime(start);}
  }
  encoder = new CKKSEncoder(context);

  start = chrono::steady_clock::now();
  if(verbose) {cout << "Reading keys..." << flush;}
  istringstream pkstream(ckksParams.pubkey());
  pk.load(context, pkstream);
  sealEncryptor = new Encryptor(context, pk);
  encryptor = new CKKSEncryptor(context, encoder, sealEncryptor, mode == DEBUG);

  if(mode != EVALUATION && secretKeyStream == nullptr) {
    throw invalid_argument("SecretKeyStream is required in for non-eval evaluator");
  }

  if(secretKeyStream != nullptr) {
    sk.load(context, *secretKeyStream);
    decryptor = new CKKSDecryptor(context, encoder, sk);
  }
  if(galoisKeyStream != nullptr) {
    gk.load(context, *galoisKeyStream);
  }
  if(relinKeyStream != nullptr) {
    rk.load(context, *relinKeyStream);
  }
  if(verbose) {printElapsedTime(start);}

  if(mode == DEBUG) {
    evaluator = new DebugEval(context, *encoder, *sealEncryptor, gk, rk, pow(2.0, logScale), *decryptor, verbose);
  }
  else if(mode == NONEVALUATION) {
    // don't make an evaluator
    return;
  }
  else { // mode == NORMAL or EVALUATION
    evaluator = new HomomorphicEval(context, *encoder, *sealEncryptor, gk, rk, verbose);
  }
}

void CKKSInstance::save(ostream *paramsStream, ostream *galoisKeyStream,
                   ostream *relinKeyStream, ostream *secretKeyStream) {
  if(mode != NORMAL && mode != DEBUG) {
    throw invalid_argument("You can only save homomorphic or debug instances.");
  }
  if(secretKeyStream != nullptr) {
    sk.save(*secretKeyStream);
  }
  if(paramsStream != nullptr) {
    protobuf::helib::CKKSParams ckksParams = saveCKKSParams();
    ckksParams.SerializeToOstream(paramsStream);
  }
  if(galoisKeyStream != nullptr) {
    // There is a SEAL limitation that prevents saving large files with compression
    // This is reported at https://github.com/microsoft/SEAL/issues/142
    gk.save(*galoisKeyStream, compr_mode_type::none);
  }
  if(relinKeyStream != nullptr) {
    rk.save(*relinKeyStream);
  }
}

CKKSInstance::CKKSInstance(int numSlots, int multDepth, int logScale, bool verbose,
                           bool useSEALParams, bool debug, vector<int> galois_steps) {
  sharedParamInit(numSlots, multDepth, logScale, useSEALParams, true);

  int numGaloisKeys = galois_steps.size();
  cout << "Generating keys for " << numSlots << " slots and depth " << multDepth <<
          ", including " << (numGaloisKeys ? to_string(numGaloisKeys) : "all") << " Galois keys." << endl;

  double keysSizeBytes = estimateKeySize(galois_steps.size(), numSlots, multDepth);
  cout << "Estimated size is " << setprecision(3);
  // using base-10 (SI) units, rather than base-2 units.
  double unitMultiplier = 1000;
  double bytesPerKB = unitMultiplier;
  double bytesPerMB = bytesPerKB * unitMultiplier;
  double bytesPerGB = bytesPerMB * unitMultiplier;
  if(keysSizeBytes < bytesPerKB) {
    cout << keysSizeBytes << " bytes" << endl;
  }
  else if(keysSizeBytes < bytesPerMB) {
    cout << keysSizeBytes / bytesPerKB << " kilobytes (base 10)" << endl;
  }
  else if(keysSizeBytes < bytesPerGB) {
    cout << keysSizeBytes / bytesPerMB << " megabytes (base 10)" << endl;
  }
  else {
    cout << keysSizeBytes / bytesPerGB << " gigabytes (base 10)" << endl;
  }

  cout << "Generating keys..." << flush;
  timepoint start = chrono::steady_clock::now();

  // generate keys
  // This call generates a KeyGenerator with fresh randomness
  // The KeyGenerator object contains deterministic keys.
  KeyGenerator keygen(context);
  sk = keygen.secret_key();
  pk = keygen.public_key();
  if(numGaloisKeys > 0) {
    gk = keygen.galois_keys_local(galois_steps);
  }
  else {
    // generate all galois keys
    gk = keygen.galois_keys_local();
  }
  rk = keygen.relin_keys_local();

  printElapsedTime(start);

  sealEncryptor = new Encryptor(context, pk);
  encryptor = new CKKSEncryptor(context, encoder, sealEncryptor, debug);
  decryptor = new CKKSDecryptor(context, encoder, sk);

  if(debug) {
    evaluator = new DebugEval(context, *encoder, *sealEncryptor, gk, rk, pow(2.0, logScale), *decryptor, verbose);
    mode = DEBUG;
  }
  else {
    evaluator = new HomomorphicEval(context, *encoder, *sealEncryptor, gk, rk, verbose);
    mode = NORMAL;
  }

  if(debug && verbose) {
    print_parameters(context);
    cout << endl;

    // There are convenience method for accessing the SEALContext::ContextData for
    // some of the most important levels:

    //     SEALContext::key_context_data(): access to key level ContextData
    //     SEALContext::first_context_data(): access to highest data level ContextData
    //     SEALContext::last_context_data(): access to lowest level ContextData

    // We iterate over the chain and print the parms_id for each set of parameters.
    cout << "Print the modulus switching chain." << endl;

    // First print the key level parameter information.
    auto context_data = context->key_context_data();
    cout << "----> Level (chain index): " << context_data->chain_index();
    cout << " ...... key_context_data()" << endl;
    cout << "      parms_id: " << context_data->parms_id() << endl;
    cout << "      coeff_modulus primes: ";
    cout << hex;
    for(const auto &prime : context_data->parms().coeff_modulus()) {
      cout << prime.value() << " ";
    }
    cout << dec << endl;
    cout << "\\" << endl;
    cout << " \\-->";

    // Next iterate over the remaining (data) levels.
    context_data = context->first_context_data();
    while (context_data) {
      cout << " Level (chain index): " << context_data->chain_index();
      if (context_data->parms_id() == context->first_parms_id()) {
        cout << " ...... first_context_data()" << endl;
      }
      else if (context_data->parms_id() == context->last_parms_id()) {
        cout << " ...... last_context_data()" << endl;
      }
      else {
        cout << endl;
      }
      cout << "      parms_id: " << context_data->parms_id() << endl;
      cout << "      coeff_modulus primes: ";
      cout << hex;
      for(const auto &prime : context_data->parms().coeff_modulus()) {
        cout << prime.value() << " ";
      }
      cout << dec << endl;
      cout << "\\" << endl;
      cout << " \\-->";

      // Step forward in the chain.
      context_data = context_data->next_context_data();
    }
    cout << " End of chain reached" << endl << endl;
  }
}

CKKSInstance::~CKKSInstance() {
  if(mode == NONEVALUATION) {
    delete encryptor;
    delete sealEncryptor;
    delete decryptor;
  }
  else {
    delete evaluator;
    if(mode >= NORMAL) {
      delete encryptor;
      delete sealEncryptor;
      if(mode != EVALUATION) {
        delete decryptor;
      }
    }
  }

  delete encoder;
  delete params;
}

int CKKSInstance::genModulusVec(int numPrimes, vector<int> &modulusVector) {

  // covers the initial and final 60-bit modulus
  int modBits = 120;
  // the SEAL examples recommend the last modulus be 60 bits; it's unclear why,
  // and also unclear how closely that choice is related to logScale (they use 40 in their examples)
  modulusVector.push_back(60);
  for(int i = 2; i < numPrimes; i++) {
    modBits += logScale;
    modulusVector.push_back(logScale);
  }
  // The special modulus has to be as large as the largest prime in the chain.
  modulusVector.push_back(max(60, (int)logScale));

  return modBits;
}

void CKKSInstance::setMaxVal(const vector<double> &plain) {
  if(mode == SCALE || mode == DEBUG) {
    double maxVal = 0;
    for(int i = 0; i < plain.size(); i++) {
      maxVal = max(maxVal, abs(plain[i]));
    }

    if(mode == SCALE) {
      ScaleEstimator *e = dynamic_cast<ScaleEstimator*>(evaluator);
      e->updatePlaintextMaxVal(maxVal);
    }
    else {
      DebugEval *e = dynamic_cast<DebugEval*>(evaluator);
      e->updatePlaintextMaxVal(maxVal);
    }
  }
}

void CKKSInstance::encryptMatrix(const Matrix mat, CKKSCiphertext &destination, int lvl) {
  encryptor->encryptMatrix(mat, pow(2.0, logScale), destination, lvl);
  setMaxVal(mat.data());
  encryptionCount++;
}

void CKKSInstance::encryptColVec(const vector<double> &plain, int matHeight, CKKSCiphertext &destination, int lvl) {
  encryptor->encryptColVec(plain, matHeight, pow(2.0, logScale), destination, lvl);
  setMaxVal(plain);
  encryptionCount++;
}
void CKKSInstance::encryptRowVec(const vector<double> &plain, int matWidth, CKKSCiphertext &destination, int lvl) {
  encryptor->encryptRowVec(plain, matWidth, pow(2.0, logScale), destination, lvl);
  setMaxVal(plain);
  encryptionCount++;
}

vector<double> CKKSInstance::decrypt(const CKKSCiphertext &encrypted, bool verbose) {
  if(mode == NORMAL || mode == DEBUG || mode == NONEVALUATION) {
    return decryptor->decrypt(encrypted, verbose);
  }
  else {
    throw invalid_argument("CKKSInstance: You cannot call decrypt unless using the Homomorphic or Debug evaluators!");
  }
}

int CKKSInstance::plaintextDim() const {
  return encoder->slot_count();
}

double CKKSInstance::getEstimatedMaxLogScale() const {
  if(mode == SCALE) {
    ScaleEstimator *e = dynamic_cast<ScaleEstimator*>(evaluator);
    return e->getEstimatedMaxLogScale();
  }
  if(mode == DEBUG) {
    DebugEval *e = dynamic_cast<DebugEval*>(evaluator);
    return e->getEstimatedMaxLogScale();
  }
  throw invalid_argument("CKKSInstance: You cannot call getEstimatedMaxLogScale unless using the ScaleEstimator or DebugEval evaluator!");
}

double CKKSInstance::getExactMaxLogPlainVal() const {
  if(mode == SCALE) {
    ScaleEstimator *e = dynamic_cast<ScaleEstimator*>(evaluator);
    return e->getExactMaxLogPlainVal();
  }
  if(mode == PLAINTEXT) {
    PlaintextEval *e = dynamic_cast<PlaintextEval*>(evaluator);
    return e->getExactMaxLogPlainVal();
  }
  if(mode == DEBUG) {
    DebugEval *e = dynamic_cast<DebugEval*>(evaluator);
    return e->getExactMaxLogPlainVal();
  }
  throw invalid_argument("CKKSInstance: You cannot call getEstimatedMaxLogScale unless using the ScaleEstimator or DebugEval evaluator!");
}

int CKKSInstance::getMultiplicativeDepth() const {
  if(mode == DEPTH) {
    DepthFinder *e = dynamic_cast<DepthFinder*>(evaluator);
    return e->getMultiplicativeDepth();
  }
  if(mode == OPCOUNT) {
    OpCount *e = dynamic_cast<OpCount*>(evaluator);
    return e->getMultiplicativeDepth();
  }
  throw invalid_argument("CKKSInstance: You cannot call getMultiplicativeDepth unless using the DepthFinder evaluator!");
}

void CKKSInstance::printOpCount() const {
  if(mode == OPCOUNT) {
    OpCount *e = dynamic_cast<OpCount*>(evaluator);
    cout  << endl << "Encryptions: " << encryptionCount;
    e->printOpCount();
    return;
  }
  throw invalid_argument("CKKSInstance: You cannot call printOpCount unless using the OpCount evaluator!");
}

CKKSInstance* tryLoadInstance(int numSlots, int multDepth, int logScale, Mode mode, vector<int> galois_steps) {
  string keydir = "keys";

  string paramID = to_string(2*numSlots)+"-"+to_string(multDepth + 2)+"-"+to_string(logScale);
  string paramsPath = keydir + "/" + paramID;

  if(!fs::exists(paramsPath)) {
    fs::create_directories(paramsPath);
  }

  string paramsFilePath = paramsPath + "/params.bin";
  string galoisFilePath = paramsPath + "/galois.bin";
  string relinFilePath = paramsPath + "/relin.bin";
  string privkeyFilePath = paramsPath + "/privkey.bin";

  CKKSInstance *c = nullptr;

  // We can't create generic fstream here for both cases:
  // if the file doesn't exist, opening an fstream with `ios::in | ios::out`
  // will create an empty file which will cause us to fall into
  // the wrong branch of the `if` statement.
  if(fs::exists(paramsFilePath) && fs::exists(privkeyFilePath)) {
    ifstream paramsFile(paramsFilePath, ios::in | ios::binary);
    ifstream privkeyFile(privkeyFilePath, ios::in | ios::binary);

    if(mode == NONEVALUATION) {
      c = CKKSInstance::loadNonEvalInstance(paramsFile, privkeyFile);
    }

    if((mode == DEBUG || mode == NORMAL) &&
       fs::exists(galoisFilePath) &&
       fs::exists(relinFilePath)) {

      ifstream galoisFile(galoisFilePath, ios::in | ios::binary);
      ifstream relinFile(relinFilePath, ios::in | ios::binary);

      if(mode == DEBUG) {
        c = CKKSInstance::loadDebugInstance(paramsFile, galoisFile, relinFile, privkeyFile);
      }
      else {
        c = CKKSInstance::loadHomomorphicInstance(paramsFile, galoisFile, relinFile, privkeyFile);
      }

      galoisFile.close();
      relinFile.close();
    }

    paramsFile.close();
    privkeyFile.close();
  }
  else {
    ofstream paramsFile(paramsFilePath, ios::out | ios::binary);
    ofstream galoisFile(galoisFilePath, ios::out | ios::binary);
    ofstream relinFile(relinFilePath, ios::out | ios::binary);
    ofstream privkeyFile(privkeyFilePath, ios::out | ios::binary);
    if(mode == DEBUG) {
      c = CKKSInstance::getNewDebugInstance(numSlots, multDepth, logScale, false, false, galois_steps);
    }
    else { // NORMAL *or* NON-EVALUATION
      c = CKKSInstance::getNewHomomorphicInstance(numSlots, multDepth, logScale, false, false, galois_steps);
    }
    cout << "Saving keys to disk..." << flush;
    timepoint start = chrono::steady_clock::now();
    c->save(&paramsFile, &galoisFile, &relinFile, &privkeyFile);
    printElapsedTime(start);
    paramsFile.close();
    galoisFile.close();
    relinFile.close();
    privkeyFile.close();
  }

  return c;
}
