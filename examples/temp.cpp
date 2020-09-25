// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/hit.h"
#include "../tests/testutil.h"

using namespace std;
using namespace hit;

void f(CKKSEvaluator &inst, CKKSCiphertext x) {
  int plaintext_inf_norm = 10;
  vector<double> y = random_vector(4096, plaintext_inf_norm);
  inst.add(x,x);
  cout << "Scale bits: " << log2(x.scale()) << " SIZE: " << x.seal_ct.size() << endl;
}

int main() {
  int num_slots = 4096;
  int max_depth = 2;
  int log_scale = 40;

  HomomorphicEval inst = HomomorphicEval(num_slots, max_depth, log_scale);

  // Generate a plaintext with `num_slots` random coefficients, each with absolute value < `plaintext_inf_norm`
  int plaintext_inf_norm = 10;
  vector<double> plaintext = random_vector(num_slots, plaintext_inf_norm);

  // Encrypt the plaintext. By default, the ciphertext is created at the maximum
  // level allowed by the parameters, which is `max_depth`.
  CKKSCiphertext ciphertext1 = inst.encrypt(plaintext);
  CKKSCiphertext ciphertext2 = inst.encrypt(plaintext);

  // linear, nominal scale
  try {
    f(inst, ciphertext1);
    cout << "Passed linear/nominal" << endl;
  }
  catch(const exception &e) {
    cout << "Failed linear/nominal:\t" << e.what() << endl;
  }

  // linear, squared scale
  CKKSCiphertext ciphertext3 = inst.multiply_plain(ciphertext2, 2);
  try {
    f(inst, ciphertext3);
    cout << "Passed linear/squared" << endl;
  }
  catch(const exception &e) {
    cout << "Failed linear/squared:\t" << e.what() << endl;
  }

  // quadratic, squared scale
  CKKSCiphertext ciphertext4 = inst.multiply(ciphertext1, ciphertext2);
  try {
    f(inst, ciphertext4);
    cout << "Passed quadratic/squared" << endl;
  }
  catch(const exception &e) {
    cout << "Failed quadratic/squared:\t" << e.what() << endl;
  }

  // quadratic, nominal scale
  CKKSCiphertext ciphertext5 = ciphertext4;
  inst.rescale_to_next_inplace(ciphertext5);
  try {
    f(inst, ciphertext5);
    cout << "Passed quadratic/nominal" << endl;
  }
  catch(const exception &e) {
    cout << "Failed quadratic/nominal:\t" << e.what() << endl;
  }









  cout << endl << endl;
  // linear/nominal and quadratic/nominal
  try {
    CKKSCiphertext temp = inst.reduce_level_to(ciphertext1, ciphertext5);
    inst.add(temp,ciphertext5);
    cout << "Passed linear/nominal and quadratic/nominal" << endl;
  }
  catch(const exception &e) {
    cout << "Failed linear/nominal and quadratic/nominal:\t" << e.what() << endl;
  }

  // linear/nominal and linear/squared
  try {
    inst.add(ciphertext1,ciphertext3);
    cout << "Passed linear/nominal and linear/squared" << endl;
  }
  catch(const exception &e) {
    cout << "Failed linear/nominal and linear/squared:\t" << e.what() << endl;
  }

  // linear/nominal and quadratic/squared
  try {
    inst.add(ciphertext1,ciphertext4);
    cout << "Passed linear/nominal and quadratic/squared" << endl;
  }
  catch(const exception &e) {
    cout << "Failed linear/nominal and quadratic/squared:\t" << e.what() << endl;
  }

  // quadratic/nominal and linear/squared
  try {
    CKKSCiphertext temp = inst.encrypt(plaintext,1);
    inst.multiply_plain_inplace(temp, 2);
    inst.add(ciphertext5,temp);
    cout << "Passed quadratic/nominal and linear/squared" << endl;
  }
  catch(const exception &e) {
    cout << "Failed quadratic/nominal and linear/squared:\t" << e.what() << endl;
  }

  // quadratic/nominal and quadratic/squared
  try {
    CKKSCiphertext temp1 = inst.encrypt(plaintext,1);
    CKKSCiphertext temp2 = inst.encrypt(plaintext,1);
    CKKSCiphertext temp3 = inst.multiply(temp1, temp2);
    inst.add(ciphertext5,temp3);
    cout << "Passed quadratic/nominal and quadratic/squared" << endl;
  }
  catch(const exception &e) {
    cout << "Failed quadratic/nominal and quadratic/squared:\t" << e.what() << endl;
  }

  // linear/squared and quadratic/squared
  try {
    inst.add(ciphertext3,ciphertext4);
    cout << "Passed linear/squared and quadratic/squared" << endl;
  }
  catch(const exception &e) {
    cout << "Failed linear/squared and quadratic/squared:\t" << e.what() << endl;
  }
}
