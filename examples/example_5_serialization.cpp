// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/hit.h"
#include <fstream>

using namespace std;
using namespace hit;

// defined in example_1_ckks.cpp
extern vector<double> randomVector(int dim, double maxNorm);

// defined in example_2_plaintext.cpp
extern CKKSCiphertext poly_eval_homomorphic_v1(CKKSEvaluator &eval, CKKSCiphertext &ct);

/* This example demonstrates how to use HIT in a basic
 * client/server application for outsourced computation.
 * In the basic scenario, a client has unencrypted data, and wants to
 * outsource the computation of a target function on the encrypted data.
 */

void example_5_client() {
/* First, the client generates homomorphic encryption parameters and keys,
 * as well as public keys needed for the server to evaluate the target function.
 */
	int num_slots = 8192;
	int max_depth = 3;
	int log_scale = 40;

	// In a production application, only the Homomorphic instance type
	// should be used!
	HomomorphicEval he_inst = HomomorphicEval(num_slots, max_depth, log_scale);

	// The next step in the client/server model is for the client to encrypt some data
	vector<double> data = randomVector(num_slots, 10);
	CKKSCiphertext ct = he_inst.encrypt(data);

/* Next, the client sends everything the server needs for evaluation. This includes:
 *   - encrypted data
 *   - cryptosystem parameters
 *   - (public) evalaution keys
 */
	// First, serialize the instance parameters
	ofstream paramsStream("/tmp/params", ios::out | ios::binary);
	ofstream galoisKeyStream("/tmp/galois", ios::out | ios::binary);
	ofstream relinKeyStream("/tmp/relin", ios::out | ios::binary);
	// We can optionally write the secret key to a stream, but we don't need to
	// for this application.
	he_inst.save(paramsStream, galoisKeyStream, relinKeyStream, nullptr);

	// Don't forget to close the streams!
	paramsStream.close();
	galoisKeyStream.close();
	relinKeyStream.close();

	// If our data consists of a single ciphertext, we can use the `save` API.
	// Typically, we might need to send several ciphertexts to the server, which
	// can be done by sending multiple small streams (via `save`) or by packaging
	// these encrypted values into a custom protobuf type using the `serialize` API.
	ofstream outputDataStream("/tmp/dataout", ios::out | ios::binary);
	ct.save(outputDataStream);

	// Don't forget to close the stream!
	outputDataStream.close();

/* At this point, the client transmits the serialized data to the server
 * and waits for a response. In this demo, we'll cheat and invoke the server
 * directly.
 */
	example_5_server();

	// The server will send back a response, which we can then read
	ofstream inputDataStream("/tmp/datain", ios::in | ios::binary);
	CKKSCiphertext homom_result = CKKSCiphertext(he_inst.context, inputDataStream);

	// Don't forget to close the stream!
	inputDataStream.close();

	// Finally, we can decrypt the result
	vector<double> plain_result = he_inst.decrypt(homom_result);
}

void example_5_server() {
	// The server waits for data from the client
	// When data is available, the server first creates an CKKS instance
	// using the parameters and evaluation keys, then parses the encrypted
	// data using the CKKS instance. Finally, the server can evaluate the
	// function on the encrypted data, serialize the result, and send it to the
	// client.

	ofstream paramsStream("/tmp/params", ios::in | ios::binary);
	ofstream galoisKeyStream("/tmp/galois", ios::in | ios::binary);
	ofstream relinKeyStream("/tmp/relin", ios::in | ios::binary);

	// We will create a HomomorphicEval instance using the instance parameters
	// and evaluation keys. However, this instance will be incapable of decryption
	// because it does not know the secret key.
	// It is an error to call `he_inst.decrypt` with a HomomorphicEval constructed
	// this way.
	HomomorphicEval he_inst = HomomorphicEval(paramsStream, galoisKeyStream, relinKeyStream);

	// Don't forget to close the streams!
	paramsStream.close();
	galoisKeyStream.close();
	relinKeyStream.close();

	// The server's input is the client's output
	ofstream inputDataStream("/tmp/dataout", ios::in | ios::binary);
	CKKSCiphertext ct_in = CKKSCiphertext(he_inst.context, inputDataStream);

	// Don't forget to close the stream!
	inputDataStream.close();

	// We can now evaluate the homomorphic function.
	CKKSCiphertext ct_result = poly_eval_homomorphic_v1(he_inst, ct_in);

	// And save the result to the client's input stream
	ofstream outputDataStream("/tmp/datain", ios::out | ios::binary);
	ct.save(outputDataStream);

	// Don't forget to close the stream!
	outputDataStream.close();
}


TODO: how to free

void example_5_driver() {
	// In this toy demo, the client invokes the server directly, so to kick things off,
	// we just invoke the client.
	example_5_client();
}
