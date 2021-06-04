// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "hit/hit.h"
#include <fstream>
#include <glog/logging.h>

using namespace std;
using namespace hit;

// defined in example_1_ckks.cpp
extern vector<double> random_vector(int dim, double maxNorm);

// defined in example_2_plaintext.cpp
extern CKKSCiphertext poly_eval_homomorphic_v1(CKKSEvaluator &eval, CKKSCiphertext &ct);

// defined below
void example_5_server();

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

	LOG(INFO) << "Generating client keys...";

	// In a production application, only the Homomorphic instance type
	// should be used!
	HomomorphicEval he_inst(num_slots, max_depth, log_scale);

	LOG(INFO) << "Encrypting client data...";
	// The next step in the client/server model is for the client to encrypt some data
	vector<double> data = random_vector(num_slots, 10);
	CKKSCiphertext ct = he_inst.encrypt(data);

	/* Next, the client sends everything the server needs for evaluation. This includes:
	 *   - encrypted data
	 *   - cryptosystem parameters
	 *   - (public) evalaution keys
	 */

	LOG(INFO) << "Serializing client keys...";
	// First, serialize the instance parameters
	ofstream params_stream("/tmp/params", ios::out | ios::binary);
	ofstream galois_key_stream("/tmp/galois", ios::out | ios::binary);
	ofstream relin_key_stream("/tmp/relin", ios::out | ios::binary);
	/* We can optionally write the secret key to a stream, but we don't need to
	 * for this application since the client blocks until the server returns
	 * its result.
	 * Alternatively, if the client does save secret key to a stream, a new
	 * instance can be loaded when the server computation is complete.
	 */
	he_inst.save(params_stream, galois_key_stream, relin_key_stream, nullptr);

	// Don't forget to close the streams!
	params_stream.close();
	galois_key_stream.close();
	relin_key_stream.close();

	LOG(INFO) << "Serializing client data...";
	// If our data consists of a single ciphertext, we can use the `save` API.
	// Typically, we might need to send several ciphertexts to the server, which
	// can be done by sending multiple small streams (via `save`) or by packaging
	// these encrypted values into a custom protobuf type using the `serialize` API.
	ofstream output_data_stream("/tmp/dataout", ios::out | ios::binary);
	ct.save(output_data_stream);

	// Don't forget to close the stream!
	output_data_stream.close();

	/* At this point, the client transmits the serialized data to the server
	 * and waits for a response. In this demo, we'll cheat and invoke the server
	 * directly.
	 */
	LOG(INFO) << "Invoking remote server...";
	example_5_server();
	LOG(INFO) << "Deserializing computation result...";

	// The server will send back a response, which we can then read
	ifstream input_data_stream("/tmp/datain", ios::in | ios::binary);
	CKKSCiphertext homom_result(he_inst.context, input_data_stream);

	// Don't forget to close the stream!
	input_data_stream.close();

	LOG(INFO) << "Decrypting computation result...";

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

	LOG(INFO) << "Server is reading instance parameters and keys...";
	ifstream params_stream("/tmp/params", ios::in | ios::binary);
	ifstream galois_key_stream("/tmp/galois", ios::in | ios::binary);
	ifstream relin_key_stream("/tmp/relin", ios::in | ios::binary);

	// We will create a HomomorphicEval instance using the instance parameters
	// and evaluation keys. However, this instance will be incapable of decryption
	// because it does not know the secret key.
	// It is an error to call `he_inst.decrypt` with a HomomorphicEval constructed
	// this way.
	HomomorphicEval he_inst(params_stream, galois_key_stream, relin_key_stream);

	// Don't forget to close the streams!
	params_stream.close();
	galois_key_stream.close();
	relin_key_stream.close();

	LOG(INFO) << "Server is deserializing data...";

	// The server's input is the client's output
	ifstream input_data_stream("/tmp/dataout", ios::in | ios::binary);
	CKKSCiphertext ct_in = CKKSCiphertext(he_inst.context, input_data_stream);

	// Don't forget to close the stream!
	input_data_stream.close();

	LOG(INFO) << "Server is computing on encrypted data...";
	// We can now evaluate the homomorphic function.
	CKKSCiphertext ct_result = poly_eval_homomorphic_v1(he_inst, ct_in);

	LOG(INFO) << "Server is serializing computation result...";
	// And save the result to the client's input stream
	ofstream output_data_stream("/tmp/datain", ios::out | ios::binary);
	ct_result.save(output_data_stream);

	// Don't forget to close the stream!
	output_data_stream.close();
}

void example_5_driver() {
	// In this toy demo, the client invokes the server directly, so to kick things off,
	// we just invoke the client.
	example_5_client();
}
