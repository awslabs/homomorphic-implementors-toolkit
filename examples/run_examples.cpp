// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>
#include <glog/logging.h>

using namespace std;

extern void example_1_driver();
extern void example_2_driver();
extern void example_3_driver();
extern void example_4_driver();
extern void example_5_driver();
extern void example_6_driver();

int main(int, char **argv) {
	google::InitGoogleLogging(argv[0]);
	LOG(INFO) << "Running example 1: " << endl;
	example_1_driver();
	LOG(INFO) << endl << endl;
	LOG(INFO) << "Running example 2: " << endl;
	example_2_driver();
	LOG(INFO) << endl << endl;
	LOG(INFO) << "Running example 3: " << endl;
	example_3_driver();
	LOG(INFO) << endl << endl;
	LOG(INFO) << "Running example 4: " << endl;
	example_4_driver();
	LOG(INFO) << endl << endl;
	LOG(INFO) << "Running example 5: " << endl;
	example_5_driver();
	LOG(INFO) << endl << endl;
	LOG(INFO) << "Running example 6: " << endl;
	example_6_driver();
	LOG(INFO) << "Done with all examples!" << endl;
}
