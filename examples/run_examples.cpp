// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

using namespace std;

extern void example_1_driver();
extern void example_2_driver();
extern void example_3_driver();
extern void example_4_driver();
extern void example_5_driver();

int main() {
	VLOG(LOG_VERBOSE) << "Running example 1: " << endl;
	example_1_driver();
	VLOG(LOG_VERBOSE) << endl << endl;
	VLOG(LOG_VERBOSE) << "Running example 2: " << endl;
	example_2_driver();
	VLOG(LOG_VERBOSE) << endl << endl;
	VLOG(LOG_VERBOSE) << "Running example 3: " << endl;
	example_3_driver();
	VLOG(LOG_VERBOSE) << endl << endl;
	VLOG(LOG_VERBOSE) << "Running example 4: " << endl;
	example_4_driver();
	VLOG(LOG_VERBOSE) << endl << endl;
	VLOG(LOG_VERBOSE) << "Running example 5: " << endl;
	example_5_driver();
	VLOG(LOG_VERBOSE) << "Done with all examples!" << endl;
}
