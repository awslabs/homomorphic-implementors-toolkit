
#include <iostream>

using namespace std;

extern void example_1_driver();
extern void example_2_driver();
extern void example_3_driver();
extern void example_4_driver();
extern void example_5_driver();

int main() {
	cout << "Running example 1: " << endl;
	example_1_driver();
	cout << endl << endl;
	cout << "Running example 2: " << endl;
	example_2_driver();
	cout << endl << endl;
	cout << "Running example 3: " << endl;
	example_3_driver();
	cout << endl << endl;
	cout << "Running example 4: " << endl;
	example_4_driver();
	cout << endl << endl;
	cout << "Running example 5: " << endl;
	example_5_driver();
	cout << "Done with all examples!" << endl;
}
