
#include "testutil.h"

using namespace std;
using namespace hit;

uint32_t create_random_positive_int(const int mod) {
    srand(time(nullptr));
    return rand() % mod + 1;
}

// generate a random vector of the given dimension, where each value is in the range [-max_norm, max_norm].
vector<double> random_vector(int dim, double max_norm) {
    vector<double> x;
    x.reserve(dim);

    for (int i = 0; i < dim; i++) {
        // generate a random double between -max_norm and max_norm
        double a = -max_norm + ((static_cast<double>(random())) / (static_cast<double>(RAND_MAX))) * (2 * max_norm);
        x.push_back(a);
    }
    return x;
}

const int max_vec_norm = 10;

Vector random_vec(int size) {
    return Vector(random_vector(size, max_vec_norm));
}

Matrix random_mat(int height, int width) {
    return Matrix(height, width, random_vector(height * width, max_vec_norm));
}
