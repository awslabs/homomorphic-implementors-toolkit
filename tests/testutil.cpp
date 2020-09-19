
#include "testutil.h"

using namespace std;
using namespace hit;

uint32_t createRandomPositiveInt(const int mod) {
    srand(time(nullptr));
    return rand() % mod + 1;
}

// generate a random vector of the given dimension, where each value is in the range [-maxNorm, maxNorm].
vector<double> randomVector(int dim, double maxNorm) {
    vector<double> x;
    x.reserve(dim);

    for (int i = 0; i < dim; i++) {
        // generate a random double between -maxNorm and maxNorm
        double a = -maxNorm + ((static_cast<double>(random())) / (static_cast<double>(RAND_MAX))) * (2 * maxNorm);
        x.push_back(a);
    }
    return x;
}

const int max_vec_norm = 10;

Vector random_vec(int size) {
    return Vector(randomVector(size, max_vec_norm));
}

Matrix random_mat(int height, int width) {
    return Matrix(height, width, randomVector(height * width, max_vec_norm));
}
