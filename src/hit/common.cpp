// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "common.h"

#include <glog/logging.h>

#include <iomanip>  // setprecision

using namespace std;

namespace hit {

    uint64_t elapsedTimeMs(timepoint start, timepoint end) {
        return chrono::duration_cast<chrono::milliseconds>(end - start).count();
    }

    string elapsedTimeToStr(timepoint start, timepoint end, TimeScale ts) {
        auto elapsedMs = static_cast<double>(elapsedTimeMs(start, end));
        stringstream buffer;
        double msPerSec = 1000;
        double msPerMin = 60 * msPerSec;
        double msPerHour = 60 * msPerMin;
        if (ts == TS_MS || (ts == TS_DYNAMIC && elapsedMs < msPerSec)) {
            buffer << setprecision(3) << elapsedMs << " ms";
        } else if (ts == TS_SEC || (ts == TS_DYNAMIC && elapsedMs < msPerMin)) {
            buffer << setprecision(3) << elapsedMs / msPerSec << " seconds";
        } else if (ts == TS_MIN || (ts == TS_DYNAMIC && elapsedMs < msPerHour)) {
            buffer << setprecision(3) << elapsedMs / msPerMin << " minutes";
        } else {
            buffer << setprecision(3) << elapsedMs / msPerHour << " hours";
        }
        return buffer.str();
    }

    string bytesToStr(uintmax_t sizeBytes) {
        double unitMultiplier = 1000;
        double bytesPerKB = unitMultiplier;
        double bytesPerMB = bytesPerKB * unitMultiplier;
        double bytesPerGB = bytesPerMB * unitMultiplier;
        stringstream buffer;

        if (sizeBytes < bytesPerKB) {
            buffer << sizeBytes << " bytes";
        } else if (sizeBytes < bytesPerMB) {
            buffer << (sizeBytes / bytesPerKB) << " KB";
        } else if (sizeBytes < bytesPerGB) {
            buffer << (sizeBytes / bytesPerMB) << " MB";
        } else {
            buffer << (sizeBytes / bytesPerGB) << " GB";
        }
        return buffer.str();
    }

    void printElapsedTime(timepoint start) {
        timepoint end = chrono::steady_clock::now();
        LOG(INFO) << elapsedTimeToStr(start, end);
    }

    // vector<double> decodePlaintext(const vector<double> &encoded_pt, CTEncoding encoding, int height, int width,
    //                                int encoded_height, int encoded_width) {
    //     vector<double> dest;

    //     if (encoding == COL_VEC && (width != 1 || height != encoded_width)) {
    //         stringstream buffer;
    //         buffer << "Invalid column vector encoding: real size= " << height << "x" << width
    //                << "; encoded size= " << encoded_height << "x" << encoded_width;
    //         throw invalid_argument(buffer.str());
    //     }
    //     if (encoding == ROW_VEC && (height != 1 || width != encoded_height)) {
    //         stringstream buffer;
    //         buffer << "Invalid row vector encoding: real size= " << height << "x" << width
    //                << "; encoded size= " << encoded_height << "x" << encoded_width;
    //         throw invalid_argument(buffer.str());
    //     }

    //     if (encoding == MATRIX || encoding == ROW_MAT || encoding == COL_MAT || encoding == COL_VEC) {
    //         int size = height * width;
    //         dest = vector<double>(encoded_pt.begin(), encoded_pt.begin() + size);
    //     } else {  // encoding is a row vector, which becomes the columns of the matrix
    //         for (int i = 0; i < width; i++) {
    //             // puts the left column into the destination, which corresponds to the encoded row vector
    //             dest.push_back(encoded_pt[i * encoded_width]);
    //         }
    //     }
    //     return dest;
    // }

    // computes the |expected-actual|/|expected|, where |*| denotes the 2-norm.
    double diff2Norm(const vector<double> &expected, const vector<double> &actual) {
        int len = expected.size();
        if (len != actual.size()) {
            stringstream buffer;
            buffer << "diff2Norm inputs do not have the same size: " << len << " != " << actual.size();
            throw invalid_argument(buffer.str());
        }

        Vector expectedVec = fromStdVector(expected);
        Vector actualVec = fromStdVector(actual);
        Vector diffVec = expectedVec - actualVec;
        double expectedL2Norm = norm_2(expectedVec);
        double actualL2Norm = norm_2(actualVec);
        double diffL2Norm = norm_2(diffVec);

        // if the expected result is the zero vector, we can't reasonably compare norms.
        // We also can't just test if the expected vector norm is exactly 0 due to
        // decoding precision in CKKS. In other words, decode(encode(<0,0,...>))
        // may contain very small non-zero values. (Note that this has nothing to
        // do with encryption noise.) The "actual" result, which typically comes
        // from decryption a CKKS ciphertext, will have much larger coefficients.
        // For example, decoding noise for the all-0 vector may result in coefficients
        // with magnitude ~10^-30. Decryption of the all-0 vector will result in
        // coefficients ~10^-11. Since these are vastly different scales, the relative
        // norm is huge, even though these vectors both represent 0. As a result,
        // we instead fuzz the norm test: if the expected vector norm is "small enough"
        // we skip the comparison altogether. The magic constant below seems to work
        // well in practice.
        int logNormLimit = 11;
        double maxAllowedL2Norm = pow(2, -logNormLimit);
        if (expectedL2Norm <= maxAllowedL2Norm && actualL2Norm <= maxAllowedL2Norm) {
            return -1;
        }

        if (expectedL2Norm <= maxAllowedL2Norm) {
            LOG(INFO) << "WEIRD NORM SITUATION: " << expectedL2Norm << "\t" << actualL2Norm;
        }
        if (diffL2Norm > MAX_NORM) {
            LOG(INFO) << "LogL2Norm: " << setprecision(8) << log2(expectedL2Norm);
        }
        return diffL2Norm;
    }

    // true if x is a power of 2, false otherwise.
    bool isPow2(int x) {
        if (x < 1) {
            return false;
        } else if (x == 1) {  // NOLINT(readability-else-after-return)
            return true;
        }
        // x > 1 and not 0 mod 2 => not a power of 2
        else if (x % 2 == 1) {
            return false;
        } else {
            return isPow2(x >> 1);
        }
    }

    int polyDegreeToMaxModBits(int poly_modulus_degree) {
        switch (poly_modulus_degree) {
            case 1024:
                return 27;
            case 2048:
                return 54;
            case 4096:
                return 109;
            case 8192:
                return 218;
            case 16384:
                return 438;
            case 32768:
                return 881;
            case 65536:
                // extrapolating a best-fit line for the above data points:
                // mod_bits <= 0.0269*poly_modulus_degree-1.4428

                // SEAL will throw an exception when poly degree is 131072 or larger
                // (which corresponds to the 262144th cyclotomic ring)
                return 1761;
            default:
                stringstream buffer;
                buffer << "poly_modulus_degree=" << poly_modulus_degree << " not supported";
                throw invalid_argument(buffer.str());
        }
    }

    int modulusToPolyDegree(int modBits) {
        // When determining what dimension to use, we must first determine how many
        // primes need to be in our modulus (more on this below). Then we must
        // consult the following table to determine the smallest possible dimension.
        // A larger coeff_modulus implies a larger noise budget, hence more encrypted
        // computation capabilities. However, an upper bound for the total bit-length
        // of the coeff_modulus is determined by the poly_modulus_degree, as follows:
        //
        //     +----------------------------------------------------+
        //     | poly_modulus_degree | max coeff_modulus bit-length |
        //     +---------------------+------------------------------+
        //     | 1024                | 27                           |
        //     | 2048                | 54                           |
        //     | 4096                | 109                          |
        //     | 8192                | 218                          |
        //     | 16384               | 438                          |
        //     | 32768               | 881                          |
        //     +---------------------+------------------------------+
        if (modBits <= 27) {
            return 1024;
            // NOLINTNEXTLINE(readability-else-after-return)
        } else if (modBits <= 54) {
            return 2048;
        } else if (modBits <= 109) {
            return 4096;
        } else if (modBits <= 218) {
            return 8192;
        } else if (modBits <= 438) {
            return 16384;
        } else if (modBits <= 881) {
            return 32768;
        } else if (modBits <= 1761) {
            return 65536;
        }
        // SEAL will throw an exception when poly degree is 131072 or larger
        // (which corresponds to the 262144th cyclotomic ring)
        // else if(modBits <= 3524) { return 131072; }
        // else if(modBits <= 7050) { return 262144; }
        else {
            stringstream buffer;
            buffer << "This computation is too big to handle right now: cannot determine a valid ring size for a "
                   << modBits << "-bit modulus";
            throw invalid_argument(buffer.str());
        }
    }

    double lInfNorm(const vector<double> &x) {
        double xmax = 0;
        for (double i : x) {
            xmax = max(xmax, abs(i));
        }
        return xmax;
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

    uintmax_t streamSize(iostream &s) {
        streampos originalPos = s.tellp();
        s.seekp(0, ios::end);
        uintmax_t size = s.tellp();
        s.seekp(originalPos);
        return size;
    }

}  // namespace hit
