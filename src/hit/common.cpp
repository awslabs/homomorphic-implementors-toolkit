// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "common.h"

#include <glog/logging.h>

#include <iomanip>  // setprecision

using namespace std;

namespace hit {

    uint64_t elapsed_time_in_ms(timepoint start, timepoint end) {
        return chrono::duration_cast<chrono::milliseconds>(end - start).count();
    }

    string elapsed_time_to_str(timepoint start, timepoint end, TimeScale ts) {
        auto elapsed_ms = static_cast<double>(elapsed_time_in_ms(start, end));
        stringstream buffer;
        double ms_per_sec = 1000;
        double ms_per_min = 60 * ms_per_sec;
        double ms_per_hour = 60 * ms_per_min;
        if (ts == TS_MS || (ts == TS_DYNAMIC && elapsed_ms < ms_per_sec)) {
            buffer << setprecision(3) << elapsed_ms << " ms";
        } else if (ts == TS_SEC || (ts == TS_DYNAMIC && elapsed_ms < ms_per_min)) {
            buffer << setprecision(3) << elapsed_ms / ms_per_sec << " seconds";
        } else if (ts == TS_MIN || (ts == TS_DYNAMIC && elapsed_ms < ms_per_hour)) {
            buffer << setprecision(3) << elapsed_ms / ms_per_min << " minutes";
        } else {
            buffer << setprecision(3) << elapsed_ms / ms_per_hour << " hours";
        }
        return buffer.str();
    }

    string bytes_to_str(uintmax_t size_bytes) {
        double unit_multiplier = 1000;
        double bytes_per_kb = unit_multiplier;
        double bytes_per_mb = bytes_per_kb * unit_multiplier;
        double bytes_per_gb = bytes_per_mb * unit_multiplier;
        stringstream buffer;

        if (size_bytes < bytes_per_kb) {
            buffer << size_bytes << " bytes";
        } else if (size_bytes < bytes_per_mb) {
            buffer << (size_bytes / bytes_per_kb) << " KB";
        } else if (size_bytes < bytes_per_gb) {
            buffer << (size_bytes / bytes_per_mb) << " MB";
        } else {
            buffer << (size_bytes / bytes_per_gb) << " GB";
        }
        return buffer.str();
    }

    void print_elapsed_time(timepoint start) {
        timepoint end = chrono::steady_clock::now();
        VLOG(VLOG_STATUS) << elapsed_time_to_str(start, end);
    }

    // computes the |expected-actual|/|expected|, where |*| denotes the 2-norm.
    double relative_error(const vector<double> &expected, const vector<double> &actual) {
        int len = expected.size();
        if (len != actual.size()) {
            LOG(ERROR) << "Inputs to relative error do not have the same size: "
                       << len << " != " << actual.size();
            throw invalid_argument("An error occurred. See the log for details.");
        }

        Vector expected_vec = Vector(expected);
        Vector actual_vec = Vector(actual);
        Vector diff_vec = expected_vec - actual_vec;
        double expected_l2_norm = norm_2(expected_vec);
        double actual_l2_norm = norm_2(actual_vec);
        double diff_l2_norm = norm_2(diff_vec);

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
        int log_norm_limit = 11;
        double max_allowed_l2_norm = pow(2, -log_norm_limit);
        if (expected_l2_norm <= max_allowed_l2_norm && actual_l2_norm <= max_allowed_l2_norm) {
            return -1;
        }

        if (expected_l2_norm <= max_allowed_l2_norm) {
            // An unexpected situation.
            LOG(WARNING) << "The expected result's norm is nearly zero (2^"
                         << setprecision(8) << log2(expected_l2_norm)
                         << "), but the actual result's norm is non-zero (2^"
                         << log2(actual_l2_norm) << ")";
        }
        if (diff_l2_norm > MAX_NORM) {
            LOG(WARNING) << "Relative norm is somewhat large (2^"
                         << setprecision(8) << log2(diff_l2_norm)
                         << "); there may be an error in the computation.";
        }
        return diff_l2_norm;
    }

    double relative_error(const Vector &expected, const Vector &actual) {
        return relative_error(expected.data(), actual.data());
    }

    double relative_error(const Matrix &expected, const Matrix &actual) {
        return relative_error(expected.data(), actual.data());
    }

    // true if x is a power of 2, false otherwise.
    bool is_pow2(int x) {
        if (x < 1) {
            return false;
        } else if (x == 1) {  // NOLINT(readability-else-after-return)
            return true;
        }
        // x > 1 and not 0 mod 2 => not a power of 2
        else if (x % 2 == 1) {
            return false;
        } else {
            return is_pow2(x >> 1);
        }
    }

    int poly_degree_to_max_mod_bits(int poly_modulus_degree) {
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
                LOG(ERROR) << "poly_modulus_degree " << poly_modulus_degree << " not supported";
                throw invalid_argument("An error occurred. See the log for details.");
        }
    }

    int modulus_to_poly_degree(int mod_bits) {
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
        if (mod_bits <= 27) {
            return 1024;
            // NOLINTNEXTLINE(readability-else-after-return)
        } else if (mod_bits <= 54) {
            return 2048;
        } else if (mod_bits <= 109) {
            return 4096;
        } else if (mod_bits <= 218) {
            return 8192;
        } else if (mod_bits <= 438) {
            return 16384;
        } else if (mod_bits <= 881) {
            return 32768;
        } else if (mod_bits <= 1761) {
            return 65536;
        }
        // SEAL will throw an exception when poly degree is 131072 or larger
        // (which corresponds to the 262144th cyclotomic ring)
        // else if(mod_bits <= 3524) { return 131072; }
        // else if(mod_bits <= 7050) { return 262144; }
        else {
            LOG(ERROR) << "This computation is too big to handle right now: cannot determine a valid ring size for a "
                       << mod_bits << "-bit modulus";
            throw invalid_argument("An error occurred. See the log for details.");
        }
    }

    double l_inf_norm(const vector<double> &x) {
        return norm_inf(Vector(x));
    }

    uintmax_t stream_size(iostream &s) {
        streampos original_pos = s.tellp();
        s.seekp(0, ios::end);
        uintmax_t size = s.tellp();
        s.seekp(original_pos);
        return size;
    }

    void decryption_warning(int level) {
        if (level != 0) {
            LOG(WARNING) << "Decrypting a ciphertext at level " << level
                         << "; consider starting with a smaller modulus"
                         << " to improve performance.";
        }
    }

}  // namespace hit
