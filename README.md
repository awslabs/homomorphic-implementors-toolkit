## Homomorphic Implementor's Toolkit

HIT is a library for simplifying the development of homomorphic functions. It allows you to write code _once_ and evaluate it in many different ways. We provide evaluators to help calcuate good values for cryptosystem parameters, verify the correctness of implementations, and evaluate homomorphically using the Microsoft SEAL library.

## License

This library is licensed under the Apache 2.0 License.

## Building
Status:
* Ubuntu 18.04 GCC 9 is
  ![Build Status](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiS0plc1RnWDFBLzBuSm1DV0J3S2RxenF5ek9XUkYwNWxodkVqSkMrbEdwUnpXQlpOME5BakN6djRnblJlWm92K3NORXZZV1dPOGdVRVIzNVB1UUVLWmtVPSIsIml2UGFyYW1ldGVyU3BlYyI6IkM2a0VPc0xsRmRHQ0hBVDIiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master)
* Ubuntu 18.04 Clang 10 is
  ![Build Status](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiTzVreHl2cjN4WENKcmNkMlh1UVpzK1VzYmQwYWJ4OFVXMlZaWHMvYWtHazkrTlA5VzlPZGljSTRPR1JNOS9McERCU1NxY2twVDlBUXEyWWdEWmM4WmRBPSIsIml2UGFyYW1ldGVyU3BlYyI6ImIrTG1JdFF5RytlOVh0MkkiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master)

### CMake Flags
 - HIT_BUILD_TESTS (default OFF): Build the unit tests. See TESTING below for more information.
 - HIT_BUILD_EXAMPLES (default OFF): Build the HIT example.
 - HIT_RUN_CLANG_TIDY (default OFF): Run clang-tidy on the hand-written source code (but not code generated by protobufs), and make the build fail if clang-tidy emits any warnings.
 - HIT_RUN_CLANG_FORMAT (default OFF): Run clang-format on the source code, and apply changes in-place.

### Ubuntu

Dependencies for this library include Google's protobuf compiler, boost, Microsoft SEAL, and GoogleTest.
We also recommend using ninja for the build system.

For convenience, the SEAL and googletest dependencies are included as submodules.
Note that SEAL requires CMAKE 3.10 or later.

The following instructions should work for a clean install of Ubuntu 18.04.
```!bash
sudo apt update
sudo apt install build-essential zlib1g-dev libboost-all-dev -y
wget https://github.com/Kitware/CMake/releases/download/v3.16.0/cmake-3.16.0-Linux-x86_64.sh
chmod +x cmake-3.16.0-Linux-x86_64.sh
./cmake-3.16.0-Linux-x86_64.sh
export PATH=~/cmake-3.16.0-Linux-x86_64/bin:$PATH

TODO: while this repo is private, you must use SSH. When we make the repo public, switch this to HTTPS.
git clone https://github.com/awslabs/homomorphic-implementors-toolkit.git
cd homomorphic-implementors-toolkit
cmake . -Bbuild -GNinja
ninja -C build
```

### Testing
To build the unit tests, run CMake with `-DHIT_BUILD_TESTS=ON`.
After building, you can execute run the target `run_hit_tests` to run the tests, e.g., `ninja run_hit_tests`.
