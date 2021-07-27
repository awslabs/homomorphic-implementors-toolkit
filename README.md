# Homomorphic Implementor's Toolkit

HIT provides tools to simplify the process of designing homomorphic circuits for the CKKS homomorphic encryption scheme. This library is intended to further research in homomorphic encryption. Users must be aware of the security issues surrounding the deployment of CKKS homomorphic encryption; see SECURITY.md for details. This branch of the HIT repository uses the [Lattigo](https://github.com/ldsec/lattigo) homomorphic encryption library as a backend, and supports CKKS bootstrapping.

#### Build Status:
* Ubuntu 18.04 GCC 9 ![Build Status](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiQ3Npc1hJQi9iQ0x0aHVlVW1EdERJZ1g0ZENhazl2b2ptMUkwTkgyS1pSRkVQNytDYUdPam9MS0VBeDc0ODlUNXRmaEVLaVZyaERna243d293aXRGRFVvPSIsIml2UGFyYW1ldGVyU3BlYyI6IkRqcnk0N08yQjRaTk8vS3IiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=main)
* Ubuntu 18.04 Clang 10 ![Build Status](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiKzFoQXZYbmppZW84SUFYWUhVYkVVSVZEaEtFYkVXL1J2MWtKUlBFTTJKY0d1d2MxSjBRNWtjRS91NE1PYjJ4QmIvck53aUQrZmMza2NBOTlTNW1ubTBBPSIsIml2UGFyYW1ldGVyU3BlYyI6IllTYS9GOGFqTS9FdmRmV3QiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=main)

Table of Contents
=================

   * [Homomorphic Implementor's Toolkit](#homomorphic-implementors-toolkit)
      * [Introduction](#introduction)
         * [Evaluators](#evaluators)
         * [Linear Algebra API](#linear-algebra-api)
         * [CKKS Parameters](#ckks-parameters)
         * [Deploying a Homomorphic Function](#deploying-a-homomorphic-function)
      * [Building HIT](#building-hit)
         * [Prerequisites](#prerequisites)
            * [Tools](#tools)
            * [Libraries](#libraries)
            * [Ubuntu 18.04](#ubuntu-1804)
         * [Building HIT with CMake](#building-hit-with-cmake)
         * [Integrating HIT](#integrating-hit)
         * [Using HIT](#using-hit)
         * [Examples](#examples)
      * [Contributing Changes](#contributing-change)

## Introduction

Homomorphic encryption is a special type of encryption scheme which enables computation of arbitrary functions on encrypted data. To evaluate a function `f`, a developer must implement `f` as a circuit `F` using only the "native" operation supported by the underlying homomorphic encryption scheme. Libraries which implement homomorphic encryption provide an API for these native operations which can be used to create homomorphic circuits. Creating a circuit also requires tracking ciphertext metadata throughout the computation such as ciphertext level, degree, and scale. This becomes infeasible for all but the smallest circuits.

### Evaluators
HIT simplifies this process by providing an abstract homomorphic evaluation API that allows a circuit to be written once, but evaluated in many different ways, including:
- Homomorphic evalaution: This is the basic evaluation strategy provided by a generic homomorphic encryption library. This branch of HIT uses the [Lattigo](https://github.com/ldsec/lattigo) homomorphic encryption library (via a [C++ wrapper](https://github.com/awslabs/aws-cppwrapper-lattigo)) to evaluate circuits on encrypted inputs.
- Count the number of operations in the circuit. Homomorphic operations are expensive to compute, and it is useful to know how changes to the circuit affect the number of operations being performed.
- Compute the multiplicative depth of a circuit. The multiplicative depth of a homomorphic circuit is the maximum number of multiplications along any path through the circuit. This circuit property is _the_ most important factor in the efficiency of circuit evaluation. Computing the depth of a circuit by hand requires tedious tracking of ciphertext metadata; HIT provides a programmatic way to compute circuit depth. Knowing the depth of a circuit is also important when selecting cryptosystem paramters for homomorphic evaluation.
- Estimate the CKKS scale parameter. CKKS homomorphic encryption has a _scale parameter_, which controls the precision of the homomorphic computation. It can be difficult to know what value to use for the scale parameter. By running the circuit on representative input, HIT helps developers choose an appropriate value for this parameter.
- Evaluate the circuit on plaintexts. Evaluating a homomorphic circuit can give unexpected results for several reasons. One of the most basic is that the circuit does not compute the desired function (e.g., a constant is incorrect, or it uses a multiplication instead of an addition). We can verify the correctness of the circuit by evaluating the circuit on plaintexts: if we get the expected result, we can eliminate the basic circuit as a souce of error.
- Evaluate the circuit on plaintext and ciphertext input simultaneously: If the circuit gives the expected result on plaintexts but fails on encrypted inputs, the problem is related to details of homomorphic encryption. For example:
  - CKKS ciphertexts have a limited capacity. If a plaintext value exceeds this capacity, the ciphertext overflows, and the plaintext is lost.
  - CKKS is an approximate homomorphic encryption scheme. It's possible that the error incurred during CKKS encryption and homomorphic operations is too great.

  By running the plaintext and ciphertext computations in parallel, HIT can compare the results after each step and help the developer understand where the computation is failing.
- Track explicit rotations required by the circuit. This is useful in order to obtain a minimal set of rotation keys required by the circuit when generating keys for homomorphic evaluation. Note that bootstrapping implicitly uses rotation/Galois keys, but this evaluator only tracks explicit rotations (i.e., calls to `rotateLeft` or `rotateRight`). Bootstrapping keys are automatically generated when parameters support bootstrapping and additional Galois keys are generated as needed for bootstrapping.

### Linear Algebra API
Developing a homomorphic circuit requires a scheme to _encode_ function inputs as CKKS ciphertexts. Depending on the complexity of the encoding scheme, a developer may end up writing many "assembly" instructions: higher level instructions composed of native instructions that operate on encoded plaintexts. HIT provides this type of API for linear algebra operations based on the framework described in [this paper](https://eprint.iacr.org/2020/1483). Using this API, it is easy for a developer to create a circuit for a function based on linear algebra. It handles encoding of linear algebra objects, and provides high-level "assembly" instructions for linear algebra operations.

### CKKS Parameters
Homomorphic encryption schemes require many parameters which interact in complex ways to affect security. HIT helps developers by exposing APIs that are oriented towards the computation. First, HIT helps developers get some basic parameter requirements based on the circuit, such as the circuit depth and estimated scale. Based on these circuit parameters, HIT selects HE parameters which meet the desired computation requirements and also provide adequate security by default. When using the homomorphic evaluator, HIT targets 128-bit security by default.

### Deploying a Homomorphic Function
A homomorphic function is typcially deployed in a client/server model:

```
   Client                                       Server
   ------                                       ------

Generate Keys

Encode and Encrypt Data

Transmit encrypted data,
parameters, and public     ---------->
keys to server
                                         Evaluate the target circuit
                                         on the encrypted inputs

                           <----------   Transmit circuit outputs (ciphertexts)
                                         back to the client
Use the private key to
decrypt the circuit
outputs
```

HIT provides serialization and deserialization of CKKS parameters and encrypted objects to facilitate the deployment of homomorphic functions. See `examples/example_5_serialization.cpp` for a detailed example of how HIT can be used to as part of the client and server in this model.

Homomorphic encryption schemes satisfy semantic security, but _not_ CCA security. In particular, this means that ciphertexts serialized by HIT are unauthenticated. Thus in the model above, the channel between the client and server _MUST_ be authenticated, though additional encryption is not necessary.

An additional consideration is that a client who wishes for a server to evaluate a particular function `f` cannot be sure that the server actually performed the correct computation on the data. The client must trust that the server evaluates a correct circuit for the target function.

## Building HIT

### Prerequisites

#### Tools
HIT requires CMake 3.12 or later and either GCC-9 or Clang-10. We recommend the `ninja` build system.

#### Libraries
HIT with Lattigo requires [Boost](https://github.com/boostorg/boost)'s thread library (Ubuntu: libboost-thread-dev) to be installed on your system.

We recommend installing the [Google Protocol Buffers library](https://github.com/protocolbuffers/protobuf) and `protoc` compiler (Ubuntu: libprotobuf-dev and protobuf-compiler) and [Boost](https://github.com/boostorg/boost)'s math library (Ubuntu: libboost-math-dev). If these dependencies are not found on the system, HIT's build system will download and build its own versions, which takes additional time.

#### Ubuntu 18.04
The HIT [docker scripts](/scripts/codebuild/docker) include a complete script to install all the necessary dependencies in Ubuntu 18.04.

### Building HIT with CMake
```!bash
git clone https://github.com/awslabs/homomorphic-implementors-toolkit.git
cd homomorphic-implementors-toolkit
cmake . -Bbuild -GNinja
ninja -Cbuild
```

By default, only the HIT library is built. To build the examples, use `cmake . -Bbuild -GNinja -DHIT_BUILD_EXAMPLES=ON`; see [BUILDING](/BUILDING.md) for more details.

### Integrating HIT
HIT is easy to integrate as a dependency into a homomorphic application. We recommend using CMake's `add_subdirectory` command to add the HIT source directory to the build. To link against HIT, use the target `aws-hit`.

See [INCORPORATING](/INCORPORATING.md) for more details.

### Using HIT
Most of the HIT headers are provided by including "hit/hit.h".

When running code that uses HIT, you can control the output with the Google Log (GLog) library.
In HIT, logging is primarily controlled by the VLOG level:
 - To see only critical security warnings and errors, define the environment variable `GLOG_v=0` or use the command line argument `--v=0`
 - To see evaluation output, define the environment variable `GLOG_v=1` or use the command line argument `--v=1`
 - To see verbose evaluation output, define the environment variable `GLOG_v=2` or use the command line argument `--v=2`

See the GLog documentation for more information: https://hpc.nih.gov/development/glog.html

As an example, we will set the log level to 2 to show most output:
```
export GLOG_v=2
export GLOG_log_dir="/tmp/hit_log"
ninja run_hit_example
```

### Examples
We recommend reading through the detailed [examples](/examples) which demonstrate how to use the features described above. For those unfamiliar with homomorphic encryption topics, we also recommend reading through the [Microsoft SEAL examples](https://github.com/microsoft/SEAL/tree/master/native/examples).

## Citing HIT
Please use the following BibTeX entry to cite HIT:
```
@misc{aws-hit,
    title = {Homomorphic Implementor's Toolkit},
    howpublished = {\url{https://github.com/awslabs/homomorphic-implementors-toolkit}},
    month = dec,
    year = 2020,
    note = {Amazon Web Services},
    key = {HIT}
}
```

## Contributing Changes
[CONTRIBUTING.md](/CONTRIBUTING.md) has details on how to contribute to this project.
