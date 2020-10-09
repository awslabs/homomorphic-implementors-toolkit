# Homomorphic Implementor's Toolkit

HIT provides tools to simplify the process of designing homomorphic circuits for the CKKS homomorphic encryption scheme. HIT is based on the [Microsoft SEAL](https://github.com/microsoft/SEAL) homomorphic encryption library.

#### Builds Status:
* Ubuntu 18.04 GCC 9 ![Build Status](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiS0plc1RnWDFBLzBuSm1DV0J3S2RxenF5ek9XUkYwNWxodkVqSkMrbEdwUnpXQlpOME5BakN6djRnblJlWm92K3NORXZZV1dPOGdVRVIzNVB1UUVLWmtVPSIsIml2UGFyYW1ldGVyU3BlYyI6IkM2a0VPc0xsRmRHQ0hBVDIiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master)
* Ubuntu 18.04 Clang 10 ![Build Status](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiTzVreHl2cjN4WENKcmNkMlh1UVpzK1VzYmQwYWJ4OFVXMlZaWHMvYWtHazkrTlA5VzlPZGljSTRPR1JNOS9McERCU1NxY2twVDlBUXEyWWdEWmM4WmRBPSIsIml2UGFyYW1ldGVyU3BlYyI6ImIrTG1JdFF5RytlOVh0MkkiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master)

## Introduction

Homomorphic encryption is a special type of encryption scheme which enables computation of arbitrary functions on encrypted data. To evaluate a function `f`, a developer must create a circuit `F` using only the "native" operation supported by the underlying homomorphic encryption scheme.

When implementing a homomorphic function, the Using existing tools, including SEAL, developers write a function which takes encrypted inputs and produces encrypted outputs. While the functionality provided by core HE implementations is sufficient for this task, this code can _only_ be evaluated on encrypted inputs, making debugging difficult.


HIT is a library for simplifying the development of homomorphic functions. Specifically, it provides
* parameter evaluators, which help calculate good values for crypto system parameters, and verify the correctness of implementations.
* homomorphic evaluator, which is built on the Microsoft SEAL library.
* high level linear algebra computation APIs.

[examples](/examples) include detailed comments and code to tell how to use above features.

## Get Started

Below files in this directory might be helpful:
  * [INCORPORATING.md](/INCORPORATING.md): how to incorporate HIT into a CMake project.
  * [BUILDING.md](/BUILDING.md): how to build HIT with CMake.

## Contributing change

[CONTRIBUTING.md](/CONTRIBUTING.md) has details on how to contribute to this project.
