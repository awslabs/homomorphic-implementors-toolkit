## Homomorphic Implementor's Toolkit

HIT is a library for simplifying the development of homomorphic functions. It allows you to write code _once_ and evaluate it in many different ways. We provide evaluators to help calcuate good values for cryptosystem parameters, verify the correctness of implementations, and evaluate homomorphically using the Microsoft SEAL library.

## License

This library is licensed under the Apache 2.0 License.

## Building

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
