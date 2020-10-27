# Building HIT with CMake

The [README](/README.md) contains basic building instructions. This document contains detailed instructions.

## Recommended Prerequisites for Ubuntu 18.04
```!bash
set -ex
apt-get update
apt-get -y --no-install-recommends install git ninja-build build-essential software-properties-common curl libboost-math-dev protobuf-compiler libprotobuf-dev ca-certificates clang clang-10 clang-tidy-10
cd /tmp
curl -LO https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-Linux-x86_64.tar.gz
tar xzf cmake-${CMAKE_VERSION}-Linux-x86_64.tar.gz -C /usr --strip-components 1
add-apt-repository ppa:ubuntu-toolchain-r/test
apt-get update
apt-get -y --no-install-recommends install gcc-9 g++-9
update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 90 --slave /usr/bin/g++ g++ /usr/bin/g++-9 --slave /usr/bin/gcov gcov /usr/bin/gcov-9
add-apt-repository --remove ppa:ubuntu-toolchain-r/test
apt-get update
update-alternatives --install /usr/bin/clang clang /usr/bin/clang-10 90 --slave /usr/bin/clang++ clang++ /usr/bin/clang-cpp-10 --slave /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-10
```

### Download HIT, Build and Test
```!bash
# Download HIT
git clone https://github.com/awslabs/homomorphic-implementors-toolkit.git
cd homomorphic-implementors-toolkit

# Run build command. See [README](/README.md) for a comlete list of CMake flags.
cmake . -Bbuild -GNinja -DHIT_BUILD_TESTS=ON -DHIT_BUILD_EXAMPLES=ON
ninja -Cbuild

# Run HIT unit tests
# Log messages to stderr instead of logfiles.
export GLOG_logtostderr=true
# For testing, only show warnings and errors
export GLOG_v=0
ninja run_hit_tests

# Run HIT example
# Show most HIT output
export GLOG_v=1
# Log to a log file instead of stderr
export GLOG_logtostderr=false
# Set Logging directory.
export GLOG_log_dir="/tmp/hit_log"
ninja run_hit_examples
```
