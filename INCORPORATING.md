# Incorporating HIT into a CMake project

## CMake Incorporation Steps

### 1. Under `third-party/hit` directory, create a file `CMakeLists.txt`, which will be used to download HIT GitHub code.
```cmake
cmake_minimum_required(VERSION 3.12)

project(AWS_HIT_DOWNLOAD)

message(STATUS "Downloading HIT in ${CMAKE_CURRENT_LIST_DIR}.")

include(ExternalProject)
ExternalProject_Add(EP_AWS_HIT
    TMP_DIR              ${CMAKE_CURRENT_LIST_DIR}/tmp
    STAMP_DIR            ${CMAKE_CURRENT_LIST_DIR}/stamp
    DOWNLOAD_DIR         ""
    SOURCE_DIR           ${CMAKE_CURRENT_LIST_DIR}/src
    BINARY_DIR           ${CMAKE_CURRENT_LIST_DIR}/build
    GIT_REPOSITORY       https://github.com/awslabs/homomorphic-implementors-toolkit.git
    GIT_TAG              master
    GIT_CONFIG           advice.detachedHead=false
    CMAKE_ARGS           -DCMAKE_BUILD_TYPE=Release
    CONFIGURE_COMMAND    ""
    BUILD_COMMAND        ""
    INSTALL_COMMAND      ""
    TEST_COMMAND         ""
)
```

### 2. In `CMakeLists.txt` of your project, link `aws-hit` target.
```cmake
# Define a external project download method.
function(download_external_project project_dir)
    message(STATUS "Downloading ${project_dir}.")
    set(EXTERNAL_PROJECT_CMAKE_CACHE_FILE ${project_dir}/CMakeCache.txt)
    if(EXISTS ${EXTERNAL_PROJECT_CMAKE_CACHE_FILE})
        message(STATUS "Removing old ${EXTERNAL_PROJECT_CMAKE_CACHE_FILE}")
        file(REMOVE ${EXTERNAL_PROJECT_CMAKE_CACHE_FILE})
    endif()
    set(COMMAND_WORK_DIR ${project_dir})
    execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${COMMAND_WORK_DIR})
    if(result)
        message(FATAL_ERROR "Failed to download (${result}).")
    endif()
    execute_process(COMMAND ${CMAKE_COMMAND} --build .
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${COMMAND_WORK_DIR})
    if(result)
        message(FATAL_ERROR "Failed to build (${result}).")
    endif()
endfunction()

# Download AWS HIT.
download_external_project(third-party/hit)
# Add 'third-party/hit/src', which defines 'aws-hit' target.
add_subdirectory(third-party/hit/src)
# Define your project target.
add_executable(example main.cpp)
# Link the project target against aws-hit as needed.
target_link_libraries(example aws-hit)
```

### 3. After link `aws-hit`, HIT header files are ready to be included in the `main.cpp` of your project.

```c++
#include "hit/CKKSInstance.h"
#include "hit/api/evaluator.h"
#include <glog/logging.h>

const int NUM_OF_SLOTS = 4096;
const int MULTI_DEPTH = 1;
const int LOG_SCALE = 30;

int main(int, char **argv) {
    hit::CKKSInstance *ckks_instance = hit::CKKSInstance::get_new_homomorphic_instance(NUM_OF_SLOTS, MULTI_DEPTH, LOG_SCALE);
    // Ready to use CKKInstance to add and multiply ciphertexts.
}
```

**Note**: HIT recommends reading *examples/evaluator_example.cpp*, which provides detailed explanation on how to use HIT evaluators.
