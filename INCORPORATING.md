# Incorporating HIT into a CMake project

## Including HIT Source
The easiest way to consume HIT with your project's build system is to include the HIT source directly in your repository (say in `third-party/aws-hit`). Then in your project's CMakeLists.txt, just include:

```
# Add 'third-party/hit/src', which defines 'aws-hit' target.
add_subdirectory(third-party/aws-hit)

# Define your project target.
add_executable(my_homom_app main.cpp)

# Link the project target against aws-hit.
target_link_libraries(my_homom_app aws-hit)
```

## Using HIT as a Dependency without Source
A more complex way to include HIT in your CMake project is to have CMake download the HIT source from Github. This avoids the need to include the HIT source code directly in your project.

### 1. Under `third-party/hit` directory, create a file `CMakeLists.txt`, which will be used to download HIT GitHub code.
```cmake
cmake_minimum_required(VERSION 3.12)

project(AWS_HIT_DOWNLOAD 0.1.2) # Change the version number "0.1.2" to whichever version you want
set(AWS_HIT_BACKEND "lattigo") # This value must be either "lattigo" or "seal"

include(ExternalProject)
ExternalProject_Add(EP_AWS_HIT
    SOURCE_DIR           ${CMAKE_CURRENT_LIST_DIR}/src
    BINARY_DIR           ${CMAKE_CURRENT_LIST_DIR}/build
    GIT_REPOSITORY       https://github.com/awslabs/homomorphic-implementors-toolkit.git
    GIT_TAG              v${PROJECT_VERSION}-${AWS_HIT_BACKEND}
    GIT_CONFIG           advice.detachedHead=false
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
download_external_project(external/hit)
# Add 'external/hit/src', which defines 'aws-hit' target.
add_subdirectory(external/hit/src)
# Define your project target.
add_executable(my_homom_app main.cpp)
# Link the project target against aws-hit as needed.
target_link_libraries(my_homom_app aws-hit)
```

### 3. HIT header files are now available in `main.cpp` of your project.

```c++
#include "hit/hit.h"
#include <glog/logging.h>

using namespace hit;

int main(int, char **argv) {
    DepthFinder *inst = DepthFinder();
    // Ready to use `inst` to compute the depth of a circuit.
}
```
