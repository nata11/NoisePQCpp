cmake_minimum_required(VERSION 4.3)

# Set experimental flag to enable `import std` support from CMake.
# This must be enabled before C++ language support.
# Below UUID is valid for CMake 4.3.x series. Check documentation for other versions.
set(CMAKE_EXPERIMENTAL_CXX_IMPORT_STD
        # This specific value changes as experimental support evolves. See
        # `Help/dev/experimental.rst` in the CMake source corresponding to
        # your CMake build for the exact value to use.
        "451f2fe2-a8a2-47c3-bc32-94786d8fc91b")

# Tell CMake that we explicitly want `import std`. This will initialize the
# property on all targets declared after this to 1
set(CMAKE_CXX_MODULE_STD 1)

project(NoisePQC++ VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ================================
# Build Configuration (output dirs, debug options, benchmarks)
# ================================
include(cmake/BuildConfig.cmake)

# ================================
# Platform Detection
# ================================
include(cmake/PlatformDetection.cmake)

# ================================
# Third-Party Libraries
# ================================
add_subdirectory(third_party)

# ================================
# NoisePQC++ Module Library
# ================================
add_subdirectory(src)

# ================================
# Examples
# ================================
add_subdirectory(examples)

# ================================
# Testing
# ================================
enable_testing()
include(CTest)
add_subdirectory(tests)

