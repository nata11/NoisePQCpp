cmake_minimum_required(VERSION 4.0)
project(NoisePQC++ VERSION 0.9.0 LANGUAGES CXX)

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

