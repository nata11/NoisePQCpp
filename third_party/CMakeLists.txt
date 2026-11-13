# ================================
# Third-Party Dependencies
# ================================

# ================================
# Botan Cryptographic Library
# ================================
# Local platform-specific builds
add_subdirectory(botan)

# ================================
# Catch2 Testing Framework
# ================================
# Downloaded via FetchContent and built with project's toolchain
# to ensure ABI compatibility (the project's toolchain: Clang 21 with libc++,
# GCC 15 with libstdc++, or MSVC)

include(FetchContent)

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.16.1
  GIT_SHALLOW    TRUE
  GIT_PROGRESS   TRUE
)

# Configure Catch2 options (disable unnecessary features)
set(CATCH_INSTALL_DOCS OFF CACHE BOOL "Install Catch2 documentation" FORCE)
set(CATCH_INSTALL_EXTRAS OFF CACHE BOOL "Install Catch2 extras" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "Build Catch2 tests" FORCE)
set(CATCH_BUILD_TESTING OFF CACHE BOOL "Build Catch2 SelfTest project" FORCE)

# Download and make Catch2 available
# This builds Catch2 with the project's toolchain (Clang 21 with libc++, GCC 15 with libstdc++, or MSVC)
# FetchContent_MakeAvailable only downloads once per cache, stored in .cmake-cache/
FetchContent_MakeAvailable(Catch2)

# Make Catch.cmake test discovery module available to parent scope
list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" PARENT_SCOPE)

# ================================
# ASIO C++ Library
# ================================
FetchContent_Declare(
        asio
        GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
        GIT_TAG asio-1-39-0
        GIT_SHALLOW    TRUE
        GIT_PROGRESS   TRUE
)

FetchContent_MakeAvailable(asio)

# Define ASIO include directory
set(ASIO_INCLUDE_DIRS ${asio_SOURCE_DIR}/include)

# Create ASIO static library
# This compiles ASIO once and links to both executables
add_library(asio_static STATIC ${asio_SOURCE_DIR}/src/asio.cpp)
target_include_directories(asio_static PUBLIC ${ASIO_INCLUDE_DIRS})
target_compile_definitions(asio_static PUBLIC ASIO_STANDALONE)
target_compile_definitions(asio_static PRIVATE ASIO_SEPARATE_COMPILATION)

# ================================
# Google Benchmark Library
# ================================
# Only fetch if NOISEPQC_BUILD_BENCHMARKS is ON (set in BuildConfig.cmake)
# For multi-config generators: fetch if benchmarks enabled
# For single-config generators: only fetch in Release if benchmarks enabled
if(NOISEPQC_BUILD_BENCHMARKS)
    if(CMAKE_CONFIGURATION_TYPES OR CMAKE_BUILD_TYPE STREQUAL "Release")
        FetchContent_Declare(
            benchmark
            GIT_REPOSITORY https://github.com/google/benchmark.git
            GIT_TAG        v1.10.0
            GIT_SHALLOW    TRUE
            GIT_PROGRESS   TRUE
            # Keep the library out of "all": it is built only when a bench
            # target needs it, so configs that skip benchmarks skip it too
            EXCLUDE_FROM_ALL
        )

        # Configure Google Benchmark options
        set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Disable benchmark tests" FORCE)
        set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "Disable benchmark install" FORCE)
        set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "Disable GTest for benchmark" FORCE)

        FetchContent_MakeAvailable(benchmark)
    endif()
endif()
