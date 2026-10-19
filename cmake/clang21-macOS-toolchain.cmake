# CMake Toolchain file for Clang 21 on macOS (Homebrew LLVM), both architectures.
# This file configures the build to use the Clang 21 compiler and link against libc++.
# Requires CMake >= 4.3 (see cmake_minimum_required in the top-level CMakeLists.txt).
#
# One file covers Apple Silicon and Intel: Homebrew's prefix is fixed per
# architecture (/opt/homebrew on Apple Silicon, /usr/local on Intel), so the
# correct LLVM 21 installation is selected by checking which one exists.
# Detecting by existence rather than `uname -m` also does the right thing
# under Rosetta 2, and stays cheap for CMake's repeated toolchain re-reads.
# Intel is untested as of 1.0.0 (see cmake/PlatformDetection.cmake).

# The experimental `import std` gate UUID and CMAKE_CXX_MODULE_STD are set in
# the top-level CMakeLists.txt (before project()), not here.

if(EXISTS "/opt/homebrew/opt/llvm@21")
    set(LLVM21_PREFIX "/opt/homebrew/opt/llvm@21")   # Apple Silicon Homebrew
elseif(EXISTS "/usr/local/opt/llvm@21")
    set(LLVM21_PREFIX "/usr/local/opt/llvm@21")      # Intel Homebrew (untested)
else()
    message(FATAL_ERROR "Homebrew LLVM 21 not found. Install it with: brew install llvm@21")
endif()

# Point to the root of the installation.
# This helps CMake's `find_*` commands locate the correct packages automatically.
set(CMAKE_PREFIX_PATH "${LLVM21_PREFIX}" CACHE PATH "Prefix path for LLVM 21 toolchain")

# Specify the Clang 21 compiler paths from the Homebrew LLVM 21 installation.
set(CMAKE_C_COMPILER "${LLVM21_PREFIX}/bin/clang")
set(CMAKE_CXX_COMPILER "${LLVM21_PREFIX}/bin/clang++")

# Point CMake directly at libc++'s std-module manifest (CMake >= 4.2) instead
# of injecting -resource-dir into compiler identification.
set(CMAKE_CXX_STDLIB_MODULES_JSON "${LLVM21_PREFIX}/lib/c++/libc++.modules.json")

# Set the required compiler flags.
# This tells Clang to use its own standard library and where to find its headers.
set(CMAKE_CXX_FLAGS_INIT "-stdlib=libc++ -I${LLVM21_PREFIX}/include" CACHE STRING "Initial C++ flags")

# Set the required linker flags.
# This tells the linker where to find libraries and to link libunwind.
# NOTE: lib/unwind is new in 21 -- libunwind moved out of lib/.
set(CMAKE_EXE_LINKER_FLAGS_INIT "-L${LLVM21_PREFIX}/lib -L${LLVM21_PREFIX}/lib/c++ -L${LLVM21_PREFIX}/lib/unwind -lunwind" CACHE STRING "Initial linker flags for executables")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-L${LLVM21_PREFIX}/lib -L${LLVM21_PREFIX}/lib/c++ -L${LLVM21_PREFIX}/lib/unwind -lunwind" CACHE STRING "Initial linker flags for shared libraries")

# clang-scan-deps 21 does not load clang's default config files, which on
# Homebrew LLVM 21 are the sole source of -isysroot. Pin the SDK explicitly, to
# the same versioned Command Line Tools SDK those config files use. Do not use
# `xcrun --show-sdk-path` or the unversioned MacOSX.sdk: both now resolve to
# SDK 27, whose math.h breaks LLVM 21's libc++ <cfloat> in C++20 and later
# (e.g. DBL_MAX_10_EXP undeclared). Revisit when the toolchain moves to LLVM 22+.
set(MACOS_SDK "/Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk")
if(NOT EXISTS "${MACOS_SDK}")
    message(FATAL_ERROR "macOS SDK 26 not found at ${MACOS_SDK}. Homebrew LLVM 21 requires the macOS 26 SDK from the Command Line Tools.")
endif()
set(CMAKE_OSX_SYSROOT "${MACOS_SDK}" CACHE PATH "macOS SDK" FORCE)

# End of clang21-macOS-toolchain.cmake
