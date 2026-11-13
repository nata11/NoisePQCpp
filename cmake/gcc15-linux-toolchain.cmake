# CMake Toolchain file for GCC 15 on Linux. Check to make sure paths are correct for your installation.
# This file configures the build to use the GCC 15 compiler and link against libstdc++.
# The C++ runtime (libstdc++) is linked statically into executables, so they
# need only glibc and libgcc_s at run time.
#
# Below paths assume GCC 15 is installed via the native distro packages
# (gcc-15, g++-15, libstdc++-15-dev) on Ubuntu 26. The distro compiler
# finds its own headers and standard library, so no extra include, library,
# or rpath flags are needed.
#
# `import std` needs no settings here: the experimental CMake gate lives in
# the top-level CMakeLists.txt, and libstdc++'s std-module manifest
# (libstdc++.modules.json) sits in GCC's default install directory where
# CMake discovers it automatically via the compiler.

# Specify the C and C++ compilers from the distro GCC 15 packages.
set(CMAKE_C_COMPILER /usr/bin/gcc-15)
set(CMAKE_CXX_COMPILER /usr/bin/g++-15)

# LTO static archives hold GIMPLE bytecode, which needs GCC's plugin-aware
# archiver wrappers. On Ubuntu 26 the unsuffixed /usr/bin/gcc-ar and
# /usr/bin/gcc-ranlib are symlinks to these (GCC 15 is the default GCC); the
# suffixed names stay correct if the distro's default GCC changes.
set(CMAKE_AR /usr/bin/gcc-ar-15 CACHE FILEPATH "")
set(CMAKE_RANLIB /usr/bin/gcc-ranlib-15 CACHE FILEPATH "")

# ISA baseline (project-wide).
#   x86_64:  portable across heterogeneous EC2 hosts (AVX2/BMI2/FMA). Botan's
#            runtime CPUID dispatch still engages AVX-512/VAES/SHA-NI on
#            capable hardware. Never use host-native tuning here.
#   aarch64: BCM2712 / Cortex-A76 (Raspberry Pi 5), which has the ARMv8
#            crypto extensions (AES, PMULL, SHA1, SHA2). GCC's
#            -mcpu=cortex-a76 leaves them off at compile time (no +crypto),
#            and the bundled Botan does not detect them at run time on Linux
#            arm64 (see the known limitation in docs/BuildGuide.md). Also a
#            portable baseline for Ubuntu 26 arm64 hosts, newer cores included.
# CMAKE_HOST_SYSTEM_PROCESSOR, not CMAKE_SYSTEM_PROCESSOR: the latter is not
# yet set when a toolchain file is read.
# The value is a cache default: -DNOISE_BOTAN_ARCH_FLAGS=<flags> overrides it
# (e.g. for an older CPU). Like any CMake cache value, it then persists in that
# build dir until changed.
if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(NOISE_BOTAN_ARCH_FLAGS "-mcpu=cortex-a76" CACHE STRING "ISA baseline flags (project-wide)")
else()
    set(NOISE_BOTAN_ARCH_FLAGS "-march=x86-64-v3" CACHE STRING "ISA baseline flags (project-wide)")
endif()

# Link libstdc++ statically into executables; libgcc_s stays dynamic.
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static-libstdc++" CACHE STRING "Initial linker flags for executables")

# End of gcc15-linux-toolchain.cmake
