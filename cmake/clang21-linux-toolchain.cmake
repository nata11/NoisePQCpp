# CMake Toolchain file for Clang 21 on Linux. Check to make sure paths are correct for your installation.
# This file configures the build to use the Clang 21 compiler and link against libc++.
# The C++ runtime (libc++ and libc++abi) is linked statically into executables,
# so they need only glibc and libgcc_s at run time.
#
# This single file covers all supported Linux hosts — x86_64, arm64, and
# Raspberry Pi 5 — as long as Clang 21 and the LLVM 21 packages (clang-21,
# clang-tools-21, llvm-21, libc++-21-dev, libc++abi-21-dev) were installed
# from the standard package repo sources on Ubuntu 26 or Raspberry Pi Debian
# Trixie (trixie-backports).
# All of these lay out the toolchain under the same paths used below.

# Specify the Clang 21 compiler paths. Below paths assume LLVM 21 is installed
# via the distro packages or the official LLVM apt repository.
set(CMAKE_C_COMPILER /usr/bin/clang-21)
set(CMAKE_CXX_COMPILER /usr/bin/clang++-21)

# LTO static archives hold LLVM bitcode, which needs LLVM's own archiver.
# The packages also install /usr/bin/llvm-ar-21 and /usr/bin/llvm-ranlib-21,
# which resolve to the same binaries.
set(CMAKE_AR /usr/lib/llvm-21/bin/llvm-ar CACHE FILEPATH "")
set(CMAKE_RANLIB /usr/lib/llvm-21/bin/llvm-ranlib CACHE FILEPATH "")

# ISA baseline (project-wide).
#   x86_64:  portable across heterogeneous EC2 hosts (AVX2/BMI2/FMA). Botan's
#            runtime CPUID dispatch still engages AVX-512/VAES/SHA-NI on
#            capable hardware. Never use host-native tuning here.
#   aarch64: BCM2712 / Cortex-A76 (Raspberry Pi 5), which has the ARMv8
#            crypto extensions (AES, PMULL, SHA1, SHA2); with Clang,
#            -mcpu=cortex-a76 enables them at compile time (the bundled
#            Botan still takes its portable code paths on Linux arm64; see
#            the known limitation in docs/BuildGuide.md). Also a portable
#            baseline for Ubuntu 26 arm64 hosts, newer cores included.
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

# Point CMake directly at libc++'s std-module manifest (CMake >= 4.2) instead
# of injecting -resource-dir into compiler identification.
set(CMAKE_CXX_STDLIB_MODULES_JSON "/usr/lib/llvm-21/lib/libc++.modules.json")

# Set the required compiler flags.
# This tells Clang to use its own standard library and where to find its headers.
set(CMAKE_CXX_FLAGS_INIT "-stdlib=libc++ -I/usr/lib/llvm-21/include" CACHE STRING "Initial C++ flags")

# Set the required linker flags.
# Executables link the C++ runtime statically: -static-libstdc++ makes the
# driver add -Bstatic -lc++ -Bdynamic after the objects. On the Ubuntu 26 and
# Debian Trixie packages, libc++.a already contains the libc++abi objects, so
# no separate -lc++abi is needed. -L keeps the LLVM 21 archive first in the
# search path. libgcc_s (the unwinder) stays dynamic.
set(CMAKE_EXE_LINKER_FLAGS_INIT "-L/usr/lib/llvm-21/lib -static-libstdc++" CACHE STRING "Initial linker flags for executables")
# The project builds no shared libraries; this keeps the dynamic runtime for any
# that a user adds. libc++abi must be listed explicitly: on the Ubuntu 26 and
# Debian Trixie packages /usr/lib/llvm-21/lib/libc++.so is a bare symlink (not
# the usual INPUT(libc++.so.1 -lc++abi) linker script), and BFD ld will not
# resolve ABI symbols from a transitive DSO ("DSO missing from command line").
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-L/usr/lib/llvm-21/lib -Wl,-rpath,/usr/lib/llvm-21/lib -lc++ -lc++abi" CACHE STRING "Initial linker flags for shared libraries")

# End of clang21-linux-toolchain.cmake
