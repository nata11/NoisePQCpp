# CMake Toolchain file for Clang 21 on Linux. Check to make sure paths are correct for your installation.
# This file configures the build to use the Clang 21 compiler and link against libc++.
#
# This single file covers all supported Linux hosts — x86_64, arm64, and
# Raspberry Pi 5 — as long as Clang 21 and the LLVM 21 packages (clang-21,
# libc++-21-dev, libc++abi-21-dev) were installed from the standard package
# repo sources on Ubuntu 26 or Raspberry Pi Debian Trixie (trixie-backports).
# All of these lay out the toolchain under the same paths used below.

# Specify the Clang 21 compiler paths. Below paths assume LLVM 21 is installed
# via the distro packages or the official LLVM apt repository.
set(CMAKE_C_COMPILER /usr/bin/clang-21)
set(CMAKE_CXX_COMPILER /usr/bin/clang++-21)

# Point CMake directly at libc++'s std-module manifest (CMake >= 4.2) instead
# of injecting -resource-dir into compiler identification.
set(CMAKE_CXX_STDLIB_MODULES_JSON "/usr/lib/llvm-21/lib/libc++.modules.json")

# Set the required compiler flags.
# This tells Clang to use its own standard library and where to find its headers.
set(CMAKE_CXX_FLAGS_INIT "-stdlib=libc++ -I/usr/lib/llvm-21/include" CACHE STRING "Initial C++ flags")

# Set the required linker flags.
# libc++abi must be listed explicitly: on the Ubuntu 26 and Debian Trixie
# packages /usr/lib/llvm-21/lib/libc++.so is a bare symlink (not the usual
# INPUT(libc++.so.1 -lc++abi) linker script), and BFD ld will not resolve
# ABI symbols from a transitive DSO ("DSO missing from command line").
set(CMAKE_EXE_LINKER_FLAGS_INIT "-L/usr/lib/llvm-21/lib -Wl,-rpath,/usr/lib/llvm-21/lib -lc++ -lc++abi" CACHE STRING "Initial linker flags for executables")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-L/usr/lib/llvm-21/lib -Wl,-rpath,/usr/lib/llvm-21/lib -lc++ -lc++abi" CACHE STRING "Initial linker flags for shared libraries")

# End of clang21-linux-toolchain.cmake
