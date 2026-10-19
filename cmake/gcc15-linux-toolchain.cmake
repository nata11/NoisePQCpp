# CMake Toolchain file for GCC 15 on Linux. Check to make sure paths are correct for your installation.
# This file configures the build to use the GCC 15 compiler and link against libstdc++.
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

# End of gcc15-linux-toolchain.cmake
