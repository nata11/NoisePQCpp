# CMake Toolchain file for Clang 18 on Linux. Check to make sure paths are correct for your installation.
# This file configures the build to use the Clang 18 compiler and link against libc++.

# Set experimental flag to enable `import std` support from CMake.
# This must be enabled before C++ language support.
# Below UUID is valid for CMake 4.0.4 series. Check documentation for other versions.
set(CMAKE_EXPERIMENTAL_CXX_IMPORT_STD
        # This specific value changes as experimental support evolves. See
        # `Help/dev/experimental.rst` in the CMake source corresponding to
        # your CMake build for the exact value to use.
        "d0edc3af-4c50-42ea-a356-e2862fe7a444")

# Tell CMake that we explicitly want `import std`. This will initialize the
# property on all targets declared after this to 1
set(CMAKE_CXX_MODULE_STD 1)

# Specify the Clang 18 compiler paths. Below paths assume LLVM 18 is installed
# via the official LLVM apt repository (e.g., Ubuntu 24.04, Debian Trixie).
set(CMAKE_C_COMPILER /usr/bin/clang-18)
set(CMAKE_CXX_COMPILER /usr/bin/clang++-18)

# Set the required compiler flags.
# This tells Clang to use its own standard library and where to find its headers.
set(CMAKE_CXX_FLAGS_INIT "-stdlib=libc++ -I/usr/lib/llvm-18/include" CACHE STRING "Initial C++ flags")

# Set the required linker flags.
# This tells the linker where to find libraries and to link libunwind.
set(CMAKE_EXE_LINKER_FLAGS_INIT "-L/usr/lib/llvm-18/lib -Wl,-rpath,/usr/lib/llvm-18/lib -lc++" CACHE STRING "Initial linker flags for executables")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-L/usr/lib/llvm-18/lib -Wl,-rpath,/usr/lib/llvm-18/lib -lc++" CACHE STRING "Initial linker flags for shared libraries")

# End of clang18-linux-toolchain.cmake