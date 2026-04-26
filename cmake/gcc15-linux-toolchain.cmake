# CMake Toolchain file for GCC 15 on Linux. Check to make sure paths are correct for your installation.
# This file configures the build to use the GCC 15 compiler and link against libstdc++.

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

# Specify the C and C++ compilers from your GCC installation.
# Package manager and custom source installation paths may vary.
set(CMAKE_C_COMPILER "/opt/gcc-15/bin/gcc-15")
set(CMAKE_CXX_COMPILER "/opt/gcc-15/bin/g++-15")

# Set the required compiler flags.
# This tells GCC to use its own standard library and where to find its headers.
set(CMAKE_CXX_FLAGS_INIT "-I/opt/gcc-15/include" CACHE STRING "Initial C++ flags for GCC")

# Set linker flags.
# The g++ driver automatically links the C++ standard library (libstdc++).
# We just need to provide the search paths to ensure it finds the correct version from this toolchain.
set(CMAKE_EXE_LINKER_FLAGS_INIT "-L/opt/gcc-15/lib64 -Wl,-rpath,/opt/gcc-15/lib64" CACHE STRING "Initial linker flags for executables")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-L/opt/gcc-15/lib64 -Wl,-rpath,/opt/gcc-15/lib64" CACHE STRING "Initial linker flags for shared libraries")

# End of gcc15-linux-toolchain.cmake