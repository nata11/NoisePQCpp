# Build Guide

This document provides detailed build instructions for NoisePQC++ across different platforms.

> **Recommended**: Before building from source, try the pre-configured Docker images. They include the exact compiler, CMake, Ninja, and Python analysis stack used to develop and test NoisePQC++, so you can build, test, and benchmark without installing any toolchain locally. See the [Docker Image Usage Guide](DockerGuide.md). Building from scratch is documented below for users who need a native toolchain or are working on an unsupported platform.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Platform-Specific Instructions](#platform-specific-instructions)
  - [Linux (x86_64 and ARM64)](#linux-x86_64-and-arm64)
    - [Raspberry Pi 4/5 (ARM64)](#raspberry-pi-45-arm64)
  - [macOS (x86_64 and ARM64)](#macos-x86_64-and-arm64)
  - [Windows (x86_64)](#windows-x86_64)
- [Docker](#docker)
- [Build Options](#build-options)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### All Platforms

- **CMake** 4.0 or higher (required for C++ module support, tested with 4.0.4)

> Note: For `import std` support make sure to use a CMake version that includes the necessary C++23 module detection features.
> CMake 4.0.4 is recommended and has been tested with the specified toolchains. With other versions, you will have to get the
> right experimental ID. Refer to CMake's documentation for the version you are using to find the correct `CMAKE_EXPERIMENTAL_CXX_IMPORT_STD` value if you are not using 4.0.4.

- **Ninja** build system (required for C++ modules)
- **C++23-compatible compiler**:
  - Clang 18+ (recommended, tested on macOS and Linux with 18.1.8)
  - GCC 15.2+ (with C++ modules support, tested on Linux x86_64 with 15.2.x)
  - MSVC 19.44+ (Visual Studio 2022 17.12+, tested on Windows x86_64)
- **Catch2** v3.11.0 for testing (automatically downloaded via CMake FetchContent if not found)
- **Botan** 3.10.0 cryptographic library (pre-downloaded Botan minimized build source in `third_party/`)
- **Google Benchmark** for benchmarking (automatically downloaded via CMake FetchContent if not found). See [Benchmarking Guide](BenchmarkingGuide.md) for complete benchmarking instructions.
- **Git** for version control

**Important**:
- C++ modules require the Ninja generator. The Unix Makefiles generator is not supported.
- On first CMake run, Catch2 and Google Benchmark (when `NOISEPQC_BUILD_BENCHMARKS` is set to `ON`, the default) will be automatically downloaded if not found system-wide.
- Botan 3.11.1 minimized build source is provided for macOS (x86_64, ARM64), Linux (x86_64, ARM64), and Windows (x86_64).

## Platform-Specific Instructions

### Linux (x86_64 and ARM64)

**Supported Architectures**: x86_64 and ARM64 (tested on Debian Trixie/Ubuntu 24.04 x86_64 and Raspberry Pi 5)  
**Botan Version**: 3.10.0 (pre-downloaded source included in `third_party/`)  
**Compilers**: Clang 18+ and GCC 15.2+

#### Ubuntu / Debian (Clang)

```bash
# Install dependencies. See cmake note above for experimental import std module support.
sudo apt update
sudo apt install cmake ninja-build clang-18 libc++-18-dev libc++abi-18-dev

# Configure with the Linux Clang toolchain file
# The toolchain file handles: compiler paths, libc++, headers, and linker flags
# Run cmake command below from inside the repository root directory (where CMakeLists.txt is located)
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-linux-toolchain.cmake

# Build
cmake --build build -j$(nproc)

# Run tests
ctest --test-dir build --output-on-failure
```

**What the toolchain file does**:
- Sets Clang 18 compiler (`/usr/bin/clang++-18`)
- Configures libc++ standard library
- Sets proper include paths for LLVM 18 headers
- Configures linker flags with rpath for libc++
- Enables `import std;` support

#### Ubuntu / Debian (GCC 15.2)

**Note**: GCC 15.2+ required for full C++23 modules support with `import std;`

```bash
# Install dependencies. See cmake note above for experimental import std module support.
# Note: GCC 15.2 may need to be built from source
# Ensure GCC 15.2 is installed to /opt/gcc-15 (or adjust toolchain file)
sudo apt update
sudo apt install cmake ninja-build gcc-15 g++-15

# Configure with the GCC 15 toolchain file
# The toolchain file handles: compiler paths, libstdc++, headers, and linker flags
# Run cmake command below from inside the repository root directory (where CMakeLists.txt is located)
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/gcc15-linux-toolchain.cmake

# Build
cmake --build build -j$(nproc)

# Run tests
ctest --test-dir build --output-on-failure
```

**What the toolchain file does**:
- Sets GCC 15 compiler (`/opt/gcc-15/bin/g++-15`)
- Configures libstdc++ standard library
- Sets proper include paths for GCC 15 headers
- Configures linker flags with rpath for libstdc++
- Enables `import std;` support

#### Raspberry Pi 4/5 (ARM64)

```bash
# Install dependencies. See cmake note above for experimental import std module support.
sudo apt update
sudo apt install cmake ninja-build clang-18 libc++-18-dev libc++abi-18-dev

# Configure with the Raspberry Pi toolchain file
# The toolchain file handles: compiler paths, libc++, headers, and linker flags
# Run cmake command below from inside the repository root directory (where CMakeLists.txt is located)
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-rasPi-toolchain.cmake

# Build (use fewer jobs on Pi to avoid memory issues)
cmake --build build -j2

# Run tests
ctest --test-dir build --output-on-failure
```

**What the toolchain file does**:
- Sets Clang 18 compiler (`/usr/bin/clang++-18`)
- Configures libc++ standard library
- Sets proper include paths for LLVM 18 headers
- Configures linker flags with rpath for libc++
- Enables `import std;` support
- Optimized for ARM64 architecture

### macOS (x86_64 and ARM64)

**Supported Architectures**: Intel (x86_64) and Apple Silicon (ARM64)  
**Botan Version**: 3.10.0 (pre-downloaded source included in `third_party/`)

#### Using Homebrew LLVM

For Homebrew Clang on macOS, review the `import std;` / `libc++.modules.json` note below before building.

```bash
# Install dependencies. See cmake note above for experimental import std module support.
brew install cmake ninja llvm@18

# Configure with the macOS toolchain file
# The toolchain file handles: compiler paths, libc++, headers, and linker flags
# Run cmake command below from inside the repository root directory (where CMakeLists.txt is located)
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-macOS-toolchain.cmake

# Build
cmake --build build -j$(sysctl -n hw.ncpu)

# Run tests
ctest --test-dir build --output-on-failure
```

**What the toolchain file does**:
- Sets Clang 18 compiler from Homebrew (`/usr/local/opt/llvm@18/bin/clang++` on Intel macOS or `/opt/homebrew/opt/llvm@18/bin/clang++` on Apple Silicon)
- Configures libc++ standard library
- Sets proper include paths for LLVM 18 headers
- Configures linker flags for libc++ and libunwind
- Enables `import std;` support

#### Homebrew Clang `import std;` Note

When building NoisePQC++ with **CMake 4.0.x** and **Homebrew Clang 18.1.x** on macOS, CMake may fail to enable `import std;` because Homebrew Clang can report a bad, relative, or incomplete path for `libc++.modules.json` during compiler detection.

Typical configure-time errors include:

```text
The "CXX_MODULE_STD" property on the target "<target>" requires that the "__CMAKE::CXX23" target exist, but it was not provided by the toolchain.
```

or:

```text
Reason: `libc++.modules.json` resource does not exist
```

This is a macOS/Homebrew toolchain discovery issue rather than a NoisePQC++ source issue. The specific path-resolution problem described here is not expected for the Linux build paths documented below. In particular:
- the Linux Clang toolchain does not use Homebrew's macOS libc++ layout
- the Linux GCC 15.2 toolchain uses `libstdc++` rather than `libc++.modules.json`

**Recommended fix (project-local and persistent for this repository)**

> **Note**: The fixes below are based on research and have not yet been fully tested. If you encounter issues, please report them.

The preferred fix is to add a Clang resource-directory hint to the macOS toolchain file so CMake sees the correct libc++ layout during compiler detection.

Open:

```text
cmake/clang18-macOS-toolchain.cmake
```

and add one of the following lines after the compiler definitions.

For Intel macOS:

```cmake
set(CMAKE_CXX_COMPILER_ID_ARG1
    "-resource-dir=/usr/local/opt/llvm@18/lib/c++"
    CACHE STRING "Extra argument used when CMake probes Clang for import std" FORCE)
```

For Apple Silicon:

```cmake
set(CMAKE_CXX_COMPILER_ID_ARG1
    "-resource-dir=/opt/homebrew/opt/llvm@18/lib/c++"
    CACHE STRING "Extra argument used when CMake probes Clang for import std" FORCE)
```

Then do a clean configure:

```bash
rm -rf build
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-macOS-toolchain.cmake
```

**One-shot configure workaround**

Instead of editing the toolchain file, pass the same hint on the CMake command line:

```bash
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-macOS-toolchain.cmake \
  -DCMAKE_CXX_COMPILER_ID_ARG1="-resource-dir=$(brew --prefix llvm@18)/lib/c++"
```

#### Alternate machine-local workaround: patch the installed CMake compiler module for Homebrew Clang 18.x

> **Note**: The fix below are based on research and **have been fully tested** to work. If you encounter issues, please report them.

If you are building on macOS with **Homebrew Clang 18.x** and **CMake 4.0.x**, and `import std;` still fails because CMake cannot locate `libc++.modules.json`, you can patch the installed CMake compiler module as a machine-local workaround.

This workaround is specifically for **Clang 18.x**. It is different from the newer **Clang 19+** workaround that uses `-print-library-module-manifest-path`.

1. Find CMake's module root:

    ```bash
    cmake --system-information | grep CMAKE_ROOT
    ```

2. Open this file under that root:

    ```text
    ${CMAKE_ROOT}/Modules/Compiler/Clang-CXX-CXXImportStd.cmake
    ```

    On Homebrew CMake this is typically one of:

    ```text
    /opt/homebrew/Cellar/cmake/4.0.4/share/cmake/Modules/Compiler/Clang-CXX-CXXImportStd.cmake
    /usr/local/Cellar/cmake/4.0.4/share/cmake/Modules/Compiler/Clang-CXX-CXXImportStd.cmake
    ```

3. Back up the file before editing it.

4. Find the compiler probe that looks like this:

    ```cmake
    COMMAND
      "${CMAKE_CXX_COMPILER}"
      ${CMAKE_CXX_COMPILER_ID_ARG1}
      -print-file-name=libc++.modules.json
    ```

5. Replace that last line with:

    ```cmake
    -print-file-name=../../c++/libc++.modules.json
    ```

    So the patched block becomes:

    ```cmake
    COMMAND
      "${CMAKE_CXX_COMPILER}"
      ${CMAKE_CXX_COMPILER_ID_ARG1}
      -print-file-name=../../c++/libc++.modules.json
    ```

6. Remove your build directory and reconfigure:

    ```bash
    rm -rf build
    cmake -B build -S . -G Ninja \
      -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-macOS-toolchain.cmake
    ```

This patch is a **machine-local workaround** and will apply to other CMake projects on that Mac, but it is not permanent across CMake upgrades or reinstalls. It should be treated as a last resort after the project-local toolchain-file fix.

This issue is specific to the macOS/Homebrew Clang + libc++ module discovery path. It is not the expected path for the Linux toolchains documented in this guide, and the Linux GCC 15.2 build path uses `libstdc++` rather than `libc++.modules.json`.

### Windows (x86_64)

**Supported Architecture**: x86_64
**Botan Version**: 3.10.0 (pre-downloaded source included in `third_party/`)
**Compiler**: MSVC 19.44+ (Visual Studio 2022 17.12+)

> **Performance Note**: MSVC's C++ modules implementation is currently slower than Clang/GCC, so Windows builds may take significantly longer to compile. For development on Windows, consider using the Docker image with Clang 18 for faster iteration.
> Use "Release" build configuration to reduce compile times and testing times, as "Debug" builds with MSVC modules can be particularly slow.

#### Prerequisites

Install Visual Studio 2022 (17.12 or later) with these workloads/components:

- **Desktop development with C++**
- **C++ CMake tools for Windows**
- **C++ Modules for v143 build tools**

Catch2 and Google Benchmark are fetched automatically via CMake FetchContent — no manual installation needed.

#### Step 1 — Launch a Developer Command Prompt

CMake auto-detects MSVC, **but only when `cl.exe` and the MSVC `INCLUDE`/`LIB` environment variables are on `PATH`**. A regular Command Prompt does **not** have these set up.



Open *Start Menu → "Developer Command Prompt for VS 2022"*.


**Verify** MSVC is on `PATH` before continuing:

```cmd
cl
```

You should see a line similar to:

```
Microsoft (R) C/C++ Optimizing Compiler Version 19.44.xxxxx for x64
```

If `cl` is not recognized, you are still in a regular Command Prompt — go back to Start Menu and look for "Developer Command Prompt for VS 2022".

#### Step 2 — Configure, build, and test

Run from the repository root (where `CMakeLists.txt` lives):

```cmd
cmake -DCMAKE_BUILD_TYPE=Release -S . -B build-release
cmake --build build-release --config Release
ctest --test-dir build-release --output-on-failure
```

**Note**: A separate toolchain file is **not** needed on Windows — the active Developer Command Prompt session is what selects MSVC. This differs from Linux/macOS, where `cmake/clang18-*-toolchain.cmake` or `cmake/gcc15-linux-toolchain.cmake` must be passed via `-DCMAKE_TOOLCHAIN_FILE`.

## Docker

Pre-configured Docker images are available for building and testing on Linux without setting up a local toolchain. The Dockerfiles are located in the `docker/` directory.

Available images:
- **Clang 18** (`docker/clang18-linux/Dockerfile`): Debian Trixie with Clang 18.1.8, CMake 4.0.4, Ninja
- **GCC 15** (`docker/gcc15-linux/Dockerfile`): Debian Trixie with GCC 15.2.0 (built from source), CMake 4.0.4, Ninja

Both images include a Python environment with analysis tools (pandas, matplotlib, seaborn, JupyterLab) for benchmark post-processing.

For detailed instructions on pulling images, building inside containers, and running benchmarks, see the [Docker Image Usage Guide](DockerGuide.md).

## Build Options

### Debug Builds with Logging

To enable comprehensive debug logging showing handshake state transitions:

```bash
cmake -B build-debug -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-macOS-toolchain.cmake \
  -DNOISE_DEBUG_BUILD=ON
```

This enables color-coded, detailed logging of:
- Token processing (e, s, ee, es, se, ss, psk)
- State transitions (plaintext → encrypted)
- Key exchanges and DH operations
- Message flows and sizes
- Role identification (Initiator/Responder)

**For complete information**, see [Logging and Debugging Guide](LoggingAndDebugging.md).

### Benchmarking

Benchmarks require a Release build configuration. They are enabled by default (`NOISEPQC_BUILD_BENCHMARKS=ON`) and Google Benchmark v1.9.1 is automatically downloaded via FetchContent on first configure.

With single-config generators (Ninja), benchmarks are only built when `CMAKE_BUILD_TYPE=Release`. With multi-config generators (Ninja Multi-Config, MS Visual Studio), build with `--config Release`.

**For complete information**, see [Benchmarking Guide](BenchmarkingGuide.md).

### CMake Configuration Options

```bash
# Debug build
cmake -B build -S . -G Ninja -DCMAKE_BUILD_TYPE=Debug

# Release build (optimized)
cmake -B build -S . -G Ninja -DCMAKE_BUILD_TYPE=Release

# RelWithDebInfo (optimized with debug symbols)
cmake -B build -S . -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo

# Specify C++ standard (23 is default)
cmake -B build -S . -G Ninja -DCMAKE_CXX_STANDARD=23
```

## Troubleshooting

### C++ Modules Not Found

**Problem**: Compiler cannot find C++ module files or "Unsupported generator" error

**Solution**:
- Ensure you're using Clang 18+ or GCC 15+
- Check that CMake is version 4.0+
- **Must use Ninja generator**: Add `-G Ninja` to cmake command
- Install Ninja: `brew install ninja` (macOS) or `sudo apt install ninja-build` (Linux)
- Try a clean rebuild: `rm -rf build && cmake -B build -S . -G Ninja`

### macOS Homebrew Clang: `import std;` / `libc++.modules.json`

**Problem**: CMake fails during configure with `__CMAKE::CXX23`, `CXX_MODULE_STD`, or `libc++.modules.json` errors when using Homebrew Clang and `import std;`.

**Solution**: See the detailed [Homebrew Clang `import std;` Note](#homebrew-clang-import-std-note) in the macOS section above for causes and fixes.

### Botan Library Errors

**Problem**: Cannot find `botan_all.h` or linking errors

**Solution**:
- Verify `third_party/botan/` directory exists
- Check that the correct platform directory is being used
- CMake should automatically select based on your system

### Test Failures

**Problem**: Tests fail during execution

**Solution**:
- Run tests individually to isolate failures: `./build/test_cipher -s`
- Check for missing runtime dependencies
- Verify platform-specific Botan library is correct

### macOS LLVM Linking Issues

**Problem**: Linker cannot find libc++ or module files

**Solution**:
```bash
# Add LLVM to PATH
# Intel macOS:
export PATH="/usr/local/opt/llvm@18/bin:$PATH"
export LDFLAGS="-L/usr/local/opt/llvm@18/lib"
export CPPFLAGS="-I/usr/local/opt/llvm@18/include"

# Apple Silicon macOS:
export PATH="/opt/homebrew/opt/llvm@18/bin:$PATH"
export LDFLAGS="-L/opt/homebrew/opt/llvm@18/lib"
export CPPFLAGS="-I/opt/homebrew/opt/llvm@18/include"

# Reconfigure with the toolchain file (recommended over manual compiler flags)
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-macOS-toolchain.cmake
```

### Windows: "No CMAKE_CXX_COMPILER could be found"

**Problem**: `cmake -B build -S .` fails immediately with:

```
-- The CXX compiler identification is unknown
CMake Error at CMakeLists.txt:2 (project):
  No CMAKE_CXX_COMPILER could be found.
```

**Cause**: You are running from a regular Command Prompt. MSVC's `cl.exe` is not on `PATH`, so CMake cannot find a C++ compiler.

**Solution**: Launch *"Developer Command Prompt for VS 2022"* from the Start Menu (see [Windows (x86_64) → Step 1](#step-1--launch-a-developer-command-prompt)). Then run `cl` to confirm MSVC is detected before re-running cmake.

**Note**: Adding `-DCMAKE_TOOLCHAIN_FILE=...` will **not** fix this — there is no Windows toolchain file in `cmake/` by design. The MSVC environment is set up by the shell, not by a CMake toolchain file.

### Windows Module Errors

**Problem**: MSVC cannot compile C++ modules

**Solution**:
- Update to Visual Studio 2022 version 17.12 or later
- Ensure the **C++ Modules for v143 build tools** component is installed via the Visual Studio Installer
- Verify MSVC version is 19.44+: run `cl` in a Developer Command Prompt and check the version line

## Testing

### Running All Tests

```bash
cd build
ctest --output-on-failure
```

### Running Individual Tests

```bash
# Run with default output
./build/tests/test_handshakestate

# Run with verbose output (Catch2)
./build/tests/test_handshakestate -s

# Run specific test case
./build/tests/test_handshakestate "XX handshake"

# List all test cases
./build/tests/test_handshakestate --list-tests
```

### Test Coverage

The project includes comprehensive tests (200+ test cases, 500+ assertions):
- **test_cipher**: Cipher module (ChaCha20-Poly1305, AES-GCM)
- **test_hash**: Hash module (SHA256, SHA512, BLAKE2b, BLAKE2s)
- **test_dh**: DH and KEM module (X25519, X448, ML-KEM-512/768/1024)
- **test_cipherstate**: CipherState module
- **test_symmetricstate**: SymmetricState module
- **test_protocol**: Protocol module (classical, PQ, and HFS protocols)
- **test_handshakestate**: Complete handshake flows for all 57 classical patterns
- **test_noise_pq**: Post-Quantum pattern tests (pqXX, pqNK, etc.)
- **test_hfs**: Hybrid Forward Secrecy pattern tests (XXhfs, NKhfs, etc.)
- **test_vectors**: Noise specification test vectors
- **test_example**: End-to-end demonstration

## Additional Resources

### NoisePQC++ Documentation
- [Docker Image Usage Guide](DockerGuide.md) - Building and testing with Docker containers
- [Pattern Guide](PatternGuide.md) - Complete guide to all Noise patterns (classical, PQ, HFS) with use cases
- [Architecture Documentation](Architecture.md) - System architecture and design principles
- [API Reference](API.md) - Complete API documentation with examples

### Development Tools
- [CMake Documentation](https://cmake.org/documentation/)
- [LLVM Documentation](https://llvm.org/docs/)
- [Catch2 v3 Documentation](https://github.com/catchorg/Catch2/tree/devel/docs)

### Noise Protocol
- [Noise Protocol Specification](https://noiseprotocol.org/noise.html) - Official specification
