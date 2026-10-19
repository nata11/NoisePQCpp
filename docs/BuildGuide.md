# Build Guide

This document provides detailed build instructions for NoisePQC++ across different platforms.

> **Recommended**: Before building from source, try the pre-configured Docker images. They include the exact compiler, CMake, Ninja, and Python analysis stack used to develop and test NoisePQC++, so you can build, test, and benchmark without installing any toolchain locally. See the [Docker Image Usage Guide](DockerGuide.md). Building from scratch is documented below for users who need a native toolchain or are working on an unsupported platform.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Platform-Specific Instructions](#platform-specific-instructions)
  - [Linux (x86_64 and ARM64)](#linux-x86_64-and-arm64)
    - [Raspberry Pi 5 (ARM64)](#raspberry-pi-5-arm64)
  - [macOS (Apple Silicon)](#macos-apple-silicon)
  - [Windows (x86_64)](#windows-x86_64)
- [Docker](#docker)
- [Build Options](#build-options)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### All Platforms

- **CMake** 4.3 or higher (required for C++ module support, tested with 4.3.5)

> Note: For `import std` support make sure to use a CMake version that includes the necessary C++23 module detection features.
> CMake 4.3.x is required and has been tested with the specified toolchains. The `CMAKE_EXPERIMENTAL_CXX_IMPORT_STD` UUID set
> in the top-level CMakeLists.txt is valid for the CMake 4.3.x series; for other versions, refer to CMake's documentation
> (`Help/dev/experimental.rst` in the CMake source) for the correct value. Distro-packaged CMake may be older than 4.3 —
> if so, install a current release from [cmake.org](https://cmake.org/download/).

- **Ninja** build system (required for C++ modules)
- **C++23-compatible compiler**:
  - Clang 21.1.x (recommended, tested on macOS and Linux with 21.1.x)
  - GCC 15.2+ (with C++ modules support, tested on Ubuntu 26.04 x86_64 with 15.2.x)
  - MSVC 19.44+ (Visual Studio 2022 17.12+, tested on Windows x86_64)
- **Catch2** v3.11.0 for testing (automatically downloaded via CMake FetchContent if not found)
- **Botan** 3.13.0 cryptographic library (pre-downloaded Botan minimized build source in `third_party/`)
- **Google Benchmark** for benchmarking (automatically downloaded via CMake FetchContent if not found). See [Benchmarking Guide](BenchmarkingGuide.md) for complete benchmarking instructions.
- **Git** for version control

**Important**:
- C++ modules require the Ninja generator. The Unix Makefiles generator is not supported.
- On first CMake run, Catch2 and Google Benchmark (when `NOISEPQC_BUILD_BENCHMARKS` is set to `ON`, the default) will be automatically downloaded if not found system-wide.
- Botan 3.13.0 minimized build source is provided for macOS (ARM64; x86_64 untested), Linux (x86_64, ARM64), and Windows (x86_64).

## Platform-Specific Instructions

### Linux (x86_64 and ARM64)

**Supported Architectures**: x86_64 and ARM64 (tested on Ubuntu 26.04 x86_64/ARM64 and Raspberry Pi 5 on Debian Trixie)  
**Botan Version**: 3.13.0 (pre-downloaded source included in `third_party/`)  
**Compilers**: Clang 21.1.x and GCC 15.2+

#### Ubuntu / Debian (Clang)

```bash
# Install dependencies. See cmake note above for experimental import std module support.
sudo apt update
sudo apt install cmake ninja-build clang-21 libc++-21-dev libc++abi-21-dev

# Configure with the Linux Clang toolchain file
# The toolchain file handles: compiler paths, libc++, headers, and linker flags
# Run cmake command below from inside the repository root directory (where CMakeLists.txt is located)
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-linux-toolchain.cmake

# Build
cmake --build build -j$(nproc)

# Run tests
ctest --test-dir build --output-on-failure
```

**What the toolchain file does**:
- Sets Clang 21 compiler (`/usr/bin/clang++-21`)
- Configures libc++ standard library
- Points CMake at libc++'s std-module manifest (`libc++.modules.json`) for `import std;` support
- Configures linker flags with rpath for libc++ (with libc++abi listed explicitly, since the distro packages ship `libc++.so` as a bare symlink rather than a linker script)

#### Ubuntu (GCC 15.2+)

**Note**: GCC 15.2+ is required for full C++23 modules support with `import std;`. On Ubuntu 26.04, GCC 15.2 is the distro default — installing `build-essential` provides the `gcc-15`/`g++-15` compilers the toolchain file expects. (The GCC build path is tested on Ubuntu only.)

```bash
# Install dependencies. See cmake note above for experimental import std module support.
sudo apt update
sudo apt install build-essential cmake ninja-build

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
- Sets the distro GCC 15 compilers (`/usr/bin/gcc-15`, `/usr/bin/g++-15`)
- Nothing else is needed: the distro compiler finds its own headers and libstdc++, and CMake discovers libstdc++'s std-module manifest (`libstdc++.modules.json`) automatically via the compiler

#### Raspberry Pi 5 (ARM64)

The Raspberry Pi 5 uses the same `cmake/clang21-linux-toolchain.cmake` as the other Linux hosts — Debian Trixie's LLVM 21 packages lay out the toolchain under the same paths as Ubuntu's. On Debian Trixie, `clang-21` comes from `trixie-backports`.

```bash
# Install dependencies. See cmake note above for experimental import std module support.
sudo apt update
sudo apt install -t trixie-backports clang-21 libc++-21-dev libc++abi-21-dev
sudo apt install cmake ninja-build

# Configure with the shared Linux Clang toolchain file
# Run cmake command below from inside the repository root directory (where CMakeLists.txt is located)
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-linux-toolchain.cmake

# Build (use fewer jobs on Pi to avoid memory issues)
cmake --build build -j2

# Run tests
ctest --test-dir build --output-on-failure
```

### macOS (Apple Silicon)

**Supported Architecture**: Apple Silicon (ARM64)  
**Intel (x86_64)**: Intel (x86_64) is untested: the build should work, but it has not been verified for this release and is pinned to the macOS 26 SDK. The Intel Botan sources (`third_party/botan/plat_mac_x86/`) will be removed in a future release.  
**macOS SDK**: the Command Line Tools `MacOSX26.sdk` must be installed (see below)  
**Botan Version**: 3.13.0 (pre-downloaded source included in `third_party/`)

#### Using Homebrew LLVM

```bash
# Install dependencies. See cmake note above for experimental import std module support.
brew install cmake ninja llvm@21

# Configure with the macOS toolchain file
# The toolchain file handles: compiler paths, libc++, headers, and linker flags
# Run cmake command below from inside the repository root directory (where CMakeLists.txt is located)
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-macOS-toolchain.cmake

# Build
cmake --build build -j$(sysctl -n hw.ncpu)

# Run tests
ctest --test-dir build --output-on-failure
```

**What the toolchain file does**:
- Selects the Homebrew LLVM 21 prefix by architecture (`/opt/homebrew/opt/llvm@21` on Apple Silicon, `/usr/local/opt/llvm@21` on Intel, untested)
- Sets the Clang 21 compilers from that prefix
- Configures libc++ standard library and include paths
- Points CMake directly at libc++'s std-module manifest (`libc++.modules.json`) via `CMAKE_CXX_STDLIB_MODULES_JSON` for `import std;` support
- Configures linker flags for libc++ and libunwind (libunwind moved to `lib/unwind` in LLVM 21)
- Pins the macOS SDK to `/Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk`, the same SDK that Homebrew LLVM 21's default config files use. The pin is needed because `clang-scan-deps` 21 does not load those config files (which on Homebrew LLVM 21 are the sole source of `-isysroot`). It does not use `xcrun --show-sdk-path`: with Xcode 27.1 that returns SDK 27, whose headers break LLVM 21's libc++ (`DBL_MAX_10_EXP` undeclared in C++20 and later). If you change SDKs, delete the build directory (or its `CMakeCache.txt`) before reconfiguring

#### Homebrew Clang `import std;` Note

Earlier releases of this project (Clang 18 with CMake 4.0.x) required manual workarounds on macOS because Homebrew Clang reported a bad path for `libc++.modules.json` during CMake's compiler detection, breaking `import std;`. This is no longer the case: with CMake ≥ 4.3 the toolchain file points CMake directly at the manifest via `CMAKE_CXX_STDLIB_MODULES_JSON`, so no toolchain patching or `-resource-dir` hints are needed. If you still see configure-time errors mentioning `CXX_MODULE_STD`, `__CMAKE::CXX23`, or `libc++.modules.json`, verify that `llvm@21` is installed via Homebrew and that you passed `-DCMAKE_TOOLCHAIN_FILE=cmake/clang21-macOS-toolchain.cmake`.

### Windows (x86_64)

**Supported Architecture**: x86_64
**Botan Version**: 3.13.0 (pre-downloaded source included in `third_party/`)
**Compiler**: MSVC 19.44+ (Visual Studio 2022 17.12+)

> **Performance Note**: MSVC's C++ modules implementation is currently slower than Clang/GCC, so Windows builds may take significantly longer to compile. For development on Windows, consider using the Docker image with Clang 21 for faster iteration.
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

**Note**: A separate toolchain file is **not** needed on Windows — the active Developer Command Prompt session is what selects MSVC. This differs from Linux/macOS, where `cmake/clang21-*-toolchain.cmake` or `cmake/gcc15-linux-toolchain.cmake` must be passed via `-DCMAKE_TOOLCHAIN_FILE`. CMake ≥ 4.3 is required on Windows as well.

## Docker

Pre-configured Docker images are available for building and testing on Linux without setting up a local toolchain. The Dockerfiles are located in the `docker/` directory.

Available images:
- **Clang 21** (`docker/clang21-ubuntu26/Dockerfile`): Ubuntu 26.04 with Clang 21.1.x, CMake 4.3.5, Ninja — amd64 and arm64
- **GCC 15** (`docker/gcc15-ubuntu26/Dockerfile`): Ubuntu 26.04 with GCC 15.2 (distro packages), CMake 4.3.5, Ninja — amd64 only
- The archived 0.9.0 images (Debian Trixie / Clang 18, paired with the `v0.9.0` tag) remain published for the paper artifact; see [Archived Images](DockerGuide.md#archived-images-090--paper-artifact).

Both images include a Python environment with analysis tools (pandas, matplotlib, seaborn, JupyterLab) for benchmark post-processing.

For detailed instructions on pulling images, building inside containers, and running benchmarks, see the [Docker Image Usage Guide](DockerGuide.md).

## Build Options

### Debug Builds with Logging

To enable comprehensive debug logging showing handshake state transitions:

```bash
cmake -B build-debug -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-macOS-toolchain.cmake \
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
- Ensure you're using Clang 21+ or GCC 15.2+
- Check that CMake is version 4.3+
- **Must use Ninja generator**: Add `-G Ninja` to cmake command
- Install Ninja: `brew install ninja` (macOS) or `sudo apt install ninja-build` (Linux)
- Try a clean rebuild: `rm -rf build && cmake -B build -S . -G Ninja`

### macOS Homebrew Clang: `import std;` / `libc++.modules.json`

**Problem**: CMake fails during configure with `__CMAKE::CXX23`, `CXX_MODULE_STD`, or `libc++.modules.json` errors when using Homebrew Clang and `import std;`.

**Solution**: Verify `llvm@21` is installed via Homebrew, CMake is ≥ 4.3, and the configure command passes `-DCMAKE_TOOLCHAIN_FILE=cmake/clang21-macOS-toolchain.cmake` — the toolchain file points CMake at the module manifest directly. See the [Homebrew Clang `import std;` Note](#homebrew-clang-import-std-note) in the macOS section above.

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
# Intel macOS (untested):
export PATH="/usr/local/opt/llvm@21/bin:$PATH"
export LDFLAGS="-L/usr/local/opt/llvm@21/lib"
export CPPFLAGS="-I/usr/local/opt/llvm@21/include"

# Apple Silicon macOS:
export PATH="/opt/homebrew/opt/llvm@21/bin:$PATH"
export LDFLAGS="-L/opt/homebrew/opt/llvm@21/lib"
export CPPFLAGS="-I/opt/homebrew/opt/llvm@21/include"

# Reconfigure with the toolchain file (recommended over manual compiler flags)
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-macOS-toolchain.cmake
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
