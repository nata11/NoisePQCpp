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
- [Testing](#testing)
- [Additional Resources](#additional-resources)

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
  - MSVC 19.44+ (Visual Studio 2022 17.14+, tested on Windows 11 x86_64 with MSVC 19.44)
- **Catch2** v3.16.1 for testing (downloaded automatically via CMake FetchContent)
- **Botan** 3.13.0 cryptographic library (pre-downloaded Botan minimized build source in `third_party/`)
- **Google Benchmark** v1.10.0 for benchmarking (downloaded automatically via CMake FetchContent). See [Benchmarking Guide](BenchmarkingGuide.md) for complete benchmarking instructions.
- **asio** 1.39.0 (standalone) for the network examples and benchmarks (downloaded automatically via CMake FetchContent)
- **Git** for version control

**Important**:
- C++ modules require the Ninja generator. The Unix Makefiles and Visual Studio generators are not supported (with a Visual Studio generator, CMake 4.3 stops at configure with "Unsupported generator" for `import std`).
- On the first CMake configure of a build tree, Catch2, asio and Google Benchmark (when `NOISEPQC_BUILD_BENCHMARKS` is `ON`, the default, and the build is Release or multi-config) are downloaded automatically and built with the project's toolchain; a system-wide installation is never used.
- Botan 3.13.0 minimized build source is provided for macOS (ARM64), Linux (x86_64, ARM64), and Windows (x86_64).

## Platform-Specific Instructions

### Linux (x86_64 and ARM64)

**Supported Architectures**: x86_64 and ARM64 (tested on Ubuntu 26.04 x86_64/ARM64 and Raspberry Pi 5 on Debian Trixie)  
**Botan Version**: 3.13.0 (pre-downloaded source included in `third_party/`)  
**Compilers**: Clang 21.1.x and GCC 15.2+

#### Ubuntu / Debian (Clang)

```bash
# Install dependencies. The packaged cmake may be older than 4.3; see the CMake note above.
sudo apt update
sudo apt install cmake ninja-build clang-21 clang-tools-21 llvm-21 libc++-21-dev libc++abi-21-dev

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
- Sets `llvm-ar`/`llvm-ranlib` for LTO archives and links libc++ statically into executables (see [ISA baseline, optimization and linking](#isa-baseline-optimization-and-linking))

#### Ubuntu (GCC 15.2+)

**Note**: GCC 15.2+ is required for full C++23 modules support with `import std;`. On Ubuntu 26.04, GCC 15.2 is the distro default — installing `build-essential` provides the `gcc-15`/`g++-15` compilers the toolchain file expects. (The GCC build path is tested on Ubuntu only.)

```bash
# Install dependencies. The packaged cmake may be older than 4.3; see the CMake note above.
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
- Sets the distro GCC 15 compilers (`/usr/bin/gcc-15`, `/usr/bin/g++-15`) and `gcc-ar-15`/`gcc-ranlib-15` for LTO archives
- Links libstdc++ statically into executables
- No include or library paths are needed: the distro compiler finds its own headers and libstdc++, and CMake discovers libstdc++'s std-module manifest (`libstdc++.modules.json`) automatically via the compiler

#### Raspberry Pi 5 (ARM64)

The Raspberry Pi 5 uses the same `cmake/clang21-linux-toolchain.cmake` as the other Linux hosts — Debian Trixie's LLVM 21 packages lay out the toolchain under the same paths as Ubuntu's. On Debian Trixie, `clang-21` comes from `trixie-backports`. The default ISA baseline for arm64 is `-mcpu=cortex-a76` (the Pi 5's core), so a Raspberry Pi 4 needs `-DNOISE_BOTAN_ARCH_FLAGS=-mcpu=cortex-a72` at configure time; see [ISA baseline, optimization and linking](#isa-baseline-optimization-and-linking).

```bash
# Install dependencies. The packaged cmake may be older than 4.3; see the CMake note above.
sudo apt update
sudo apt install -t trixie-backports clang-21 clang-tools-21 llvm-21 libc++-21-dev libc++abi-21-dev
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
**macOS SDK**: the Command Line Tools `MacOSX26.sdk` must be installed (see below)  
**Botan Version**: 3.13.0 (pre-downloaded source included in `third_party/`)

#### Using Homebrew LLVM

```bash
# Install dependencies.
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
- Uses the Homebrew LLVM 21 prefix on Apple Silicon (`/opt/homebrew/opt/llvm@21`)
- Sets the Clang 21 compilers from that prefix
- Configures libc++ standard library and include paths
- Points CMake directly at libc++'s std-module manifest (`libc++.modules.json`) via `CMAKE_CXX_STDLIB_MODULES_JSON` for `import std;` support
- Configures linker flags for libc++ and libunwind (libunwind moved to `lib/unwind` in LLVM 21)
- Pins the macOS SDK to `/Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk`, the SDK Homebrew LLVM 21's config files use (`clang-scan-deps` 21 does not read them). `xcrun --show-sdk-path` and the unversioned `MacOSX.sdk` resolve to SDK 27 once it is installed, and its headers break LLVM 21's libc++ (`DBL_MAX_10_EXP` undeclared). After changing SDKs, delete the build directory (or its `CMakeCache.txt`)

### Windows (x86_64)

**Supported Architecture**: x86_64  
**Botan Version**: 3.13.0 (pre-downloaded source included in `third_party/`)  
**Compiler**: MSVC 19.44+ (Visual Studio 2022 17.14+; tested on Windows 11 with Visual Studio 2022 17.14 and MSVC 19.44)

> **Build times**: Debug builds are quick. Release builds take longer, because each executable gets its own link-time code generation (`/LTCG`) pass over Botan and the library, a few minutes each; the links run in parallel. On a 24-thread machine a Debug build took about 20 seconds and a Release build about 4 minutes. A Debug test run takes about 2 minutes, mostly the Cacophony test vectors, because Botan is not optimized in MSVC Debug builds; a Release test run takes seconds. For faster iteration, consider the Docker image with Clang 21.

#### Prerequisites

Install:

- **Visual Studio 2022 (17.14 or later)**, or its Build Tools, with the **Desktop development with C++** workload. The C++ standard library modules (`std.ixx`) come with the MSVC toolset; no separate modules component is needed.
- **CMake 4.3 or later** from [cmake.org](https://cmake.org/download/). The CMake installed by Visual Studio's "C++ CMake tools for Windows" component is older (3.31 in Visual Studio 2022 17.14) and cannot configure this project.
- **Ninja** on `PATH`, from the [Ninja releases](https://github.com/ninja-build/ninja/releases) (tested with 1.13.2).
- **Git for Windows** on `PATH`: CMake uses it to download Catch2, asio and Google Benchmark on the first configure. No other manual installation is needed.

#### Step 1 — Launch a Developer Command Prompt

CMake auto-detects MSVC, **but only when `cl.exe` is on `PATH` and the MSVC `INCLUDE`/`LIB` environment variables are set**. A regular Command Prompt does **not** have these set up.

Open *Start Menu → "x64 Native Tools Command Prompt for VS 2022"*. The plain "Developer Command Prompt for VS 2022" sets up the 32-bit x86 compiler by default, which this project does not support.

**Verify** MSVC, CMake and Ninja before continuing:

```cmd
cl
cmake --version
ninja --version
```

You should see `Microsoft (R) C/C++ Optimizing Compiler Version 19.44.xxxxx for x64`, CMake 4.3 or later, and a Ninja version. If `cmake --version` is older than 4.3, Visual Studio's copy of CMake comes first on `PATH`: put the cmake.org one first, or call it by its full path.

If `cl` is not recognized, or its banner does not end in `for x64`, you are not in the x64 Native Tools Command Prompt; go back to the Start Menu.

#### Step 2 — Configure, build, and test

Run from the repository root (where `CMakeLists.txt` lives):

**With the presets** (one command):

```cmd
cmake --workflow --preset windows-release
```

This configures `build\windows-release` with Ninja, `CMAKE_BUILD_TYPE=Release` and `NOISE_DEBUG_BUILD=OFF`, builds it, and runs the tests. `CMakePresets.json` also defines `windows-debug` and `windows-release-mt` (the static runtime, see [Runtime library](#runtime-library)), which run step by step:

```cmd
cmake --preset windows-release-mt
cmake --build --preset windows-release-mt
ctest --preset windows-release-mt
```

`cmake --list-presets` lists them. The presets apply only on a Windows host, and Ninja must be on `PATH`.

**Without the presets**, the same build is:

```cmd
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DNOISE_DEBUG_BUILD=OFF -S . -B build-release
cmake --build build-release
ctest --test-dir build-release --output-on-failure
```

If Ninja is not on `PATH`, add `-DCMAKE_MAKE_PROGRAM=<full path to ninja.exe>` to the first command. `-G Ninja` is required: without it, CMake picks the Visual Studio generator and stops (see [Troubleshooting](#windows-unsupported-generator-visual-studio-17-2022)). For Debug and Release in one build directory, use `-G "Ninja Multi-Config"` without `-DCMAKE_BUILD_TYPE`, then `--config Debug` or `--config Release` on the build and `-C Debug` or `-C Release` on `ctest`.

**Note**: A separate toolchain file is **not** needed on Windows — the command prompt's MSVC environment is what selects MSVC. This differs from Linux/macOS, where `cmake/clang21-*-toolchain.cmake` or `cmake/gcc15-linux-toolchain.cmake` must be passed via `-DCMAKE_TOOLCHAIN_FILE`. CMake ≥ 4.3 is required on Windows as well.

#### Runtime library

By default, MSVC builds link the Microsoft C/C++ runtime dynamically (`/MD`; `/MDd` in Debug). Release executables then need `MSVCP140.dll`, `VCRUNTIME140.dll` and `VCRUNTIME140_1.dll`, which Visual Studio installs. To run a Release executable on a machine without Visual Studio, install the Microsoft Visual C++ Redistributable for Visual Studio 2015–2022 (x64), the same version as the toolset that built it, or later. Debug executables use Visual Studio's debug runtime, which is not redistributable, so they run only where Visual Studio is installed.

To build self-contained executables instead, link the runtime statically with one more configure option. Keep the double quotes, because `cmd` would otherwise treat `<` and `>` as redirection:

```cmd
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DNOISE_DEBUG_BUILD=OFF -DCMAKE_MSVC_RUNTIME_LIBRARY="MultiThreaded$<$<CONFIG:Debug>:Debug>" -S . -B build-release-mt
```

The `windows-release-mt` preset sets the same option. The option applies to every target, the downloaded dependencies included. The executables then depend only on Windows system DLLs, and each Release executable is about 0.2–0.3 MB larger. Both runtimes pass the full test suite. Like every cache value, the option persists in its build directory, so use a fresh directory for each runtime.

## Docker

Pre-configured Docker images are available for building and testing on Linux without setting up a local toolchain. The Dockerfiles are located in the `docker/` directory.

Available images:
- **Clang 21** (`docker/clang21-ubuntu26/Dockerfile`): Ubuntu 26.04 with Clang 21.1.x, CMake 4.3.5, Ninja — amd64 and arm64
- **GCC 15** (`docker/gcc15-ubuntu26/Dockerfile`): Ubuntu 26.04 with GCC 15.2 (distro packages), CMake 4.3.5, Ninja — amd64 only
- The archived 0.9.0 images (Debian Trixie with Clang 18 or GCC 15.2, paired with the `v0.9.0` tag) remain published for the paper artifact; see [Archived Images](DockerGuide.md#archived-images-090--paper-artifact).

Both images include a Python environment with analysis tools (pandas, matplotlib, seaborn, JupyterLab) for benchmark post-processing.

For detailed instructions on pulling images, building inside containers, and running benchmarks, see the [Docker Image Usage Guide](DockerGuide.md).

## Build Options

### Debug Builds with Logging

Debug logging is compiled in by default (`NOISE_DEBUG_BUILD` is `ON`); pass `-DNOISE_DEBUG_BUILD=OFF` for a build without it. The option applies to every configuration of a build tree, so a Ninja Multi-Config tree configured with it `ON` logs in `--config Release` too. To set it explicitly:

```bash
cmake -B build-debug -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-macOS-toolchain.cmake \
  -DNOISE_DEBUG_BUILD=ON
```

This enables color-coded, detailed logging of:
- Token processing (e, s, ee, es, se, ss, psk, ekem, skem)
- State transitions (plaintext → encrypted)
- Key exchanges and DH operations
- Message flows and sizes
- Role identification (Initiator/Responder)

**For complete information**, see [Logging and Debugging Guide](LoggingAndDebugging.md).

### Benchmarking

Benchmarks require a Release build configuration. They are enabled by default (`NOISEPQC_BUILD_BENCHMARKS=ON`) and Google Benchmark v1.10.0 is automatically downloaded via FetchContent on first configure.

With single-config generators (Ninja), benchmarks are only built when `CMAKE_BUILD_TYPE=Release`. With Ninja Multi-Config, `--config Debug` skips the benchmark targets and Google Benchmark, and the other configs build them. In either case, run benchmarks from a `--config Release` build configured with `-DNOISE_DEBUG_BUILD=OFF`; `scripts/run_benchmarks.sh` does both.

**For complete information**, see [Benchmarking Guide](BenchmarkingGuide.md).

### ISA baseline, optimization and linking

**ISA baseline.** The cache variable `NOISE_BOTAN_ARCH_FLAGS` holds the ISA baseline. `cmake/BuildConfig.cmake` appends it to `CMAKE_CXX_FLAGS`, so it applies to every C++ compile and link in every config (third-party code and CMake's std-module targets included) and sets the CPU floor for every binary. Each toolchain file sets the default:

| Toolchain | Default | CPU requirement |
| --- | --- | --- |
| Linux x86_64, Clang 21 and GCC 15 | `-march=x86-64-v3` | AVX2-class (x86-64-v3) |
| Linux arm64 and Raspberry Pi 5 | `-mcpu=cortex-a76` | Cortex-A76 / ARMv8.2-A. A Raspberry Pi 4 does not qualify |
| macOS Apple Silicon | `-mcpu=native` | binaries are tied to the build host's CPU generation |
| Windows MSVC (no toolchain file; set in `cmake/BuildConfig.cmake`) | `/arch:AVX2` | AVX2 |

**Known limitation on Linux arm64 (1.0.0 and 1.1.0).** The bundled Botan build does not detect CPU features at run time on Linux arm64 (Raspberry Pi 5, AWS Graviton and other aarch64 Linux hosts), so it uses its portable code paths there: ChaCha20 without NEON, and AES, GHASH and SHA-2 without the ARMv8 instructions. Results are correct; only speed is affected, mostly transport-phase throughput and less so the handshake. macOS on Apple Silicon and all x86_64 builds are not affected. `-DNOISE_BOTAN_ARCH_FLAGS` does not change this.

**Overriding it.** Pass `-DNOISE_BOTAN_ARCH_FLAGS=<flags>` at configure time, for example `-DNOISE_BOTAN_ARCH_FLAGS=-mcpu=cortex-a72` for a Raspberry Pi 4, or `-DNOISE_BOTAN_ARCH_FLAGS=-march=x86-64-v2` for a more portable x86_64 build. Like every CMake cache value, it persists in that build directory until it is changed, so changing it means reconfiguring that directory.

**Optimization defaults.** `botan_static` is always optimized, independent of the build type: `-O3` with `-ffunction-sections -fdata-sections` and `NDEBUG` in every config (MSVC: `/O2` outside Debug, `/Gy`). Link-time optimization (IPO/LTO; ThinLTO on Clang) is enabled for Release and RelWithDebInfo on `botan_static`, `noisepqc` and every executable, and executables are linked with a dead-strip in every config except Debug (`-dead_strip` on macOS, `--gc-sections` on Linux, `/OPT:REF /OPT:ICF` on MSVC). Benchmark targets and Google Benchmark are not built in the Ninja Multi-Config Debug config (`--config Debug --target <bench>` still builds one on demand).

**Static C++ runtime on Linux.** Linux executables link the C++ runtime statically (libc++ and libc++abi with Clang 21, libstdc++ with GCC 15) and need only glibc and `libgcc_s` at run time. macOS executables link libc++ dynamically. Existing build directories need a fresh configure, because `*_LINKER_FLAGS_INIT` only seeds a new cache. Windows links the MSVC runtime dynamically by default; see [Runtime library](#runtime-library).

**Outputs.** Built executables and libraries go to each build tree: `${CMAKE_BINARY_DIR}/bin/<Config>/…` with a multi-config generator and `${CMAKE_BINARY_DIR}/bin/…` with a single-config one (the root is `NOISEPQC_BIN_DIR`, overridable at configure time), so separate build directories never overwrite each other's binaries.

### CMake Configuration Options

```bash
# Debug build
cmake -B build -S . -G Ninja -DCMAKE_TOOLCHAIN_FILE=<toolchain file> -DCMAKE_BUILD_TYPE=Debug

# Release build (optimized)
cmake -B build -S . -G Ninja -DCMAKE_TOOLCHAIN_FILE=<toolchain file> -DCMAKE_BUILD_TYPE=Release

# RelWithDebInfo (optimized with debug symbols)
cmake -B build -S . -G Ninja -DCMAKE_TOOLCHAIN_FILE=<toolchain file> -DCMAKE_BUILD_TYPE=RelWithDebInfo
```

Project options (set in `cmake/BuildConfig.cmake`):

| Option | Default | Effect |
| --- | --- | --- |
| `NOISE_DEBUG_BUILD` | `ON` | Compiles in debug logging (see [Debug Builds with Logging](#debug-builds-with-logging)) |
| `NOISEPQC_BUILD_BENCHMARKS` | `ON` | Builds the benchmarks (see [Benchmarking](#benchmarking)) |
| `NOISE_BOTAN_ARCH_FLAGS` | set by the toolchain file | ISA baseline (see [ISA baseline, optimization and linking](#isa-baseline-optimization-and-linking)) |
| `NOISEPQC_BIN_DIR` | `${CMAKE_BINARY_DIR}/bin` | Root directory for built executables and libraries |

## Troubleshooting

### C++ Modules Not Found

**Problem**: Compiler cannot find C++ module files or "Unsupported generator" error

**Solution**:
- Ensure you're using Clang 21 or GCC 15.2+
- Check that CMake is version 4.3+
- **Must use Ninja generator**: Add `-G Ninja` to cmake command
- Install Ninja: `brew install ninja` (macOS) or `sudo apt install ninja-build` (Linux)
- Try a clean rebuild: `rm -rf build && cmake -B build -S . -G Ninja -DCMAKE_TOOLCHAIN_FILE=<toolchain file>`

### macOS Homebrew Clang: `import std;` / `libc++.modules.json`

**Problem**: CMake fails during configure with `__CMAKE::CXX23`, `CXX_MODULE_STD`, or `libc++.modules.json` errors when using Homebrew Clang and `import std;`.

**Solution**: Verify `llvm@21` is installed via Homebrew, CMake is ≥ 4.3, and the configure command passes `-DCMAKE_TOOLCHAIN_FILE=cmake/clang21-macOS-toolchain.cmake` — the toolchain file points CMake at the module manifest directly.

### Botan Library Errors

**Problem**: Cannot find `botan_all.h` or linking errors

**Solution**:
- Verify `third_party/botan/` directory exists
- Check that the correct platform directory is being used
- CMake should automatically select based on your system

### Test Failures

**Problem**: Tests fail during execution

**Solution**:
- Run tests individually to isolate failures: `./build/bin/tests/test_cipher -s`
- Check for missing runtime dependencies
- Verify platform-specific Botan library is correct

### macOS LLVM Linking Issues

**Problem**: Linker cannot find libc++ or module files

**Solution**:
```bash
# Reconfigure a fresh build directory with the toolchain file
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-macOS-toolchain.cmake
```

### Windows: "No CMAKE_CXX_COMPILER could be found"

**Problem**: `cmake -G Ninja -B build -S .` fails immediately with:

```
-- The CXX compiler identification is unknown
CMake Error at CMakeLists.txt:16 (project):
  No CMAKE_CXX_COMPILER could be found.
```

**Cause**: You are running from a regular Command Prompt. MSVC's `cl.exe` is not on `PATH`, so CMake cannot find a C++ compiler.

**Solution**: Launch *"x64 Native Tools Command Prompt for VS 2022"* from the Start Menu (see [Windows (x86_64) → Step 1](#step-1--launch-a-developer-command-prompt)). Then run `cl` to confirm MSVC is detected before re-running cmake.

**Note**: Adding `-DCMAKE_TOOLCHAIN_FILE=...` will **not** fix this — there is no Windows toolchain file in `cmake/` by design. The MSVC environment is set up by the shell, not by a CMake toolchain file.

### Windows: "Unsupported generator: Visual Studio 17 2022"

**Problem**: configure stops with `The "CXX_MODULE_STD" property on target "..." requires toolchain support, but it was not provided. Reason: Unsupported generator: Visual Studio 17 2022`, and `cmake --build` then reports `MSB1009: Project file does not exist`.

**Cause**: no `-G` option was given, so CMake picked the Visual Studio generator, which CMake 4.3's `import std` support does not handle.

**Solution**: configure a fresh build directory with `-G Ninja` (or `-G "Ninja Multi-Config"`), as in [Step 2](#step-2--configure-build-and-test).

### Windows Module Errors

**Problem**: MSVC cannot compile C++ modules

**Solution**:
- Update to Visual Studio 2022 version 17.14 or later
- Verify MSVC version is 19.44+: run `cl` in the x64 Native Tools Command Prompt and check the version line
- Check that `cmake --version` reports 4.3 or later (see the Windows [Prerequisites](#prerequisites-1))

## Testing

### Running All Tests

```bash
ctest --test-dir build --output-on-failure
```

### Running Individual Tests

```bash
# Run with default output
./build/bin/tests/test_handshakestate

# Run with verbose output (Catch2)
./build/bin/tests/test_handshakestate -s

# Run specific test case
./build/bin/tests/test_handshakestate "HandshakeState - Complete XX handshake"

# List all test cases
./build/bin/tests/test_handshakestate --list-tests
```

### Test Coverage

The project includes 374 test cases in 13 executables:
- **test_cipher**: Cipher module (ChaCha20-Poly1305, AES-GCM)
- **test_hash**: Hash module (SHA256, SHA512, BLAKE2b, BLAKE2s)
- **test_dh**: DH and KEM module (X25519, X448, ML-KEM-512/768/1024)
- **test_cipherstate**: CipherState module
- **test_symmetricstate**: SymmetricState module
- **test_protocol**: Protocol module (classical, PQ, and HFS protocols)
- **test_handshakestate**: Complete handshake flows for all 59 classical patterns (3 one-way + 12 interactive + 23 deferred + 21 PSK)
- **test_pattern**: Built-in pattern validation
- **test_noise_pq**: Post-Quantum pattern tests (pqXX, pqNK, etc.)
- **test_hfs**: Hybrid Forward Secrecy pattern tests (XXhfs, NKhfs, etc.)
- **test_vectors**: Cacophony test vectors (`testdata/cacophony.json`)
- **test_wiping**: Secret material is wiped before its memory is freed
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
