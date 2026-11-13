# NoisePQC++

[![DOI](https://zenodo.org/badge/1076354966.svg)](https://doi.org/10.5281/zenodo.19782168)

A C++23 reference implementation of the Noise Protocol Framework with Post-Quantum Cryptography (PQC) and Hybrid Forward Secrecy (HFS) support.

## Overview

NoisePQC++ is a modern, type-safe implementation of the [Noise Protocol Framework](https://noiseprotocol.org/) using C++23 modules. The project provides a clean, well-tested cryptographic protocol library with support for classical, post-quantum, and hybrid cryptographic primitives.

> **Security Notice**: This library is provided for research, educational, and experimental use. It has **not** undergone formal security auditing, evaluation, or validation. Do not use it in production systems or security-critical applications without independent review.

## Features

- **Modern C++23**: Uses C++ modules for better encapsulation and compile times
- **Type-Safe Cryptography**: Strong type system prevents common cryptographic mistakes
- **Complete Noise Protocol**: Full support for all 59 classical Noise handshake patterns (3 one-way + 12 interactive + 23 deferred + 21 PSK)
- **Post-Quantum Ready**: ML-KEM (CRYSTALS-Kyber) support with 13 PQ patterns (1 one-way + 12 interactive), such as pqXX and pqNK
- **Hybrid Forward Secrecy**: 35 HFS patterns (12 interactive + 23 deferred) combining classical DH with post-quantum KEM
- **Cross-Platform**: Supports macOS (ARM64, Apple Silicon), Linux (x86_64, ARM64), and Windows (x86_64)
- **Well-Tested**: Comprehensive test suite with 374 test cases in 13 executables
- **Modular Design**: Clean separation between cipher, hash, DH, KEM, and state management
- **ASIO Networking Examples**: Ready-to-use TCP client/server examples with Noise Protocol
- **Performance Optimized**: Data is encrypted and decrypted directly into output buffers, keeping copies and memory allocations to a minimum
- **Comprehensive Benchmarking**: Google Benchmark integration with handshake and network performance benchmarks
- **Instrumentation**: Builds with `NOISE_DEBUG_BUILD` (on by default) provide color-coded, real-time logging of handshake state transitions, token processing, and key exchanges—ideal for learning and protocol analysis. See [LoggingAndDebugging.md](docs/LoggingAndDebugging.md)

### Supported Algorithms

#### Symmetric Ciphers

- ChaCha20-Poly1305 (default for `Cipher()`)
- AES-256-GCM

#### Hash Functions

- SHA-256 (default for `Hash()`)
- SHA-512
- BLAKE2b
- BLAKE2s

#### Key Exchange (DH)

- X25519 (Curve25519)
- X448 (Curve448)

#### Key Encapsulation Mechanism (KEM) - Post-Quantum

- ML-KEM-512 (CRYSTALS-Kyber)
- ML-KEM-768 (CRYSTALS-Kyber) - Recommended
- ML-KEM-1024 (CRYSTALS-Kyber)

#### Noise Handshake Patterns

**Classical Patterns (59 Total)**

**One-Way Patterns** (3):
- N, K, X

**Fundamental Interactive Patterns** (12):
- NN, NK, NX, KN, KK, KX, XN, XK, XX, IN, IK, IX

**Deferred Patterns** (23):
- NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1
- K1N, K1K, KK1, K1K1, K1X, KX1, K1X1
- I1N, I1K, IK1, I1K1, I1X, IX1, I1X1

**PSK (Pre-Shared Key) Patterns** (21):
- Npsk0, Kpsk0, Xpsk1 (one-way)
- NNpsk0, NNpsk2, NKpsk0, NKpsk2, NXpsk2
- XNpsk3, XKpsk3, XXpsk3
- KNpsk0, KNpsk2, KKpsk0, KKpsk2, KXpsk2
- INpsk1, INpsk2, IKpsk1, IKpsk2, IXpsk2

**Post-Quantum Patterns (PQNoise)** (13):
- pqN, pqNN, pqNK, pqNX
- pqXN, pqXK, pqXX
- pqKN, pqKK, pqKX
- pqIN, pqIK, pqIX

**Hybrid Forward Secrecy (HFS) Patterns** (35):
- NNhfs, NKhfs, NXhfs
- XNhfs, XKhfs, XXhfs
- KNhfs, KKhfs, KXhfs
- INhfs, IKhfs, IXhfs
- Deferred: the 23 deferred patterns with the `hfs` suffix (NK1hfs … I1X1hfs)

All classical, PQ, and HFS patterns are implemented and covered by automated tests.

## Building

### Prerequisites

- **C++23 Compiler**:
  - Clang 21.1.x (Required for C++ modules and "import std;". Tested on macOS (Apple Silicon), Linux (x86_64, ARM64, Raspberry Pi 5 ARM64))
  - MSVC 19.44+ (Visual Studio 2022 17.14+, Windows 11 x86_64; build with `-G Ninja`, see [docs/BuildGuide.md](docs/BuildGuide.md#windows-x86_64))
  - GCC 15.2+ (Required for C++ modules and "import std;". Tested on Linux x86_64)
- **CMake** 4.3+ (required for `import std;` support)
- **Ninja** build system (required for C++ modules)
- **Catch2** v3.16.1 (downloaded automatically via CMake FetchContent and built with the project's toolchain)
- **Google Benchmark** v1.10.0 for the benchmarks (downloaded automatically via CMake FetchContent)
- **ASIO** 1.39.0 (standalone, non-Boost) for the networking examples and network benchmarks (downloaded automatically via CMake FetchContent)
- **Botan** 3.13.0 (included in `third_party/` for multiple platforms)
- **Minimum CPU**: x86-64-v3 (AVX2) on x86_64 Linux and Windows; Cortex-A76 (ARMv8.2-A) on arm64 Linux, Raspberry Pi 5 included. The defaults and the `-DNOISE_BOTAN_ARCH_FLAGS` override are in [ISA baseline, optimization and linking](docs/BuildGuide.md#isa-baseline-optimization-and-linking)

### Build Instructions

**Note**: On the first CMake configure of a build tree, Catch2, asio and Google Benchmark (when benchmarks are enabled and the build is Release or multi-config) are downloaded automatically via FetchContent and built with the project's toolchain; a system-wide installation is never used.

**Botan 3.13.0** minimized build sources are provided in `third_party/` for:
- **macOS**: ARM64 (Apple Silicon) with Clang 21
- **Linux**: x86_64 and ARM64 with GCC 15.2 and Clang 21
- **Windows**: x86_64 with MSVC 19.44+

```bash
# Configure with Ninja (required for C++ modules)
# Use the appropriate toolchain file for your platform:
#   - macOS (Apple Silicon): cmake/clang21-macOS-toolchain.cmake
#   - Linux incl. Raspberry Pi 5 (Clang 21): cmake/clang21-linux-toolchain.cmake
#   - Linux (GCC 15.2+): cmake/gcc15-linux-toolchain.cmake
#   - Windows (MSVC): no toolchain file; in the x64 Native Tools Command Prompt: cmake --workflow --preset windows-release
```

### Linux (Clang 21)

**Supported Architectures**: x86_64 and ARM64 (tested on Ubuntu 26.04 x86_64/ARM64 and Raspberry Pi 5 on Debian Trixie)

```bash
# Install dependencies. The packaged cmake may be older than 4.3; see the CMake note in docs/BuildGuide.md.
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
For platform-specific instructions (macOS, Raspberry Pi, GCC 15.2+, Windows, Docker) and advanced build options, see [docs/BuildGuide.md](docs/BuildGuide.md).

## Testing

The project includes a comprehensive test suite with **374 test cases** in 13 executables:

```bash
# Run all tests
ctest --test-dir build --output-on-failure

# Run specific test modules
./build/bin/tests/test_cipher          # Cipher operations
./build/bin/tests/test_hash            # Hash functions
./build/bin/tests/test_dh              # Diffie-Hellman and ML-KEM
./build/bin/tests/test_cipherstate     # CipherState
./build/bin/tests/test_symmetricstate  # SymmetricState
./build/bin/tests/test_protocol        # Protocol parsing
./build/bin/tests/test_pattern         # Pattern validation
./build/bin/tests/test_handshakestate  # All 59 classical patterns
./build/bin/tests/test_noise_pq        # Post-Quantum patterns
./build/bin/tests/test_hfs             # Hybrid Forward Secrecy
./build/bin/tests/test_vectors         # Cacophony test vectors
./build/bin/tests/test_wiping          # Secret wiping
./build/bin/tests/test_example         # End-to-end API example

# Run with Catch2 filters
./build/bin/tests/test_handshakestate "[xx]"        # XX pattern only
./build/bin/tests/test_handshakestate "[oneway]"    # All one-way patterns
./build/bin/tests/test_handshakestate "[psk]"       # All PSK patterns
./build/bin/tests/test_handshakestate "[deferred]"  # All deferred patterns
./build/bin/tests/test_noise_pq "[pqxx]"            # pqXX pattern only
./build/bin/tests/test_hfs "[xxhfs]"                # XXhfs pattern only
./build/bin/tests/test_handshakestate --list-tests  # List all test cases
```

**Test Coverage**:
- Cryptographic primitives (Cipher, Hash, DH, KEM)
- State management (CipherState, SymmetricState)
- All 59 classical Noise handshake patterns (3 one-way + 12 interactive + 23 deferred + 21 PSK)
- All 13 PQ patterns (1 one-way + 12 interactive)
- All 35 HFS patterns (12 interactive + 23 deferred)
- ML-KEM encapsulation/decapsulation
- Error handling and edge cases
- Observer pattern and callbacks
- Prologue handling
- Pre-shared key (PSK) support

For detailed testing documentation, see [tests/README.md](tests/README.md) and [BuildGuide.md](docs/BuildGuide.md).

## Benchmarking

NoisePQC++ includes Google Benchmark micro-benchmarks and TCP network benchmarks.

**Available Benchmarks**:
- **bench_handshake** - Measures handshake performance for classical, PQ, and HFS patterns
- **bench_example** - SHA-256 hashing, X25519 key generation and DH
- **bench_client** - Network handshake performance from client perspective
- **bench_server** - Responder that bench_client and bench_stress connect to
- **bench_stress** - Stress testing tool for concurrent handshakes

**Performance Analysis**:
The `analysis/` directory contains tools for analyzing benchmark results:
- **benchmark_analysis.ipynb** - Jupyter notebook for visualizing performance data
- **scripts/json_to_csv.py** - Convert JSON benchmark output to CSV for analysis
- **scripts/render_results.py** - Render benchmark CSVs into figures and a Markdown summary

For detailed benchmarking documentation, see [benchmarks/README.md](benchmarks/README.md).

## Usage Example

### Complete Noise XX Handshake

```cpp
import noise;
using namespace Noise;

// Create protocol: Noise_XX_25519_ChaChaPoly_SHA256
Protocol protocol(XX, X25519, ChaChaPoly, SHA256);

// Generate static keys for both parties
auto aliceStatic = protocol.dh.GenerateKeypair();
auto bobStatic = protocol.dh.GenerateKeypair();

// Configure Alice (initiator)
HandshakeConfig aliceCfg{
    .protocol = protocol,
    .isInitiator = true,
    .localStatic = aliceStatic
};

// Configure Bob (responder)
HandshakeConfig bobCfg{
    .protocol = protocol,
    .isInitiator = false,
    .localStatic = bobStatic
};

// Create handshake states
HandshakeState aliceHs(aliceCfg);
HandshakeState bobHs(bobCfg);

// Message 1: Alice -> Bob
std::vector<std::uint8_t> hello{'h', 'e', 'l', 'l', 'o'};
auto msg1 = aliceHs.WriteMessage(hello);
auto recv1 = bobHs.ReadMessage(msg1);

// Message 2: Bob -> Alice
auto msg2 = bobHs.WriteMessage({});
aliceHs.ReadMessage(msg2);

// Message 3: Alice -> Bob (handshake complete)
auto msg3 = aliceHs.WriteMessage({});
bobHs.ReadMessage(msg3);

// Both sides now have matching cipher states for secure communication:
// take them (moved out of the HandshakeState, not copied)
auto aliceStates = aliceHs.TakeCipherStates();   // std::optional<std::pair<CipherState, CipherState>>
auto& [aliceTx, aliceRx] = *aliceStates;          // initiator: cs1 sends, cs2 receives
auto bobStates = bobHs.TakeCipherStates();
auto& [bobRx, bobTx] = *bobStates;                // responder: cs1 receives, cs2 sends

// Use cipher states for transport encryption
std::vector<std::uint8_t> message{'s', 'e', 'c', 'r', 'e', 't'};
auto encrypted = aliceTx.EncryptWithAd({}, message);
auto decrypted = bobRx.DecryptWithAd({}, encrypted);
```

### Additional Examples

The [examples/](examples/) directory contains comprehensive demonstrations:

- **[example_test.cpp](examples/example_test.cpp)** - Complete API walkthrough
  - Protocol construction (from string and manual)
  - Keypair generation and management
  - Full XX handshake execution with detailed logging
  - Transport encryption after handshake completion

- **[example_test_pq.cpp](examples/example_test_pq.cpp)** - Post-Quantum API demonstration
  - pqXX pattern with ML-KEM-768
  - KEM-based key exchange
  - Complete PQ handshake lifecycle

- **[pattern_zoo.cpp](examples/pattern_zoo.cpp)** - Interactive pattern explorer
  - Demonstrates 84 patterns: all 59 classical and 13 PQ patterns, and the 12 interactive HFS patterns
  - Run any pattern by name: `./pattern_zoo XX`, `./pattern_zoo pqXX`, `./pattern_zoo XXhfs`
  - Shows message flows and state transitions

- **[asio-networking/](examples/asio-networking/)** - TCP Client/Server Examples
  - Basic Noise client/server with XX handshake
  - Multi-mode support (XX, pqXX, XXhfs)
  - Alice/Bob quote exchange application
  - See [asio-networking/README.md](examples/asio-networking/README.md) for details

For detailed usage instructions and more examples, see [examples/README.md](examples/README.md).

## Documentation

Comprehensive documentation is available in the [docs/](docs/) directory:

- **[PatternGuide.md](docs/PatternGuide.md)** - Guide to the classical, PQ and HFS patterns with use cases and examples
- **[Architecture.md](docs/Architecture.md)** - System architecture, design principles, and module organization
- **[API.md](docs/API.md)** - Complete API reference for all modules with examples
- **[BuildGuide.md](docs/BuildGuide.md)** - Detailed build instructions for all platforms
- **[BenchmarkingGuide.md](docs/BenchmarkingGuide.md)** - Detailed benchmarking instructions
- **[DockerGuide.md](docs/DockerGuide.md)** - Docker image usage for building and testing
- **[LoggingAndDebugging.md](docs/LoggingAndDebugging.md)** - Debug builds and state transition logging

**Quick Links**:
- [Pattern Selection Guide](docs/PatternGuide.md#pattern-selection-guide) - Choose the right pattern for your use case
- [Testing Matrix](docs/PatternGuide.md#testing-matrix) - Complete test coverage for all patterns
- [HandshakeState API](docs/API.md#handshakestate) - Complete handshake API with examples
- [Logging and Debugging](docs/LoggingAndDebugging.md) - Enable debug mode for detailed handshake logging
- [Testing Guide](docs/BuildGuide.md#testing) - How to run and filter tests

## Development Status

**Current Version**: 1.1.0 (Performance Optimized PQC + HFS Noise Protocol Framework)

This release includes complete implementations of classical Noise, Post-Quantum Noise (PQNoise), and Hybrid Forward Secrecy (HFS) patterns, providing quantum-resistant cryptographic options alongside classical primitives. Version 1.1.0 follows a complete review of the library code: Botan exceptions no longer cross the API (failures surface as `NoiseError` and its subclasses), keys and protocol names are checked earlier, secret material is scrubbed as soon as it is no longer needed, and handshakes cost fewer instructions and allocations. The build adds an ISA baseline, link-time optimization, dead-stripping and a static C++ runtime on Linux. 1.1.0 has breaking changes; see the [CHANGELOG](CHANGELOG.md).

Implemented components:

- ✅ **Cipher** (ChaCha20-Poly1305, AES-256-GCM)
- ✅ **Hash** (SHA-256, SHA-512, BLAKE2b, BLAKE2s)
- ✅ **Diffie-Hellman** (X25519, X448)
- ✅ **Key Encapsulation** (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
- ✅ **CipherState** (complete with rekey support)
- ✅ **SymmetricState** (complete with HKDF)
- ✅ **HandshakeState** (complete with observer pattern)
- ✅ **Classical Patterns** (all 59 patterns: 3 one-way + 12 interactive + 23 deferred + 21 PSK)
- ✅ **Post-Quantum Patterns** (13: pqN one-way + 12 interactive: pqNN, pqNK, pqNX, pqXN, pqXK, pqXX, pqKN, pqKK, pqKX, pqIN, pqIK, pqIX)
- ✅ **HFS Patterns** (35: 12 interactive + 23 deferred; every interactive base pattern with the hfs modifier)
- ✅ **Protocol** (complete protocol specification with PQ/HFS support)
- ✅ **ASIO Networking** (TCP client/server examples with multi-mode support)

## License

NoisePQC++ is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE).

This project uses Apache-2.0 because it is a standard, permissive open-source
license with an express patent grant, which is especially useful for
cryptographic and post-quantum software.

In short, Apache-2.0 allows:

- commercial use
- modification
- distribution
- private use

subject to the license terms, notices, and disclaimer.

## Research Use and Citation

If you use NoisePQC++ in academic research, publications, theses,
dissertations, benchmarks, or other scholarly work, please cite the project.

Recommended citation information is provided in:

- [CITATION.cff](CITATION.cff)
- [RESEARCH-CITATION.md](RESEARCH-CITATION.md)

Suggested BibTeX:

```bibtex
@software{ahmed2026noisepqcpp,
  author       = {Ahmed, Nadeem},
  title        = {NoisePQC++: A C++23 Implementation of the Noise Protocol Framework with Post-Quantum Cryptography},
  year         = {2026},
  url          = {https://github.com/nata11/NoisePQCpp},
  version      = {1.1.0}
}
```

Suggested text citation:

> Ahmed, Nadeem (2026). _NoisePQC++: A C++23 Implementation of the Noise Protocol Framework with Post-Quantum Cryptography._ Version 1.1.0, 2026. https://github.com/nata11/NoisePQCpp

For reproducibility in scholarly work, please also record the exact version,
release tag, or commit hash used in your experiments.

## Third-Party Components

NoisePQC++ includes or depends on third-party software that remains subject to
its own license terms. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## References

- [Noise Protocol Framework Specification](https://noiseprotocol.org/noise.html)

## Acknowledgments

Built with:
- [Botan 3.13.0](https://botan.randombit.net/) - Cryptographic primitives
- [Catch2 v3.16.1](https://github.com/catchorg/Catch2) - Testing framework
- [Google Benchmark v1.10.0](https://github.com/google/benchmark) - Micro benchmarking
- [asio 1.39.0](https://github.com/chriskohlhoff/asio) - Networking (examples and network benchmarks)