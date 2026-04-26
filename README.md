# NoisePQC++

A C++23 reference implementation of the Noise Protocol Framework with Post-Quantum Cryptography (PQC) and Hybrid Forward Secrecy (HFS) support.

## Overview

NoisePQC++ is a modern, type-safe implementation of the [Noise Protocol Framework](https://noiseprotocol.org/) using C++23 modules. The project provides a clean, well-tested cryptographic protocol library with support for classical, post-quantum, and hybrid cryptographic primitives.

> **Security Notice**: This library is provided for research, educational, and experimental use. It has **not** undergone formal security auditing, evaluation, or validation. Do not use it in production systems or security-critical applications without independent review.

## Features

- **Modern C++23**: Uses C++ modules for better encapsulation and compile times
- **Type-Safe Cryptography**: Strong type system prevents common cryptographic mistakes
- **Complete Noise Protocol**: Full support for all 57 classical Noise handshake patterns (15 base + 21 deferred + 21 PSK)
- **Post-Quantum Ready**: ML-KEM (CRYSTALS-Kyber) support with pqXX, pqNK, and other PQ patterns
- **Hybrid Forward Secrecy**: HFS patterns combining classical DH with post-quantum KEM
- **Cross-Platform**: Supports macOS (x86_64, ARM64), Linux (x86_64, ARM64), and Windows (x86_64)
- **Well-Tested**: Comprehensive test suite with 200+ test cases and 500+ assertions
- **Modular Design**: Clean separation between cipher, hash, DH, KEM, and state management
- **ASIO Networking Examples**: Ready-to-use TCP client/server examples with Noise Protocol
- **Performance Optimized**: Direct buffer operations with zero-copy design for minimal memory allocations
- **Comprehensive Benchmarking**: Google Benchmark integration with handshake and network performance benchmarks
- **Instrumentation**: Debug builds provide color-coded, real-time logging of handshake state transitions, token processing, and key exchanges—ideal for learning and protocol analysis. See [LoggingAndDebugging.md](docs/LoggingAndDebugging.md)

### Supported Algorithms

#### Symmetric Ciphers

- ChaCha20-Poly1305 (default)
- AES-256-GCM

#### Hash Functions

- SHA-256 (default)
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

**Classical Patterns (57 Total)**

**One-Way Patterns** (3):
- N, K, X

**Fundamental Interactive Patterns** (12):
- NN, NK, NX, KN, KK, KX, XN, XK, XX, IN, IK, IX

**Deferred Patterns** (21):
- NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1
- K1N, K1K, KK1, K1K1, K1X, KX1, K1X1
- I1N, I1K, IK1, I1K1, I1X, IX1, I1X1

**PSK (Pre-Shared Key) Patterns** (21):
- Npsk0, Kpsk0, Xpsk1 (one-way)
- NNpsk0, NNpsk2, NKpsk0, NKpsk2, NXpsk2
- XNpsk3, XKpsk3, XXpsk3
- KNpsk0, KNpsk2, KKpsk0, KKpsk2, KXpsk2
- INpsk1, INpsk2, IKpsk1, IKpsk2, IXpsk2

**Post-Quantum Patterns (PQNoise)**:
- pqN, pqNN, pqNK, pqNX
- pqXN, pqXK, pqXX
- pqKN, pqKK, pqKX
- pqIN, pqIK, pqIX

**Hybrid Forward Secrecy (HFS) Patterns**:
- NNhfs, NKhfs, NXhfs
- XNhfs, XKhfs, XXhfs
- KNhfs, KKhfs, KXhfs
- INhfs, IKhfs, IXhfs

All classical, PQ, and HFS patterns are implemented and covered by automated tests.

## Project Structure

```
NoisePQC++/
├── analysis/                       # Benchmark analysis tools
│   ├── benchmark_analysis.ipynb    # Jupyter notebook for results visualization
│   ├── data/                       # Raw benchmark data (JSON/CSV)
│   ├── figures/                    # Generated charts and plots
│   ├── requirements.txt            # Python analysis dependencies
│   └── scripts/                    # Analysis scripts
│       ├── json_to_csv.py          # Convert Google Benchmark JSON to CSV
│       └── render_results.py       # Render performance charts
│
├── benchmarks/                     # Performance benchmarks (Google Benchmark)
│   ├── bench_common.hpp            # Shared benchmark helpers
│   ├── bench_handshake.cpp         # Handshake pattern performance benchmarks
│   ├── bench_example.cpp           # Basic benchmark examples
│   └── network/                    # Network performance benchmarks
│       ├── bench_server.cpp        # Benchmark server
│       ├── bench_client.cpp        # Benchmark client
│       └── bench_stress.cpp        # Stress testing tool
│
├── cmake/                          # CMake toolchains and build configuration
│   ├── BuildConfig.cmake           # Shared build options and flags
│   ├── PlatformDetection.cmake     # Platform/architecture detection
│   ├── clang18-linux-toolchain.cmake     # Linux Clang 18 toolchain
│   ├── clang18-macOS-toolchain.cmake     # macOS Clang 18 toolchain
│   ├── clang18-rasPi-toolchain.cmake     # Raspberry Pi Clang 18 toolchain
│   └── gcc15-linux-toolchain.cmake       # Linux GCC 15 toolchain
│
├── docker/                         # Docker build environments
│   ├── clang18-linux/Dockerfile    # Clang 18 Debian Trixie image
│   └── gcc15-linux/Dockerfile      # GCC 15 Debian Trixie image
│
├── docs/                           # Project documentation
│   ├── API.md                      # Public API reference
│   ├── Architecture.md             # System architecture and module layers
│   ├── BenchmarkingGuide.md        # Benchmarking workflows
│   ├── BuildGuide.md               # Platform-specific build instructions
│   ├── DockerGuide.md              # Docker build/run guide
│   ├── LoggingAndDebugging.md      # Debug build and logging guide
│   └── PatternGuide.md             # Noise pattern reference
│
├── examples/                       # Usage examples
│   ├── dh_sandbox.cpp              # DH/KEM exploration sandbox
│   ├── example_test.cpp            # Complete XX handshake example
│   ├── example_test_pq.cpp         # PQNoise API demonstration
│   ├── hs_sandbox.cpp              # HandshakeState exploration sandbox
│   ├── mlkem_sandbox.cpp           # ML-KEM exploration sandbox
│   ├── pattern_zoo.cpp             # Interactive pattern explorer
│   ├── protocol_sandbox.cpp        # Protocol parsing sandbox
│   └── asio-networking/            # TCP client/server examples
│       ├── asio_common.hpp         # Shared ASIO helpers
│       ├── alice.cpp               # Quote exchange server
│       ├── bob.cpp                 # Quote exchange client
│       ├── noise_client.cpp        # Basic Noise client (XX)
│       ├── noise_client_multi.cpp  # Multi-mode client
│       ├── noise_server.cpp        # Basic Noise server (XX)
│       └── noise_server_multi.cpp  # Multi-mode server (XX/pqXX/XXhfs)
│
├── include/                        # Generated/configured headers
│   └── version.h.in                # CMake-configured version header
│
├── output/                         # Runtime output artifacts
│   └── debug-logs/                 # Sample debug captures (HTML/MD/PNG)
│
├── scripts/                        # Helper shell scripts
│   ├── capture_debug_output.sh     # Capture debug logs to HTML/MD/PNG
│   └── run_benchmarks.sh           # Run benchmark suite
│
├── src/                            # Source modules (.cppm files)
│   ├── Cipher.cppm                 # AEAD cipher operations
│   ├── CipherState.cppm            # Cipher state management
│   ├── CipherState.debug.cppm      # Debug version with logging
│   ├── Common.cppm                 # Common types and constants
│   ├── Dh.cppm                     # Diffie-Hellman and KEM operations
│   ├── Errors.cppm                 # Error handling
│   ├── HandshakeState.cppm         # Handshake state machine (classical + PQ + HFS)
│   ├── HandshakeState.debug.cppm   # Debug version with logging
│   ├── Hash.cppm                   # Hash operations
│   ├── Noise.cppm                  # Main module interface
│   ├── Pattern.cppm                # Noise pattern definitions (classical + PQ + HFS)
│   ├── Protocol.cppm               # Protocol identifier
│   ├── SymmetricState.cppm         # Symmetric state management
│   └── SymmetricState.debug.cppm   # Debug version with logging
│
├── testdata/                       # Test vectors and fixtures
│   ├── alice_bob_quotes.json       # Quote exchange fixture (Alice → Bob)
│   ├── bob_alice_quotes.json       # Quote exchange fixture (Bob → Alice)
│   └── cacophony.json              # Cacophony reference test vectors
│
├── tests/                          # Test suite (Catch2)
│   ├── test_cipher.cpp             # Cipher operations
│   ├── test_cipherstate.cpp        # CipherState management
│   ├── test_dh.cpp                 # DH and ML-KEM operations
│   ├── test_example.cpp            # Example integration tests
│   ├── test_handshakestate.cpp     # All 57 classical patterns
│   ├── test_hash.cpp               # Hash functions
│   ├── test_hfs.cpp                # Hybrid Forward Secrecy tests
│   ├── test_noise_pq.cpp           # Post-Quantum pattern tests
│   ├── test_pattern.cpp            # Pattern definitions
│   ├── test_protocol.cpp           # Protocol parsing
│   ├── test_symmetricstate.cpp     # Symmetric state
│   └── test_vectors.cpp            # Test vector validation
│
├── third_party/                    # Third-party dependencies
│   ├── botan/                      # Botan crypto library (platform-specific builds)
│   │   ├── plat_linux_arm64/       # Linux ARM64 (Raspberry Pi)
│   │   ├── plat_linux_x86_clang/   # Linux x86_64 (Clang)
│   │   ├── plat_linux_x86_gcc/     # Linux x86_64 (GCC)
│   │   ├── plat_mac_arm64/         # macOS Apple Silicon
│   │   ├── plat_mac_x86/           # macOS Intel
│   │   └── plat_win_x86/           # Windows x86_64
│   └── nlohmann/                   # nlohmann/json header-only library
│
├── CMakeLists.txt                  # Root build entry point
├── Doxyfile                        # Doxygen API doc configuration
├── CHANGELOG.md                    # Release notes
├── CITATION.cff                    # Citation metadata
├── LICENSE                         # Project license
├── README.md                       # This file
├── RESEARCH-CITATION.md            # Research citation references
└── THIRD_PARTY_NOTICES.md          # Third-party license notices
```

## Building

### Prerequisites

- **C++23 Compiler**:
  - Clang 18.1.8 (Required for C++ modules and "import std;". Tested on macOS (Intel & Apple Silicon), Linux (x86_64, Raspberry Pi 5 ARM64)
  - MSVC 19.44+ (Visual Studio 2022 Update 17+ for Windows 11)
  - GCC 15.2.0 (Required for C++ modules and "import std;". Tested on Linux x86_64)
- **CMake** 4.0+
- **Ninja** build system (required for C++ modules)
- **Catch2** v3.11.0 (automatically downloaded via CMake FetchContent if not found system-wide)
- **ASIO** (standalone, non-Boost) for networking examples (automatically downloaded via CMake FetchContent if not found system-wide)
- **Botan** 3.10.0 (included in `third_party/` for multiple platforms)

### Build Instructions

**Note**: On first CMake run, Catch2 and Google Benchmark will be automatically downloaded via FetchContent if not found system-wide.

**Pre-built Botan 3.10.0** minimized build sources are provided in `third_party/` for:
- **macOS**: x86_64 (Intel) and ARM64 (Apple Silicon) with Clang 18
- **Linux**: x86_64 and ARM64 with GCC 15.2 and Clang 18
- **Windows**: x86_64 with MSVC 19.44+

```bash
# Configure with Ninja (required for C++ modules)
# Use the appropriate toolchain file for your platform:
#   - macOS (Intel/Apple Silicon): cmake/clang18-macOS-toolchain.cmake
#   - Linux (Clang 18): cmake/clang18-linux-toolchain.cmake
#   - Linux (GCC 15): cmake/gcc15-linux-toolchain.cmake
#   - Raspberry Pi (ARM64): cmake/clang18-rasPi-toolchain.cmake

# Example for Linux (Clang 18):
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-linux-toolchain.cmake

# Build (Catch2 will download on first run if needed)
cmake --build build

# Run tests
cd build
ctest --output-on-failure
```

### Linux (Clang 18)

**Supported Architectures**: x86_64 and ARM64 (tested on Debian Trixie/Ubuntu 24.04 x86_64 and Raspberry Pi 5)

```bash
# Install dependencies. See cmake note in BuildGuide.md for experimental import std module support.
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
For platform-specific instructions (macOS, Raspberry Pi, GCC 15, Windows, Docker) and advanced build options, see [docs/BuildGuide.md](docs/BuildGuide.md).

## Testing

The project includes a comprehensive test suite with **200+ test cases** and **500+ assertions**:

```bash
# Run all tests
cd build
ctest --output-on-failure

# Run specific test modules
./tests/test_cipher              # Cipher operations
./tests/test_hash                # Hash functions
./tests/test_dh                  # Diffie-Hellman and ML-KEM
./tests/test_cipherstate         # CipherState
./tests/test_symmetricstate      # SymmetricState
./tests/test_protocol            # Protocol parsing
./tests/test_handshakestate      # All 57 classical patterns
./tests/test_noise_pq            # Post-Quantum patterns
./tests/test_hfs                 # Hybrid Forward Secrecy
./tests/test_vectors             # Test vector validation

# Run with Catch2 filters
./tests/test_handshakestate "[xx]"        # XX pattern only
./tests/test_handshakestate "[oneway]"    # All one-way patterns
./tests/test_handshakestate "[psk]"       # All PSK patterns
./tests/test_handshakestate "[deferred]"  # All deferred patterns
./tests/test_noise_pq "[pqxx]"            # pqXX pattern only
./tests/test_hfs "[xxhfs]"                # XXhfs pattern only
./tests/test_handshakestate --list-tests  # List all test cases
```

**Test Coverage**:
- Cryptographic primitives (Cipher, Hash, DH, KEM)
- State management (CipherState, SymmetricState)
- All 57 classical Noise handshake patterns
- Post-Quantum patterns (pqNN, pqNK, pqXX, etc.)
- Hybrid Forward Secrecy patterns (XXhfs, NKhfs, etc.)
- ML-KEM encapsulation/decapsulation
- Error handling and edge cases
- Observer pattern and callbacks
- Prologue handling
- Pre-shared key (PSK) support

For detailed testing documentation, see [tests/README.md](tests/README.md) and [BuildGuide.md](docs/BuildGuide.md).

## Benchmarking

NoisePQC++ includes comprehensive performance benchmarks using Google Benchmark.

**Available Benchmarks**:
- **bench_handshake** - Measures handshake performance for classical, PQ, and HFS patterns
- **bench_client** - Network handshake performance from client perspective
- **bench_server** - Network handshake performance from server perspective
- **bench_stress** - Stress testing tool for concurrent handshakes

**Performance Analysis**:
The `analysis/` directory contains tools for analyzing benchmark results:
- **benchmark_analysis.ipynb** - Jupyter notebook for visualizing performance data
- **scripts/json_to_csv.py** - Convert JSON benchmark output to CSV for analysis

For detailed benchmarking documentation, see [benchmarks/README.md](benchmarks/README.md).

## Usage Example

### Complete Noise XX Handshake

```cpp
import noise;
using namespace Noise;

// Create protocol: Noise_XX_X25519_ChaChaPoly_SHA256
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
auto msg1 = aliceHs.WriteMessage({'h', 'e', 'l', 'l', 'o'});
auto recv1 = bobHs.ReadMessage(msg1);

// Message 2: Bob -> Alice
auto msg2 = bobHs.WriteMessage({});
aliceHs.ReadMessage(msg2);

// Message 3: Alice -> Bob (handshake complete)
auto msg3 = aliceHs.WriteMessage({});
bobHs.ReadMessage(msg3);

// Both sides now have matching cipher states for secure communication
auto [aliceTx, aliceRx] = *aliceHs.GetStatus().cipherStates;
auto [bobRx, bobTx] = *bobHs.GetStatus().cipherStates;

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
  - Demonstrates all Noise handshake patterns (classical, PQ, HFS)
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

- **[PatternGuide.md](docs/PatternGuide.md)** - Complete guide to all 57 Noise patterns with use cases and examples
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

**Current Version**: 0.9.0 (Performance Optimized PQC + HFS Noise Protocol Framework)

This release includes complete implementations of classical Noise, Post-Quantum Noise (PQNoise), and Hybrid Forward Secrecy (HFS) patterns, providing quantum-resistant cryptographic options alongside classical primitives. Version 0.9.0 introduces significant performance optimizations with direct buffer operations and comprehensive benchmarking tools.

Implemented components:

- ✅ **Cipher** (ChaCha20-Poly1305, AES-256-GCM)
- ✅ **Hash** (SHA-256, SHA-512, BLAKE2b, BLAKE2s)
- ✅ **Diffie-Hellman** (X25519, X448)
- ✅ **Key Encapsulation** (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
- ✅ **CipherState** (complete with rekey support)
- ✅ **SymmetricState** (complete with HKDF)
- ✅ **HandshakeState** (complete with observer pattern)
- ✅ **Classical Patterns** (all 57 patterns: 3 one-way + 12 fundamental + 21 deferred + 21 PSK)
- ✅ **Post-Quantum Patterns** (pqN, pqNN, pqNK, pqNX, pqXN, pqXK, pqXX, pqKN, pqKK, pqKX, pqIN, pqIK, pqIX)
- ✅ **HFS Patterns** (NNhfs, NKhfs, NXhfs, XXhfs, and all other interactive patterns with HFS modifier)
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
  version      = {0.9.0}
}
```

Suggested text citation:

> Ahmed, Nadeem (2026). _NoisePQC++: A C++23 Implementation of the Noise Protocol Framework with Post-Quantum Cryptography._ Version 0.9.0, 2026 https://github.com/nata11/NoisePQCpp

For reproducibility in scholarly work, please also record the exact version,
release tag, or commit hash used in your experiments.

## Third-Party Components

NoisePQC++ includes or depends on third-party software that remains subject to
its own license terms. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## References

- [Noise Protocol Framework Specification](https://noiseprotocol.org/noise.html)
- [Botan Crypto Library](https://botan.randombit.net/)
- [Catch2 Testing Framework](https://github.com/catchorg/Catch2)
- [Google Benchmark](https://github.com/google/benchmark)

## Acknowledgments

Built with:
- [Botan 3.10.0](https://botan.randombit.net/) - Cryptographic primitives
- [Catch2 v3.11.0](https://github.com/catchorg/Catch2) - Testing framework
- [Google Benchmark](https://github.com/google/benchmark) - Micro benchmarking