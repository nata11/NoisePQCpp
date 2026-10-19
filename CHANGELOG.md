# Changelog

All notable changes to NoisePQC++ will be documented in this file.

## [1.0.0] - 2026-10-19

First stable release. NoisePQC++ 1.0.0 completes the toolchain
modernization: Clang 21, GCC 15.2, CMake 4.3, and Botan 3.13.0
across every supported platform, with all documentation brought in
line.

### Cryptographic Library
- Upgraded Botan from 3.11.1 to 3.13.0; refreshed minimized build
  sources for all six platform targets (macOS x86_64/ARM64,
  Linux x86_64/ARM64 Clang and GCC, Windows x86_64)

### Toolchain & Build System
- Migrated from Clang 18 to Clang 21 (21.1.x) on macOS and Linux
- CMake requirement raised from 4.0 to 4.3; `import std;` experimental
  gate updated for the CMake 4.3.x series
- Consolidated toolchain files:
  - `clang21-macOS-toolchain.cmake` — one file for Apple Silicon and
    Intel; selects the Homebrew LLVM 21 prefix by architecture
  - `clang21-linux-toolchain.cmake` — one file for Linux x86_64,
    ARM64, and Raspberry Pi 5 (Ubuntu 26.04 / Debian Trixie packages)
  - `gcc15-linux-toolchain.cmake` — simplified to target Ubuntu 26.04's
    native `gcc-15`/`g++-15` distro packages
  - Removed the separate Raspberry Pi and MSVC toolchain files
    (Windows needs no toolchain file)
- `import std;` discovery now handled directly via
  `CMAKE_CXX_STDLIB_MODULES_JSON` — the previous macOS Homebrew Clang
  workarounds (resource-dir hints, CMake module patching) are no
  longer needed
- macOS SDK pinned to the Command Line Tools `MacOSX26.sdk`, the SDK
  Homebrew LLVM 21's own config uses: `clang-scan-deps` 21 needs an
  explicit sysroot, and SDK 27 (Xcode 27.1) is incompatible with
  LLVM 21's libc++ headers
- Benchmark automation script updated to the Clang 21 toolchain

### Platform Support
- Linux (x86_64, ARM64) with Clang 21.1.x and GCC 15.2 — verified on
  Ubuntu 26.04
- Raspberry Pi 5 (ARM64, Debian Trixie) with Clang 21.1.x from
  trixie-backports — full test suite verified
- macOS (ARM64) with Homebrew LLVM 21 and the macOS 26 SDK — verified
  on Apple Silicon
- macOS (x86_64, Intel) — **untested**: the build should work, pinned
  to the macOS 26 SDK, but it was not verified for this release. The
  Intel Botan sources (`third_party/botan/plat_mac_x86/`) will be
  removed in a future release
- Windows (x86_64) with MSVC 19.44+ and CMake 4.3+

### Container Images
- New Ubuntu 26.04 Docker images with CMake 4.3.5 added alongside the
  existing ones: `docker/clang21-ubuntu26/` (Clang 21; amd64 + arm64)
  and `docker/gcc15-ubuntu26/` (GCC 15.2 distro packages; amd64 only).
  The 0.9.0 Debian Trixie images (`docker/clang18-linux/`,
  `docker/gcc15-linux/`) are retained unchanged as the paper-pinned
  artifact

### Documentation
- Full documentation sweep for the new toolchain: main README,
  BuildGuide, BenchmarkingGuide, LoggingAndDebugging, Architecture,
  DockerGuide, and the examples/tests/benchmarks READMEs
- Removed obsolete Clang 18 `import std;` workaround instructions
- Rewrote the GCC build path for Ubuntu 26.04 (`build-essential`)

## [0.9.0] - 2026-04-25

First public release of NoisePQC++.

### Cryptographic Primitives
- **Cipher**: ChaCha20-Poly1305 and AES-256-GCM AEAD via Botan 3.11.1
- **Hash**: SHA-256, SHA-512, BLAKE2b, BLAKE2s with one-shot and incremental modes
- **DH**: X25519 and X448 key exchange
- **KEM**: ML-KEM-512, ML-KEM-768, ML-KEM-1024 (CRYSTALS-Kyber) post-quantum key encapsulation

### Protocol Implementation
- All 57 classical Noise handshake patterns (3 one-way, 12 fundamental, 21 deferred, 21 PSK)
- 13 Post-Quantum (PQNoise) patterns: pqN, pqNN, pqNK, pqNX, pqXN, pqXK, pqXX, pqKN, pqKK, pqKX, pqIN, pqIK, pqIX
- Hybrid Forward Secrecy (HFS) patterns combining classical DH with post-quantum KEM
- Complete state management: CipherState, SymmetricState, HandshakeState
- Protocol configuration from components or parsed from string (e.g., `Noise_XXhfs_25519+M768_ChaChaPoly_SHA256`)
- Observer pattern for key validation
- Prologue and pre-shared key (PSK) support
- Rekey support for forward secrecy

### Performance
- Direct buffer operations with zero-copy design
- Performance-optimized handshake execution
- Google Benchmark integration for handshake and network benchmarks

### Platform Support
- Linux (x86_64, ARM64) with Clang 18 and GCC 15.2
- macOS (x86_64, ARM64) with Clang 18
- Windows (x86_64) with MSVC 19.44+

### Testing
- 200+ test cases with 500+ assertions (Catch2 v3.11.0)
- Cacophony test vectors from the Noise specification
- Coverage across all classical, PQ, and HFS patterns

### Examples & Documentation
- ASIO TCP client/server networking examples (classical, PQ, and HFS modes)
- Interactive sandbox examples for DH, protocol, handshake, and pattern exploration
- Debug builds with color-coded real-time logging of handshake state transitions
- Comprehensive documentation: API reference, architecture guide, pattern guide, build guide

### Build System
- C++23 modules with CMake 4.0+ and Ninja / MSBuild (Windows)
- Botan 3.11.1 minimized build source included for all supported platforms
- Multi-config build support (Debug/Release)

### Container Images
- Multi-arch (amd64, arm64) Docker images published to GHCR for Clang 18 and GCC 15
- Debian Trixie base; CMake 4.0.4, Ninja 1.12.1, Python analysis stack pre-installed
- Reproducible pulls by SHA256 digest documented in `docs/DockerGuide.md`
