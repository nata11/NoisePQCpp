# Changelog

All notable changes to NoisePQC++ will be documented in this file.

## [0.9.0] - 2026-04-25

First public release of NoisePQC++.

### Cryptographic Primitives
- **Cipher**: ChaCha20-Poly1305 and AES-256-GCM AEAD via Botan 3.10.0
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
- Botan 3.10.0 minimized build source included for all supported platforms
- Multi-config build support (Debug/Release)

### Container Images
- Multi-arch (amd64, arm64) Docker images published to GHCR for Clang 18 and GCC 15
- Debian Trixie base; CMake 4.0.4, Ninja 1.12.1, Python analysis stack pre-installed
- Reproducible pulls by SHA256 digest documented in `docs/DockerGuide.md`
