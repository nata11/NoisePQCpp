# Architecture

**Version**: 0.9.0
**Last Updated**: 2026-04-25

This document describes the architecture and design of the NoisePQC++ library.

## Overview

NoisePQC++ is organized as layered C++ modules that mirror the structure of the Noise protocol. The library implements the Noise Protocol Framework using modern C++23 features, particularly C++ modules for better encapsulation and compilation performance, and supports classical Noise patterns, Post-Quantum Noise (PQNoise) patterns, and Hybrid Forward Secrecy (HFS) patterns.

At a high level, the implementation separates cryptographic primitives (DH/KEM, cipher, and hash), protocol state objects (`CipherState`, `SymmetricState`, and `HandshakeState`), and protocol/pattern logic that drives a full handshake. This follows the classic Noise decomposition in which `HandshakeState` uses `SymmetricState`, which in turn relies on hash and cipher functionality and a DH-style key exchange interface. The diagram below depicts this high-level 5-layer module architecture.

## Module Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       Layer 4: Application                      │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                      Noise.cppm                           │  │
│  │               (Application-Facing Facade)                 │  │
│  └───────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                  Layer 3: Protocol & Handshake                  │
│  ┌─────────────────────────┐  ┌───────────────────────────┐    │
│  │     HandshakeState      │  │        Protocol           │    │
│  │  (Token Processing &    │  │  (Pattern + Algorithm     │    │
│  │   Handshake Execution)  │  │   Configuration)          │    │
│  └─────────────────────────┘  └───────────────────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│                   Layer 2: Protocol State                       │
│  ┌─────────────────────────┐  ┌───────────────────────────┐    │
│  │      CipherState        │  │     SymmetricState        │    │
│  │  (AEAD Key & Nonce)     │  │  (Chaining Key & Hash)    │    │
│  └─────────────────────────┘  └───────────────────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│                Layer 1: Cryptographic Primitives                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │  Cipher  │  │   Hash   │  │    Dh    │  │   Pattern    │   │
│  │ (AEAD)   │  │(Hash/HMAC│  │ (DH/KEM) │  │  (Handshake  │   │
│  │          │  │ /HKDF)   │  │          │  │   Patterns)  │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│               Layer 0: Common Utilities & Errors                │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │           Common.cppm  &  Errors.cppm                     │  │
│  │     (Types, Constants, Algorithm IDs, Error Hierarchy)    │  │
│  └───────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                  External Cryptographic Library                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    Botan 3.10.0                            │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Layer Descriptions

### Layer 0: Common Utilities & Errors

**Modules**: `Common.cppm`, `Errors.cppm`

Layer 0 provides shared utilities and error handling. The `Common` module defines core types (byte arrays, spans, etc.), constants, and algorithm identifiers, along with compile-time options and logging controls. The `Errors` module defines the exception hierarchy, including `NoiseError` and specific subclasses such as `HandshakeError` and `InvalidTokenError`, to provide explicit failure modes for malformed messages and cryptographic errors.

**Common.cppm provides**:
- Common types, constants, and enumerations
- Platform-independent type definitions
- Constants for key sizes, nonce limits, etc.
- Algorithm enumerations (CipherAlgo, HashAlgo, KeyAlgo)
- Logging control functions (debug builds only)

**Key Types and Constants**:
- `SYMMETRIC_KEY_SIZE` (32 bytes)
- `MAX_NONCE` (2^64 - 1)
- `NOISE_MAX_MESSAGE_SIZE` (65535 bytes)
- Enum classes: `CipherAlgo`, `HashAlgo`, `KeyAlgo`
- Type aliases: `PublicKey`, `PrivateKey`, `KeyPair`

**Logging Control** (debug builds only):
- `EnableAllLogging()` / `DisableAllLogging()`
- `EnableTokenProcessing()` / `DisableTokenProcessing()`
- `EnableMessageLogging()` / `DisableMessageLogging()`
- `EnableStateTransitions()` / `DisableStateTransitions()`
- `EnableKeyExchange()` / `DisableKeyExchange()`

See [LoggingAndDebugging.md](LoggingAndDebugging.md) for details.

**Errors.cppm provides**:
- Exception hierarchy for error handling
- All exceptions derive from `NoiseError` (extends `std::runtime_error`)
- Specific error types for handshake, configuration, and protocol errors

### Layer 1: Cryptographic Primitives

Layer 1 contains the cryptographic primitive modules that implement the fundamental building blocks used by the protocol state and handshake layers above.

#### Cipher (`Cipher.cppm`)

Wraps AEAD encryption and decryption. NoisePQC++ supports **ChaCha20-Poly1305** and **AES-256-GCM** through Botan behind a uniform interface that accepts a key, nonce, and associated data. Nonce management is handled primarily by the `CipherState` module. Cipher contexts are reset safely, and key material is wiped when no longer needed.

**Supported Algorithms**:
- ChaCha20-Poly1305 (default)
- AES-256-GCM

**Key Methods**:
- `Encrypt(key, nonce, ad, plaintext)` → ciphertext
- `Decrypt(key, nonce, ad, ciphertext)` → plaintext
- `Reset()` - Clear internal state

**Design Notes**:
- Uses Botan for cryptographic implementations
- 12-byte nonce for ChaCha20-Poly1305
- 16-byte authentication tag

#### Hash (`Hash.cppm`)

Provides hashing, HMAC, and HKDF functionality. The module supports both one-shot and incremental hashing for transcript maintenance and key derivation. The selected hash determines the protocol naming and output sizes used by higher layers.

**Supported Algorithms**:
- SHA-256 (default, 32-byte output)
- SHA-512 (64-byte output)
- BLAKE2b (64-byte output)
- BLAKE2s (32-byte output)

**Key Methods**:
- `Hash(data)` → digest
- `update(data)` - Incremental hashing
- `Reset()` - Clear state for reuse

**Design Notes**:
- Supports both one-shot and incremental hashing
- Output size varies by algorithm
- Used by SymmetricState for key derivation (HKDF)

#### Dh (`Dh.cppm`)

Unifies classical Diffie-Hellman and post-quantum KEM operations behind one interface. The interface exposes key generation, shared-secret derivation for DH, and encapsulation/decapsulation for KEMs. A `KeyAlgo` enum identifies the active algorithm, and higher layers use `IsKEM()` to decide whether to invoke DH or KEM logic. All exchanges produce a 32-byte shared secret, so downstream code can treat DH and KEM outputs uniformly.

**Supported DH Algorithms**:
- X25519 (Curve25519, 32-byte keys)
- X448 (56-byte keys)

**Supported KEM Algorithms (Post-Quantum)**:
- ML-KEM-512 (CRYSTALS-Kyber, 800-byte public key)
- ML-KEM-768 (CRYSTALS-Kyber, 1184-byte public key) - Recommended
- ML-KEM-1024 (CRYSTALS-Kyber, 1568-byte public key)

**Key Methods**:
- `GenerateKeyPair()` → KeyPair{public_key, private_key}
- `DH(private_key, public_key)` → shared_secret (DH algorithms only)
- `Encapsulate(peer_public_key)` → {ciphertext, shared_secret} (KEM algorithms only)
- `Decapsulate(private_key, ciphertext)` → shared_secret (KEM algorithms only)
- `Size()` → shared secret size in bytes
- `PublicKeySize()` → public key size in bytes
- `CiphertextSize()` → KEM ciphertext size (KEM algorithms only)
- `IsKEM()` → true for ML-KEM algorithms, false for DH
- `String()` → algorithm name

**Design Notes**:
- Uses elliptic curve Diffie-Hellman (ECDH) for X25519/X448
- Uses ML-KEM (CRYSTALS-Kyber) for post-quantum key encapsulation
- Provides both span-based and KeyPair-based operations
- KEM operations return 32-byte shared secrets

#### Pattern (`Pattern.cppm`)

Represents handshake patterns as token sequences grouped by message. NoisePQC++ includes all standard classical Noise patterns, the published PQNoise patterns, and labeled HFS variants. Pattern definitions also encode hybrid behavior by combining classical and PQ tokens in a single declarative structure. The module validates token ordering and other pattern constraints before execution.

**NoisePQC++ v0.9.0 implements all Noise patterns including PQ and HFS**:

**Classical Patterns (57 Total)**:

**One-Way Patterns** (3):
- **N, K, X** - Single-message patterns for unidirectional communication

**Fundamental Interactive Patterns** (12):
- **NN, NK, NX** - Initiator unknown patterns (2-3 messages)
- **KN, KK, KX** - Initiator known patterns (2 messages)
- **XN, XK, XX** - Initiator sends static patterns (3 messages)
- **IN, IK, IX** - Immediate identity patterns (2 messages)

**Deferred Patterns** (21):
- Patterns with "1" suffix for deferred static key transmission
- Examples: **NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1**
- **K1N, K1K, KK1, K1K1, K1X, KX1, K1X1**
- **I1N, I1K, IK1, I1K1, I1X, IX1, I1X1**

**PSK (Pre-Shared Key) Patterns** (21):
- Patterns with "psk" modifier for pre-shared key support
- One-way: **Npsk0, Kpsk0, Xpsk1**
- Fundamental: **NNpsk0, NNpsk2, NKpsk0, NKpsk2, NXpsk2**
- **XNpsk3, XKpsk3, XXpsk3**
- **KNpsk0, KNpsk2, KKpsk0, KKpsk2, KXpsk2**
- **INpsk1, INpsk2, IKpsk1, IKpsk2, IXpsk2**

**Post-Quantum Patterns (PQNoise)** (13):
- Replace DH operations with KEM encapsulation/decapsulation
- **pqN, pqNN, pqNK, pqNX, pqXN, pqXK, pqXX, pqKN, pqKK, pqKX, pqIN, pqIK, pqIX**
- Uses `ekem` (encapsulate to ephemeral) and `skem` (encapsulate to static) tokens

**Hybrid Forward Secrecy Patterns (HFS)** (12+):
- Combine classical DH with post-quantum KEM
- All interactive patterns with "hfs" suffix: **NNhfs, NKhfs, NXhfs, XXhfs**, etc.
- Also available with PQ: **pqXXhfs**, etc.
- Uses `e1` (KEM ephemeral key) and `ekem1` (encapsulate to e1) tokens

**Pattern Structure**:
- Pre-message tokens (initiator and responder)
- Message patterns with tokens (e, s, ee, es, se, ss, psk, ekem, skem, e1, ekem1)
- Pattern validation and execution
- PSK modifiers (psk0, psk1, psk2, psk3) indicating where PSK is mixed

**Key Types**:
- `Token` - Pattern tokens: e, s, ee, es, se, ss, psk, ekem, skem, e1, ekem1
- `MessagePattern` - Sequence of tokens for a message
- `HandshakePattern` - Complete pattern with pre-messages and messages

**Pattern Selection**:
See [PatternGuide.md](PatternGuide.md) for comprehensive pattern selection guide with use cases and security properties.

### Layer 2: Protocol State

Layer 2 manages the evolving protocol state during a handshake, tracking the cryptographic material needed for encryption and key derivation.

#### CipherState (`CipherState.cppm`)

Tracks the key and nonce for one AEAD instance. After completion of the handshake, two `CipherState` objects are used for transport encryption, one per direction. The module provides initialization, authenticated encryption/decryption, automatic nonce incrementing, and optional `Rekey()` support for future transport rekeying. It also enforces nonce safety by rejecting overflow.

**Key Responsibilities**:
- Key initialization and management
- Nonce tracking and auto-increment
- Encryption/decryption with automatic nonce handling
- Rekey operations for forward secrecy

**Key Methods**:
- `InitializeKey(key)` - Set the cipher key
- `EncryptWithAd(ad, plaintext)` → ciphertext
- `DecryptWithAd(ad, ciphertext)` → plaintext
- `Rekey(hash_algo)` - Derive new key (forward secrecy)
- `HasKey()` - Check if key is set

**Design Notes**:
- Automatically increments nonce after each operation
- Returns plaintext/ciphertext unchanged if no key is set
- Supports rekeying with configurable hash algorithm

#### SymmetricState (`SymmetricState.cppm`)

Maintains the handshake's **chaining key (`ck`)** and **handshake hash (`h`)**. It is initialized from the protocol name and provides `MixKey()` and `MixHash()` operations, along with helpers such as `MixKeyAndHash()`, `EncryptAndHash()`, and `DecryptAndHash()`. This layer is agnostic to whether input key material comes from DH or KEM; PQ and hybrid integration therefore reduces to mixing the resulting shared secret into `ck`. At handshake completion, `Split()` derives the two transport cipher keys.

**Key Responsibilities**:
- Protocol name initialization
- Chaining key (ck) management
- Handshake hash (h) accumulation
- Key derivation using HKDF
- Splitting into transport keys

**Key Methods**:
- `InitializeSymmetric(protocol_name)` - Initialize with protocol
- `MixKey(input_key_material)` - Derive new keys from IKM
- `MixHash(data)` - Update handshake hash
- `MixKeyAndHash(data)` - Combined operation
- `EncryptAndHash(plaintext)` / `DecryptAndHash(ciphertext)`
- `Split()` → (CipherState1, CipherState2) for transport

**Design Notes**:
- Uses HKDF for key derivation
- Maintains chaining key and hash state
- Agnostic to DH vs. KEM input — treats all shared secrets uniformly
- Produces two CipherStates for bidirectional transport

### Layer 3: Protocol & Handshake

Layer 3 contains the protocol configuration and token processing logic that drives a full handshake.

#### Protocol (`Protocol.cppm`)

Combines a pattern with concrete algorithm choices to form a full protocol configuration. Examples include `Noise_XX_25519_ChaChaPoly_SHA256`, `Noise_pqXX_M768_ChaChaPoly_SHA256`, and `Noise_XXhfs_25519+M768_ChaChaPoly_SHA256`. The `Protocol` class can be built from components or parsed from a string, and it enforces consistency between pattern type and selected algorithms.

**Components**:
- Handshake pattern (XX, pqXX, XXhfs, etc.)
- DH algorithm (X25519, X448)
- KEM algorithm (M512, M768, M1024) - for PQ and HFS patterns
- Cipher algorithm (ChaChaPoly, AESGCM)
- Hash algorithm (SHA256, SHA512, BLAKE2b, BLAKE2s)

**Key Methods**:
- Constructor from components: `Protocol(pattern, dh, cipher, hash)`
- HFS constructor: `Protocol(pattern, dh, kem, cipher, hash)`
- Constructor from string: `Protocol("Noise_XX_25519_ChaChaPoly_SHA256")`
- `String()` → full protocol name
- `IsHFS()` → true if protocol uses HFS (DH + KEM)

**Design Notes**:
- Immutable after construction (all members const)
- String constructor uses parsing with validation
- Supports classical, PQ, and HFS protocol strings
- Modern C++ idioms (no redundant factory methods)

**Protocol String Examples**:
- Classical: `Noise_XX_25519_ChaChaPoly_SHA256`
- Post-Quantum: `Noise_pqXX_M768_ChaChaPoly_SHA256`
- HFS: `Noise_XXhfs_25519+M768_ChaChaPoly_SHA256`

#### HandshakeState (`HandshakeState.cppm`)

Implements the handshake execution and token processing logic. A `HandshakeState` is initialized with a `Protocol`, the required static keys, and optional Pre-Shared Key (PSK) or prologue data, and then advances through the pattern via `WriteMessage()` and `ReadMessage()`.

Internally, it contains:
- A `SymmetricState` for transcript and chaining-key maintenance
- Cipher material used during handshake and later split into transport keys
- The relevant local and remote DH/KEM keys, including ephemeral and optional secondary HFS keys
- Pattern progress state, including message index and sending direction

**Key Methods**:
- `WriteMessage(payload)` → handshake message
- `ReadMessage(message)` → decrypted payload
- `GetStatus()` → HandshakeStatus
- `GetSymmetricState()` → SymmetricState reference

**Key Classes**:
- `HandshakeConfig` - Configuration for handshake setup
- `HandshakeStatus` - Current state with keys and errors
- `HandshakeObserver` - Optional callback for key validation

**Token Processing**: During `WriteMessage()` and `ReadMessage()`, tokens are processed in sequence:
- **`e`** and **`e1`**: Generate and send the required ephemeral public key
- **`s`**: Send the local static public key, encrypted if the pattern requires it
- **`ee`**, **`es`**, **`se`**, **`ss`**: Compute the corresponding DH shared secret and immediately mix it into `SymmetricState`
- **`ekem`** and **`ekem1`**: Encapsulate to the required peer key, append the ciphertext to the message, and mix the resulting shared secret into `SymmetricState`
- **`skem`**: On message reception, decapsulate the received ciphertext with the local static private key and mix the shared secret into `SymmetricState`
- **`psk`**: Mix the pre-shared secret at the required point in the pattern

After token processing, any handshake payload is encrypted or decrypted using `EncryptAndHash()` or `DecryptAndHash()`, ensuring transcript binding and authenticated protection of payload data.

This structure naturally supports hybrid handshakes. If a message contains both classical and PQ tokens, `HandshakeState` executes them in the exact order declared by the pattern and mixes each resulting secret into the chaining key in sequence. Correct ordering is therefore enforced at the pattern level and validated through interoperability tests.

After the final handshake message, `Split()` derives the two transport `CipherState` objects and the handshake transitions to transport mode. Any attempt to continue the handshake after completion raises `HandshakeDoneError`.

**Supported Patterns**:
- **All 57 classical Noise patterns**:
  - 3 one-way patterns (N, K, X)
  - 12 fundamental interactive patterns (NN, NK, NX, KN, KK, KX, XN, XK, XX, IN, IK, IX)
  - 21 deferred patterns (with "1" suffix for deferred static key transmission)
  - 21 PSK patterns (with "psk" modifier for pre-shared keys)
- **Post-Quantum (PQNoise) patterns**:
  - 13 PQ patterns: pqN, pqNN, pqNK, pqNX, pqXN, pqXK, pqXX, pqKN, pqKK, pqKX, pqIN, pqIK, pqIX
  - Uses KEM tokens: `ekem` (encapsulate to ephemeral), `skem` (encapsulate to static)
- **Hybrid Forward Secrecy (HFS) patterns**:
  - All interactive patterns with "hfs" suffix (e.g., XXhfs, NKhfs)
  - Combines DH + KEM for defense-in-depth
  - Uses HFS tokens: `e1` (KEM ephemeral), `ekem1` (encapsulate to e1)

**Design Notes**:
- Provides automatic key management and state transitions
- Non-copyable, non-movable for safety
- Debug version available with detailed state logging (see LoggingAndDebugging.md)

### Layer 4: Application

Layer 4 is the application layer that exposes the NoisePQC++ API to the consumer of the library.

**Module**: `Noise.cppm`

The `Noise.cppm` module serves as the main application-facing facade, re-exporting the public types and functions from the lower layers into a single import for library consumers. Application code imports this module to access protocol configuration, handshake execution, and transport encryption without needing to know the internal module structure.

In total, the implementation spans several thousand lines of C++, excluding Botan. Its layered organization closely follows the conceptual structure of Noise, which helps keep the code modular, extensible, and easier to reason about.

## Design Principles

### 1. Type Safety

- Strong typing prevents mixing incompatible algorithm types
- Enum classes for algorithm selection
- `std::array` for fixed-size keys
- `std::span` for flexible input/output

### 2. Memory Safety

- No raw pointers in public API
- RAII for resource management
- Secure memory wiping using Botan's `secure_scrub_memory()`
- Move semantics for large objects

### 3. Modularity

- Each module has a single responsibility
- Clear dependencies between modules
- Modules can be used independently when appropriate

### 4. Testability

- Every module has comprehensive unit tests using Catch2 v3
- Integration tests for complete handshake flows
- Test vectors from Noise specification
- **Test Suite** (200+ test cases, 500+ assertions):
  - `test_cipher` - Cipher module tests (ChaCha20-Poly1305, AES-GCM)
  - `test_hash` - Hash module tests (SHA256, SHA512, BLAKE2b, BLAKE2s)
  - `test_dh` - DH and KEM module tests (X25519, X448, ML-KEM-512/768/1024)
  - `test_cipherstate` - CipherState module tests
  - `test_symmetricstate` - SymmetricState module tests
  - `test_protocol` - Protocol module tests
  - `test_handshakestate` - Complete handshake tests for all 57 classical patterns
  - `test_noise_pq` - Post-Quantum pattern tests (pqXX, pqNK, etc.)
  - `test_hfs` - Hybrid Forward Secrecy pattern tests (XXhfs, NKhfs, etc.)
  - `test_vectors` - Noise specification test vectors
  - `test_example` - End-to-end handshake demonstration

### 5. Performance

- Zero-copy where possible using `std::span`
- Move semantics to avoid copies
- Efficient key derivation using HKDF
- Minimal allocations in hot paths

## Threading Model

Currently, NoisePQC++ is **not thread-safe**. Design considerations:

- Each `CipherState`, `SymmetricState`, and `HandshakeState` is intended for single-threaded use
- Nonce management requires exclusive access
- Future: Thread-safe wrapper or per-thread instances

## Error Handling

Errors are handled using exceptions defined in `Errors.cppm`:

**Error Classes**:
- `NoiseError` - Base error class
- `HandshakeDoneError` - Signals successful handshake completion
- `OutOfOrderError` - Handshake messages out of sequence
- `TruncatedMessageError` - Incomplete handshake message
- `MessageSizeError` - Message exceeds size limit
- `MissingKeyError` - Required key not provided
- `MissingPSKError` - Pre-shared key missing
- `BadPSKError` - Invalid pre-shared key
- `PreMessageError` - Invalid pre-message token
- `InvalidTokenError` - Unknown pattern token
- `ProtocolNotSupportedError` - Invalid protocol specification

**Error Categories**:
- Invalid key sizes
- Nonce overflow
- Authentication failures (from Botan)
- Protocol violations
- Handshake state errors

## Cryptographic Implementation

All cryptographic operations are delegated to **Botan**:
- Battle-tested implementations
- Platform-optimized (SIMD, AES-NI)
- Constant-time operations
- Memory wiping

**Platform Support**:
- macOS x86_64
- Linux x86_64
- Linux ARM64 (Raspberry Pi)
- Windows x86_64

## Current Status (v0.9.0)

NoisePQC++ v0.9.0 represents a **complete implementation** of the Noise Protocol Framework with Post-Quantum Cryptography (PQC) and Hybrid Forward Secrecy (HFS) support, featuring performance-optimized direct buffer operations and comprehensive benchmarking capabilities.

**Completed Features**:
- ✅ All 57 classical Noise handshake patterns (one-way, interactive, deferred, PSK)
- ✅ Post-Quantum patterns with ML-KEM (pqNN, pqNK, pqXX, etc.)
- ✅ Hybrid Forward Secrecy patterns (XXhfs, NKhfs, etc.)
- ✅ Complete cryptographic primitives (Cipher, Hash, DH, KEM)
- ✅ ML-KEM-512/768/1024 key encapsulation support
- ✅ Full state management (CipherState, SymmetricState, HandshakeState)
- ✅ Observer pattern for key validation
- ✅ Prologue support
- ✅ Pre-shared key (PSK) modes (21 patterns)
- ✅ Deferred patterns (21 patterns)
- ✅ ASIO networking examples (TCP client/server)
- ✅ Comprehensive test suite (200+ test cases, 500+ assertions)
- ✅ Debug builds with detailed state logging
- ✅ Cross-platform support (macOS, Linux x86_64/ARM64, Windows)

## Future Enhancements

### Additional Features (Under Consideration)

- **Fallback patterns** - For version negotiation and protocol upgrade
- **Rekey support** - Periodic key refresh for long-lived connections
- **Multi-algorithm handshakes** - Different DH per message (advanced patterns)

## Dependencies

```
NoisePQC++ v0.9.0
├── Botan 3.10.0 (third_party/botan/)
│   ├── ChaCha20-Poly1305 (AEAD cipher)
│   ├── AES-256-GCM (AEAD cipher)
│   ├── SHA-256/512 (hash functions)
│   ├── BLAKE2b/s (hash functions)
│   ├── HKDF (key derivation)
│   ├── X25519/X448 (key exchange)
│   ├── ML-KEM-512/768/1024 (post-quantum key encapsulation)
│   └── Secure memory operations
└── nlohmann/json (third_party/nlohmann/, header-only)
    └── Test vector and fixture parsing (testdata/*.json)

Tests & Examples
└── Catch2 v3.11.0 (auto-downloaded via FetchContent)

Benchmarks
└── Google Benchmark v1.9.1 (auto-downloaded via FetchContent)

Networking Examples
└── ASIO (standalone, header-only)
```

**Build System**:
- CMake 4.0+ (required for C++ modules)
- Ninja (required for C++ modules)
- Clang 18+ or GCC 15.2+ or MSVC 19.44+

**Platform-Specific Botan 3.10.0 Builds**:
Minimized build source included for:
- macOS (x86_64, ARM64) with Clang 18
- Linux (x86_64, ARM64) with Clang 18 and GCC 15.2
- Windows (x86_64) with MSVC 19.44+

## Performance Characteristics

### Cipher Performance

- **ChaCha20-Poly1305**: ~1-3 GB/s (software)
- **AES-256-GCM**: ~2-5 GB/s (with AES-NI)

### Hash Performance

- **SHA-256**: ~200-400 MB/s
- **BLAKE2b**: ~500-1000 MB/s

### DH Performance

- **X25519**: ~100k operations/sec
- **X448**: ~20k operations/sec

### KEM Performance (Post-Quantum)

- **ML-KEM-768 KeyGen**: ~50k operations/sec
- **ML-KEM-768 Encapsulation**: ~50k operations/sec
- **ML-KEM-768 Decapsulation**: ~30k operations/sec

*Note: Actual performance depends on hardware and optimization flags*

## References

### NoisePQC++ Documentation

- [Pattern Guide](PatternGuide.md) - Complete guide to all 57 Noise patterns with selection guide and use cases
- [API Reference](API.md) - Complete API documentation with examples
- [Build Guide](BuildGuide.md) - Platform-specific build instructions and testing
- [Logging and Debugging Guide](LoggingAndDebugging.md) - Debug builds and state transition logging

### Noise Protocol

- [Noise Protocol Framework Specification](https://noiseprotocol.org/noise.html) - Official specification

### Cryptography

- [Botan Handbook](https://botan.randombit.net/handbook/)
