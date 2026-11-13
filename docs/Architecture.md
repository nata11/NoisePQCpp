# Architecture

**Version**: 1.1.0
**Last Updated**: 2026-11-13

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
│  │                    Botan 3.13.0                            │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Layer Descriptions

### Layer 0: Common Utilities & Errors

**Modules**: `Common.cppm`, `Errors.cppm`

Layer 0 provides shared utilities and error handling. The `Common` module defines core types (byte arrays, spans, etc.), constants, and algorithm identifiers, along with compile-time options and logging controls. The `Errors` module defines the exception hierarchy, including `NoiseError` and specific subclasses such as `InvalidTokenError` and `DecryptionError`, to provide explicit failure modes for malformed messages and cryptographic errors.

**Common.cppm provides**:
- Common types, constants, and enumerations
- Platform-independent type definitions
- Constants for key sizes, nonce limits, etc.
- Algorithm enumerations (CipherAlgo, HashAlgo, KeyAlgo)
- Logging control functions (no-ops when `NOISE_DEBUG_BUILD` is OFF)

**Key Types and Constants**:
- `SYMMETRIC_KEY_SIZE` (32 bytes)
- `MAX_NONCE` (2^64 - 1)
- `NOISE_MAX_MESSAGE_SIZE` (65535 bytes)
- Enum classes: `CipherAlgo`, `HashAlgo`, `KeyAlgo`
- Type aliases `PublicKey`, `PrivateKey` and the `KeyPair` struct (in `Dh.cppm`)

**Logging Control** (no-ops when `NOISE_DEBUG_BUILD` is OFF):
- `EnableAllLogging()` / `DisableAllLogging()`
- `SetHandshakeLogging(bool)`
- `SetSymmetricLogging(bool)`

See [LoggingAndDebugging.md](LoggingAndDebugging.md) for details.

**Errors.cppm provides**:
- Exception hierarchy for error handling
- All library errors derive from `NoiseError` (which extends `std::runtime_error`); `Exit` is the examples' exit signal
- Specific error types for handshake, configuration, and protocol errors

### Layer 1: Cryptographic Primitives

Layer 1 contains the cryptographic primitive modules that implement the fundamental building blocks used by the protocol state and handshake layers above.

#### Cipher (`Cipher.cppm`)

Wraps AEAD encryption and decryption. NoisePQC++ supports **ChaCha20-Poly1305** and **AES-256-GCM** through Botan behind a uniform interface that accepts a key, nonce, and associated data. Nonce management is handled primarily by the `CipherState` module. Cipher contexts are reset safely, and key material is wiped when no longer needed.

**Supported Algorithms**:
- ChaCha20-Poly1305 (default)
- AES-256-GCM

**Key Methods**:
- `Encrypt(dst, key, nonce, ad, plaintext)` / `Decrypt(dst, key, nonce, ad, ciphertext)` - Append the result to `dst`
- `GetAeadTagSize()` - Tag size in bytes
- `String()` - Algorithm name
- `Reset()` - Clear internal state

**Design Notes**:
- Uses Botan for cryptographic implementations
- 12-byte nonce for ChaCha20-Poly1305
- 16-byte authentication tag

#### Hash (`Hash.cppm`)

Wraps the four Noise hash functions; HMAC and HKDF are computed in `SymmetricState`. The selected hash determines the protocol naming and output sizes used by higher layers.

**Supported Algorithms**:
- SHA-256 (default, 32-byte output)
- SHA-512 (64-byte output)
- BLAKE2b (64-byte output)
- BLAKE2s (32-byte output)

**Key Methods**:
- `String()` → algorithm name
- `Size()` → output length in bytes (HASHLEN)
- `hash_function` - The Botan hash object, for one-shot or incremental hashing

**Design Notes**:
- Supports both one-shot and incremental hashing
- Output size varies by algorithm
- Used by SymmetricState for key derivation (HKDF)

#### Dh (`Dh.cppm`)

Unifies classical Diffie-Hellman and post-quantum KEM operations behind one interface. The interface exposes key generation, shared-secret derivation for DH, and encapsulation/decapsulation for KEMs. A `KeyAlgo` enum identifies the active algorithm, resolved from the Noise name through the `Common` `KeyAlgos` table at construction (as `Cipher` and `Hash` resolve theirs); the key sizes and the ML-KEM mode are fixed there too, so no operation compares strings. Higher layers use `IsKEM()` to decide whether to invoke DH or KEM logic. Shared secrets are 32 bytes (56 for X448), and downstream code treats DH and KEM outputs uniformly. A loaded-key handle (`DhPrivateKey`, from `LoadPrivateKey()` or `GenerateKeypairWithKey()`) keeps a DH private key's Botan object alive across agreements, so `HandshakeState` derives each local public key once per handshake and every DH token costs one scalar multiplication instead of two. A decoded-key handle (`KemPublicKey`, from `LoadPublicKey()`) keeps a received ML-KEM key's Botan object, so `HandshakeState` decodes and checks each received key once, at the `ReadMessage` that carries it, and encapsulates to the kept key.

**Supported DH Algorithms**:
- X25519 (Curve25519, 32-byte keys)
- X448 (56-byte keys)

**Supported KEM Algorithms (Post-Quantum)**:
- ML-KEM-512 (CRYSTALS-Kyber, 800-byte public key)
- ML-KEM-768 (CRYSTALS-Kyber, 1184-byte public key) - Recommended
- ML-KEM-1024 (CRYSTALS-Kyber, 1568-byte public key)

**Key Methods**:
- `GenerateKeypair()` → KeyPair{public_key, private_key}
- `DH(private_key, public_key)` → shared_secret (DH algorithms only)
- `LoadPrivateKey(private_key)` / `GenerateKeypairWithKey()` → `DhPrivateKey`; `DH(DhPrivateKey, public_key)` → shared_secret with one multiplication (DH algorithms only)
- `LoadPublicKey(public_key)` → `KemPublicKey`; `Encapsulate(KemPublicKey)` → {ciphertext, shared_secret} with no second decode (KEM algorithms only)
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
- Provides span-based, `KeyPair`-based and loaded-key (handle) operations
- KEM operations return 32-byte shared secrets

#### Pattern (`Pattern.cppm`)

Represents handshake patterns as token sequences grouped by message. NoisePQC++ includes all standard classical Noise patterns, the published PQNoise patterns, and labeled HFS variants. Pattern definitions also encode hybrid behavior by combining classical and PQ tokens in a single declarative structure. The module validates token ordering and other pattern constraints before execution.

**NoisePQC++ v1.1.0 implements all Noise patterns including PQ and HFS**:

**Classical Patterns (59 Total: 3 one-way + 12 interactive + 23 deferred + 21 PSK)**:

**One-Way Patterns** (3):
- **N, K, X** - Single-message patterns for unidirectional communication

**Fundamental Interactive Patterns** (12):
- **NN, NK, NX** - Initiator unknown patterns (2 messages)
- **KN, KK, KX** - Initiator known patterns (2 messages)
- **XN, XK, XX** - Initiator sends static patterns (3 messages)
- **IN, IK, IX** - Immediate identity patterns (2 messages)

**Deferred Patterns** (23):
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

**Hybrid Forward Secrecy Patterns (HFS)** (35: 12 interactive + 23 deferred):
- Combine classical DH with post-quantum KEM
- All interactive patterns with "hfs" suffix: **NNhfs, NKhfs, NXhfs, XXhfs**, etc.
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

Tracks the key and nonce for one AEAD instance. After completion of the handshake, two `CipherState` objects are used for transport encryption, one per direction. The module provides initialization, authenticated encryption/decryption, automatic nonce incrementing, and optional `Rekey()` support for future transport rekeying. It also enforces nonce safety: it rejects the reserved nonce 2⁶⁴−1 (Noise spec Section 5.1) with `NonceExhaustedError`, and bounds every transport message by `maxMessageSize` with `MessageSizeError`.

**Key Responsibilities**:
- Key initialization and management
- Nonce tracking and auto-increment
- Encryption/decryption with automatic nonce handling
- Rekey (Noise spec Section 4.2 REKEY) for forward secrecy

**Key Methods**:
- `InitializeKey(key)` - Set the cipher key
- `EncryptWithAd(ad, plaintext)` → ciphertext
- `DecryptWithAd(ad, ciphertext)` → plaintext
- `Rekey()` - Replace the key with REKEY(k) = ENCRYPT(k, 2⁶⁴−1, zerolen, zeros)[0..32) (forward secrecy; nonce unchanged)
- `HasKey()` - Check if key is set

**Design Notes**:
- Automatically increments nonce after each operation
- Returns plaintext/ciphertext unchanged if no key is set
- Rekey uses the cipher itself (Noise spec Section 4.2's default REKEY)

#### SymmetricState (`SymmetricState.cppm`)

Maintains the handshake's **chaining key (`ck`)** and **handshake hash (`h`)**. It is initialized from the protocol name and provides `MixKey()` and `MixHash()` operations, along with helpers such as `MixKeyAndHash()`, `EncryptAndHash()`, and `DecryptAndHash()`. This layer is agnostic to whether input key material comes from DH or KEM; PQ and hybrid integration therefore reduces to mixing the resulting shared secret into `ck`. At handshake completion, `Split()` derives the two transport cipher keys. The chaining key is scrubbed when the `SymmetricState` is destroyed, and each `CipherState` scrubs its key when it is destroyed. Each `SymmetricState` owns a clone of the protocol's hash function, so no handshake mutates the shared `Protocol`.

**Key Responsibilities**:
- Protocol name initialization
- Chaining key (ck) management
- Handshake hash (h) accumulation
- Key derivation using HKDF, computed in the state as Noise spec Section 4.3 writes it (three HMAC calls) with one HMAC object owned per `SymmetricState`; no per-derivation Botan factory call
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

Combines a pattern with concrete algorithm choices to form a full protocol configuration. Examples include `Noise_XX_25519_ChaChaPoly_SHA256`, `Noise_pqXX_M768_ChaChaPoly_SHA256`, and `Noise_XXhfs_25519+M768_ChaChaPoly_SHA256`. The `Protocol` class can be built from components or parsed from a string. Every field is allowlisted at construction: the pattern must be in the registry (HFS names are looked up in full, so only the 35 registered `hfs` patterns parse), and the algorithm names must be exactly the Noise set (`25519`, `448`, `M512`, `M768`, `M1024`; `ChaChaPoly`, `AESGCM`; `SHA256`, `SHA512`, `BLAKE2b`, `BLAKE2s`), resolved through the `Common` tables before any Botan call. The constructors also enforce consistency between the pattern's tokens and the algorithms (DH tokens need a DH, KEM tokens need a KEM, `e1`/`ekem1` need an HFS KEM), throwing `ProtocolNotSupportedError` instead of failing mid-handshake.

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
- **`ekem`**, **`skem`** and **`ekem1`**: the writer encapsulates to the peer's ephemeral, static or `e1` key and appends the ciphertext; the reader decapsulates it with its own private key; both mix the shared secret into `SymmetricState`
- **`psk`**: Mix the pre-shared secret at the required point in the pattern

After token processing, any handshake payload is encrypted or decrypted using `EncryptAndHash()` or `DecryptAndHash()`, ensuring transcript binding and authenticated protection of payload data.

This structure naturally supports hybrid handshakes. If a message contains both classical and PQ tokens, `HandshakeState` executes them in the exact order declared by the pattern and mixes each resulting secret into the chaining key in sequence. Correct ordering is therefore enforced at the pattern level and checked by the HFS tests (`test_hfs.cpp`).

After the final handshake message, `Split()` derives the two transport `CipherState` objects and the handshake transitions to transport mode. Completion is signaled without an exception: the final call returns normally, `HandshakeStatus::state` becomes `Done` (and `err` holds a `HandshakeComplete`, the documented tri-state), `IsComplete()`/`HasError()` read `state` without rethrowing, and `TakeCipherStates()` moves the two transport states out. Any attempt to continue the handshake after completion raises `HandshakeComplete`. At that point `Reset()` scrubs the library's copies of the chaining key and of all local keypairs (including the HFS `e1` decapsulation key); every DH/KEM shared secret is scrubbed by its token handler as soon as it has been mixed in. The caller's `HandshakeConfig` is never touched.

**Supported Patterns**:
- **All 59 classical Noise patterns**:
  - 3 one-way patterns (N, K, X)
  - 12 fundamental interactive patterns (NN, NK, NX, KN, KK, KX, XN, XK, XX, IN, IK, IX)
  - 23 deferred patterns (with "1" suffix for deferred static key transmission)
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

- No owning raw pointers in the public API (the optional observer is a non-owning pointer)
- RAII for resource management
- Secure memory wiping using Botan's `secure_scrub_memory()`: `CipherState` and `SymmetricState` scrub their key and chaining key on destruction, `HandshakeState` scrubs shared secrets after use and local keypairs at completion; the caller owns the keys and PSKs it passes in `HandshakeConfig`
- Move semantics for large objects

### 3. Modularity

- Each module has a single responsibility
- Clear dependencies between modules
- Modules can be used independently when appropriate

### 4. Testability

- Every module has comprehensive unit tests using Catch2 v3
- Integration tests for complete handshake flows
- Cacophony test vectors
- **Test Suite** (374 test cases):
  - `test_cipher` - Cipher module tests (ChaCha20-Poly1305, AES-GCM)
  - `test_hash` - Hash module tests (SHA256, SHA512, BLAKE2b, BLAKE2s)
  - `test_dh` - DH and KEM module tests (X25519, X448, ML-KEM-512/768/1024)
  - `test_cipherstate` - CipherState module tests
  - `test_symmetricstate` - SymmetricState module tests
  - `test_protocol` - Protocol module tests
  - `test_pattern` - Built-in pattern validation
  - `test_handshakestate` - Complete handshake tests for all 59 classical patterns
  - `test_noise_pq` - Post-Quantum pattern tests (pqXX, pqNK, etc.)
  - `test_hfs` - Hybrid Forward Secrecy pattern tests (XXhfs, NKhfs, etc.)
  - `test_vectors` - Cacophony test vectors
  - `test_wiping` - Secret material is wiped before its memory is freed
  - `test_example` - End-to-end handshake demonstration

### 5. Performance

- Zero-copy where possible using `std::span`
- Move semantics to avoid copies
- Efficient key derivation using HKDF
- Minimal allocations in hot paths

## Threading Model

NoisePQC++ has no internal locking. Design considerations:

- Each `CipherState`, `SymmetricState`, and `HandshakeState` is intended for single-threaded use
- Nonce management requires exclusive access
- A `Protocol` is immutable after construction: every `SymmetricState` owns a clone of the protocol's hash and every `CipherState` its own cipher copy, so one `Protocol` can be shared by handshakes on different threads (each thread with its own `HandshakeState`)
- Future: Thread-safe wrapper or per-thread instances

## Error Handling

Errors are handled using exceptions defined in `Errors.cppm`:

**Error Classes**:
- `NoiseError` - Base error class
- `HandshakeComplete` - The completion marker stored in `HandshakeStatus::err` when the handshake completes; thrown only by a call made after completion (not an error)
- `OutOfOrderError` - Handshake messages out of sequence
- `TruncatedMessageError` - Incomplete handshake message
- `MessageSizeError` - Handshake or transport message exceeds size limit
- `DecryptionError` - AEAD tag verification failed, or ciphertext shorter than the tag
- `NonceExhaustedError` - Nonce reached the reserved value 2^64 - 1
- `InvalidPublicKeyError` - Peer public key rejected: low-order DH point, ML-KEM key failing the FIPS 203 check, or wrong length
- `MissingKeyError` - Required key not provided
- `MissingPSKError` - Pre-shared key missing
- `BadPSKError` - Invalid pre-shared key
- `PreMessageError` - Invalid pre-message token
- `InvalidTokenError` - Unknown pattern token
- `ProtocolNotSupportedError` - Invalid protocol specification

**Error Categories**:
- Invalid key sizes
- Nonce overflow
- Authentication failures (`DecryptionError`; Botan types never escape)
- Unknown algorithm or pattern names, incompatible combinations (`ProtocolNotSupportedError`)
- Protocol violations
- Handshake state errors

## Cryptographic Implementation

All cryptographic operations are delegated to **Botan**:
- Battle-tested implementations
- Platform-optimized (SIMD, AES-NI) where Botan detects the CPU features; see [ISA baseline, optimization and linking](BuildGuide.md#isa-baseline-optimization-and-linking)
- Constant-time operations
- Memory wiping

**Platform Support**:
- macOS ARM64 (Apple Silicon)
- Linux x86_64
- Linux ARM64 (Raspberry Pi)
- Windows x86_64

## Current Status (v1.1.0)

NoisePQC++ v1.1.0 represents a **complete implementation** of the Noise Protocol Framework with Post-Quantum Cryptography (PQC) and Hybrid Forward Secrecy (HFS) support, featuring performance-optimized direct buffer operations and comprehensive benchmarking capabilities.

**Completed Features**:
- ✅ All 59 classical Noise handshake patterns (3 one-way + 12 interactive + 23 deferred + 21 PSK)
- ✅ Post-Quantum patterns with ML-KEM (pqNN, pqNK, pqXX, etc.)
- ✅ Hybrid Forward Secrecy patterns (XXhfs, NKhfs, etc.)
- ✅ Complete cryptographic primitives (Cipher, Hash, DH, KEM)
- ✅ ML-KEM-512/768/1024 key encapsulation support
- ✅ Full state management (CipherState, SymmetricState, HandshakeState)
- ✅ Observer pattern for key validation
- ✅ Prologue support
- ✅ Pre-shared key (PSK) modes (21 patterns)
- ✅ Deferred patterns (23 patterns)
- ✅ ASIO networking examples (TCP client/server)
- ✅ Comprehensive test suite (374 test cases)
- ✅ Debug builds with detailed state logging
- ✅ Cross-platform support (macOS, Linux x86_64/ARM64, Windows)

## Future Enhancements

### Additional Features (Under Consideration)

- **Fallback patterns** - For version negotiation and protocol upgrade
- **Automatic rekeying** - `CipherState::Rekey()` exists; a periodic rekey policy for long-lived connections does not
- **Multi-algorithm handshakes** - Different DH per message (advanced patterns)

## Dependencies

```
NoisePQC++ v1.1.0
├── Botan 3.13.0 (third_party/botan/)
│   ├── ChaCha20-Poly1305 (AEAD cipher)
│   ├── AES-256-GCM (AEAD cipher)
│   ├── SHA-256/512 (hash functions)
│   ├── BLAKE2b/s (hash functions)
│   ├── HMAC (HKDF is computed in SymmetricState)
│   ├── X25519/X448 (key exchange)
│   ├── ML-KEM-512/768/1024 (post-quantum key encapsulation)
│   └── Secure memory operations
└── nlohmann/json (third_party/nlohmann/, header-only)
    └── Test vector and fixture parsing (testdata/*.json)

Tests
└── Catch2 v3.16.1 (auto-downloaded via FetchContent)

Benchmarks
└── Google Benchmark v1.10.0 (auto-downloaded via FetchContent)

Networking examples and network benchmarks
└── ASIO 1.39.0 (standalone, compiled once into asio_static)
```

**Build System**:
- CMake 4.3+ (required for C++ modules)
- Ninja (required for C++ modules)
- Clang 21 or GCC 15.2+ or MSVC 19.44+

**Platform-Specific Botan 3.13.0 Builds**:
Minimized build source included for:
- macOS (ARM64) with Clang 21
- Linux (x86_64, ARM64) with Clang 21 and GCC 15.2
- Windows (x86_64) with MSVC 19.44+

## Performance Characteristics

Measure on your own hardware with the benchmark suite; see the [Benchmarking Guide](BenchmarkingGuide.md).

## References

### NoisePQC++ Documentation

- [Pattern Guide](PatternGuide.md) - Guide to the classical, PQ and HFS patterns with selection guide and use cases
- [API Reference](API.md) - Complete API documentation with examples
- [Build Guide](BuildGuide.md) - Platform-specific build instructions and testing
- [Logging and Debugging Guide](LoggingAndDebugging.md) - Debug builds and state transition logging

### Noise Protocol

- [Noise Protocol Framework Specification](https://noiseprotocol.org/noise.html) - Official specification

### Cryptography

- [Botan Handbook](https://botan.randombit.net/handbook/)
