# NoisePQC++ Test Suite

This directory contains the comprehensive test suite for NoisePQC++ v1.1.0 using Catch2 v3.16.1.

**Total Test Coverage**: 374 test cases across all Noise Protocol Framework components, including classical, post-quantum, and hybrid patterns.

## Structure

```
tests/
├── README.md                  # This file
├── CMakeLists.txt             # CMake target definitions for the test suite
├── test_cipher.cpp            # Cipher module tests (AEAD operations)
├── test_cipherstate.cpp       # CipherState module tests (nonce, rekey, encryption)
├── test_dh.cpp                # DH and KEM module tests (X25519, X448, ML-KEM)
├── test_hash.cpp              # Hash module tests (SHA-256, SHA-512, BLAKE2b/s)
├── test_symmetricstate.cpp    # SymmetricState module tests (HKDF, key derivation)
├── test_protocol.cpp          # Protocol module tests (protocol string parsing)
├── test_pattern.cpp           # Pattern module tests (pattern definitions)
├── test_handshakestate.cpp    # HandshakeState tests (all 59 classical patterns)
├── test_noise_pq.cpp          # Post-Quantum pattern tests (pqXX, pqNK, etc.)
├── test_hfs.cpp               # Hybrid Forward Secrecy tests (XXhfs, NKhfs, etc.)
├── test_example.cpp           # Example integration tests
├── test_vectors.cpp           # Cacophony test vectors
└── test_wiping.cpp            # Secret wiping before memory is freed
```

## Building Tests

**Note**: Catch2 v3.16.1 is downloaded automatically via CMake FetchContent on the first configure of a build tree.

### Build All Tests

```bash
# From project root

# Configure with the appropriate toolchain file for your platform:
#   - macOS (Apple Silicon): cmake/clang21-macOS-toolchain.cmake
#   - Linux incl. Raspberry Pi 5 (Clang 21): cmake/clang21-linux-toolchain.cmake
#   - Linux (GCC 15.2+): cmake/gcc15-linux-toolchain.cmake
#   - Windows (MSVC): No toolchain file needed

# Example for macOS:
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-macOS-toolchain.cmake

# Example for Linux with Clang:
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-linux-toolchain.cmake

# Build all targets
cmake --build build

# Or build just the tests
cmake --build build --target test_cipher test_cipherstate test_dh test_hash \
  test_symmetricstate test_protocol test_pattern test_handshakestate \
  test_noise_pq test_hfs test_example test_vectors test_wiping
```

## Running Tests

### Run All Tests via CTest

```bash
ctest --test-dir build --output-on-failure

# Or with verbose output
ctest --test-dir build -V

# Run tests in parallel (faster)
ctest --test-dir build -j$(nproc)
```

### Run Individual Test Executables

Paths are for a single-config build; with Ninja Multi-Config, use `build/bin/<Config>/tests/`.

```bash
# Core module tests
./build/bin/tests/test_cipher
./build/bin/tests/test_cipherstate
./build/bin/tests/test_dh
./build/bin/tests/test_hash
./build/bin/tests/test_symmetricstate
./build/bin/tests/test_protocol
./build/bin/tests/test_pattern

# Comprehensive tests
./build/bin/tests/test_handshakestate  # All 59 classical Noise patterns
./build/bin/tests/test_noise_pq        # Post-Quantum patterns (pqXX, pqNK, etc.)
./build/bin/tests/test_hfs             # Hybrid Forward Secrecy patterns
./build/bin/tests/test_vectors         # Cacophony test vectors
./build/bin/tests/test_wiping          # Secret wiping
./build/bin/tests/test_example         # Integration examples
```

### Run Specific Tests via CTest

```bash
# CTest names each test after its Catch2 test case (for example "Cipher - ...")
ctest --test-dir build -R "^Cipher - "        # Only cipher tests
ctest --test-dir build -R "^HandshakeState"   # Only handshake tests

# Run with detailed output
ctest --test-dir build -R "^Dh - " --verbose
```

### Run Specific Test Cases
```bash
# Cipher module tests
./build/bin/tests/test_cipher "[encryption]"           # Run only encryption tests
./build/bin/tests/test_cipher "[chacha]"               # Run only ChaCha20 tests
./build/bin/tests/test_cipher "[aesgcm]"               # Run only AES-GCM tests
./build/bin/tests/test_cipher "[security]"             # Run security-related tests

# CipherState module tests
./build/bin/tests/test_cipherstate "[nonce]"           # Run nonce-related tests
./build/bin/tests/test_cipherstate "[rekey]"           # Run rekey tests
./build/bin/tests/test_cipherstate "[roundtrip]"       # Run encryption/decryption roundtrip tests

# Dh module tests
./build/bin/tests/test_dh "[keygen]"                   # Run key generation tests
./build/bin/tests/test_dh "[dh-operation]"             # Run DH operation tests
./build/bin/tests/test_dh "[x25519]"                   # Run X25519 specific tests
./build/bin/tests/test_dh "[x448]"                     # Run X448 specific tests

# Hash module tests
./build/bin/tests/test_hash "[hashing]"                # Run hashing tests
./build/bin/tests/test_hash "[sha256]"                 # Run SHA-256 specific tests
./build/bin/tests/test_hash "[blake2b]"                # Run BLAKE2b specific tests
./build/bin/tests/test_hash "[test-vector]"            # Run known test vector tests

# SymmetricState module tests
./build/bin/tests/test_symmetricstate "[initialize]"   # Run initialization tests
./build/bin/tests/test_symmetricstate "[mixkey]"       # Run MixKey tests
./build/bin/tests/test_symmetricstate "[encrypt]"      # Run encryption tests
./build/bin/tests/test_symmetricstate "[split]"        # Run Split tests
./build/bin/tests/test_symmetricstate "[integration]"  # Run integration tests

# List all test cases for a module
./build/bin/tests/test_cipher --list-tests
./build/bin/tests/test_dh --list-tests
./build/bin/tests/test_symmetricstate --list-tests

# List all tags
./build/bin/tests/test_cipher --list-tags
```

## Test Coverage

### Cipher Module Tests (`test_cipher.cpp`)
- ✅ Default and explicit constructors (string and enum)
- ✅ Copy and move constructors
- ✅ Encryption and decryption with ChaCha20-Poly1305
- ✅ Encryption and decryption with AES-256-GCM
- ✅ Associated data handling
- ✅ Nonce variation
- ✅ Key variation
- ✅ Reset functionality
- ✅ Edge cases (empty plaintext, large plaintext)
- ✅ Security tests (wrong key, wrong nonce, tampered ciphertext)
- ✅ Utility methods (String(), GetAeadTagSize())

### CipherState Module Tests (`test_cipherstate.cpp`)
- ✅ Default, copy, and move constructors
- ✅ Key initialization and management
- ✅ Nonce management and incrementation
- ✅ Encryption and decryption with and without keys
- ✅ Associated data handling
- ✅ Rekey (Noise spec Section 4.2 REKEY)
- ✅ Reset functionality
- ✅ Edge cases (empty plaintext, large plaintext)
- ✅ Multiple sequential encryptions
- ✅ std::span compatibility
- ✅ Works with both ChaCha20-Poly1305 and AES-256-GCM

### Dh Module Tests (`test_dh.cpp`)
- ✅ Default and explicit constructors (string and enum)
- ✅ Copy and move constructors
- ✅ Key generation for X25519 and X448
- ✅ Correct key lengths (32 bytes for X25519, 56 bytes for X448)
- ✅ DH operation (Diffie-Hellman key exchange)
- ✅ Shared secret computation
- ✅ Both parties compute same shared secret
- ✅ KeyPair struct and IsEmpty() method
- ✅ Different algorithms produce different key sizes
- ✅ Deterministic output for same inputs
- ✅ Security properties (different peers, shared secret uniqueness)
- ✅ Edge cases (mismatched key lengths, zero keys)
- ✅ Utility methods (String(), PrintKeys())
- ✅ **ML-KEM-512/768/1024 key generation**
- ✅ **KEM encapsulation and decapsulation**
- ✅ **Correct KEM key sizes (800/1184/1568 bytes public key)**
- ✅ **Correct ciphertext sizes (768/1088/1568 bytes)**
- ✅ **IsKEM() method distinguishes DH from KEM**
- ✅ **KEM shared secret computation**

### Hash Module Tests (`test_hash.cpp`)
- ✅ Default and explicit constructors (string and enum)
- ✅ Copy and move constructors
- ✅ Support for SHA-256, SHA-512, BLAKE2b, and BLAKE2s
- ✅ Correct hash output lengths
- ✅ Basic hashing functionality for all algorithms
- ✅ Deterministic output (same input → same hash)
- ✅ Collision resistance (different inputs → different hashes)
- ✅ Edge cases (empty input, large input, all zeros, all ones)
- ✅ Single byte sensitivity
- ✅ Incremental hashing with update()
- ✅ Known test vectors (SHA-256)
- ✅ Multiple hashes with same Hash object
- ✅ Copy constructor independence
- ✅ Utility methods (String(), Size())

### SymmetricState Module Tests (`test_symmetricstate.cpp`)
- ✅ Default, copy, and move constructors
- ✅ Support for different hash algorithms (SHA-256, SHA-512, BLAKE2b, BLAKE2s)
- ✅ InitializeSymmetric with short and long protocol names
- ✅ MixKey functionality and key derivation
- ✅ MixHash functionality and hash accumulation
- ✅ MixKeyAndHash combined operations
- ✅ EncryptAndHash and DecryptAndHash
- ✅ GetHandshakeHash retrieval
- ✅ Split operation for transport keys
- ✅ Complete handshake simulation (integration test)
- ✅ Edge cases (empty protocol name, no key encryption, large data)
- ✅ Compatibility with different cipher and hash algorithms
- ✅ State synchronization between parties
- ✅ Multiple sequential MixHash operations
- ✅ Transport key generation and uniqueness

### Protocol Module Tests (`test_protocol.cpp`)
- ✅ Constructor with individual parameters (pattern, DH, cipher, hash)
- ✅ Constructor with protocol string parsing
- ✅ String() method round-trip testing
- ✅ All pattern combinations (XX, NN, KK, NK)
- ✅ All DH algorithm combinations (X25519, X448)
- ✅ All cipher combinations (ChaCha20-Poly1305, AES-256-GCM)
- ✅ All hash combinations (SHA-256, SHA-512, BLAKE2b, BLAKE2s)
- ✅ Invalid protocol string error handling
- ✅ Pattern describe() method (outputs formatted pattern structure)
- ✅ Comprehensive combination testing (64 protocol combinations)
- ✅ HFS protocol strings, all DH+KEM combinations and the deferred HFS patterns
- ✅ Rejection of non-Noise names, unregistered HFS names, malformed DH+KEM forms and incompatible combinations
- ✅ `String()` for every registry pattern

### Pattern Module Tests (`test_pattern.cpp`)
- ✅ Every registry pattern passes `HandshakePattern::IsValid` (all 107: 59 classical, 13 PQ, 35 HFS)
- ✅ The one-way flag matches the message count

### HandshakeState Module Tests (`test_handshakestate.cpp`)
- ✅ **All 59 classical patterns** (3 one-way + 12 interactive + 23 deferred + 21 PSK)
  - 3 one-way patterns (N, K, X)
  - 12 fundamental interactive patterns (NN, NK, NX, KN, KK, KX, XN, XK, XX, IN, IK, IX)
  - 23 deferred patterns (NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1, K1N, K1K, KK1, K1K1, K1X, KX1, K1X1, I1N, I1K, IK1, I1K1, I1X, IX1, I1X1)
  - 21 PSK patterns (Npsk0, Kpsk0, Xpsk1, NNpsk0, NNpsk2, NKpsk0, NKpsk2, NXpsk2, XNpsk3, XKpsk3, XXpsk3, KNpsk0, KNpsk2, KKpsk0, KKpsk2, KXpsk2, INpsk1, INpsk2, IKpsk1, IKpsk2, IXpsk2)
- ✅ Pattern-specific handshake execution
- ✅ Key configuration validation (static, ephemeral, remote static)
- ✅ Message flow verification
- ✅ Completion status checks
- ✅ Handshake hash matching between parties
- ✅ Cipher state generation and split
- ✅ Pre-shared key (PSK) support and integration
- ✅ Deferred pattern static key transmission
- ✅ Error handling (truncation, out-of-order messages, size limits)
- ✅ Observer pattern callbacks
- ✅ Prologue handling
- ✅ Multiple algorithm combinations

**Running HandshakeState Tests**:
```bash
# Run all HandshakeState tests
./build/bin/tests/test_handshakestate

# Run specific pattern categories
./build/bin/tests/test_handshakestate "[oneway]"    # The 6 one-way patterns (N, K, X and their PSK variants)
./build/bin/tests/test_handshakestate "[deferred]"  # All 23 deferred patterns
./build/bin/tests/test_handshakestate "[psk]"       # All 21 PSK patterns
./build/bin/tests/test_handshakestate "[xx]"        # XX pattern only

# List all test cases
./build/bin/tests/test_handshakestate --list-tests
```

### Post-Quantum Noise Tests (`test_noise_pq.cpp`)
- ✅ **PQNoise pattern execution**, all 13 (pqN, pqNN, pqNK, pqNX, pqXN, pqXK, pqXX, pqKN, pqKK, pqKX, pqIN, pqIK, pqIX)
- ✅ **ML-KEM integration** with handshake state
- ✅ **KEM token handling** (ekem, skem)
- ✅ **Complete PQ handshake lifecycle**
- ✅ **Multi-message exchange validation**
- ✅ **Transport encryption after PQ handshake**
- ✅ **Various ML-KEM sizes** (M512, M768, M1024)
- ✅ **Mixed cipher/hash combinations** with KEM

**Running PQNoise Tests**:
```bash
./build/bin/tests/test_noise_pq

# Run specific PQ pattern
./build/bin/tests/test_noise_pq "[pqxx]"
./build/bin/tests/test_noise_pq "[pqnk]"

# List all PQ test cases
./build/bin/tests/test_noise_pq --list-tests
```

### Hybrid Forward Secrecy Tests (`test_hfs.cpp`)
- ✅ **All 35 HFS patterns** (12 interactive + 23 deferred)
- ✅ **HFS protocol string parsing** (NNhfs, NKhfs, XXhfs, etc.)
- ✅ **DH + KEM combination validation**
- ✅ **Pattern transformation and HFS modifier**
- ✅ **e1 and ekem1 token handling**
- ✅ **HFS suffix enforcement**
- ✅ **Complete HFS handshake execution**
- ✅ **Mixed DH/KEM algorithms** (X25519+M768, X448+M1024)
- ✅ **Transport encryption after HFS handshake**

**Running HFS Tests**:
```bash
./build/bin/tests/test_hfs

# Run specific HFS pattern
./build/bin/tests/test_hfs "[xxhfs]"
./build/bin/tests/test_hfs "[nkhfs]"

# List all HFS test cases
./build/bin/tests/test_hfs --list-tests
```

### Example Integration Tests (`test_example.cpp`)
- ✅ Protocol construction from a string, and manual vs string
- ✅ Full XX handshake with keypair generation
- ✅ Transport encryption after the handshake

**Running Example Tests**:
```bash
./build/bin/tests/test_example
```

### Cacophony Test Vectors (`test_vectors.cpp`)
- ✅ All 944 vectors in `testdata/cacophony.json` (336 of them PSK)
- ✅ Each vector run from the initiator and the responder side
- ✅ Every message (payload and ciphertext) and the handshake hash compared

**Running Test Vector Tests**:
```bash
./build/bin/tests/test_vectors

# Runs all Cacophony vectors from both sides
```

### Wiping Tests (`test_wiping.cpp`)
- ✅ A test hook sees freed buffers (macOS, Linux and Windows)
- ✅ The SymmetricState destructor scrubs the chaining key
- ✅ An XX handshake leaves no secret in freed memory

**Running Wiping Tests**:
```bash
./build/bin/tests/test_wiping
```

## Adding New Tests

To add tests for a new module:

1. Create `test_<module>.cpp` in the `tests/` directory
2. Include Catch2 headers and import your module
3. Write test cases using Catch2 macros
4. In `CMakeLists.txt`, add the executable linked to `NoisePQC::noisepqc` and `Catch2::Catch2`, then `catch_discover_tests(<target>)` and `noisepqc_optimize_target(<target>)`

Example structure:
```cpp
#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>

import noise;

TEST_CASE("Module - Feature", "[module][tag]") {
    // Your test code here
    REQUIRE(condition);
}

int main(int argc, char* argv[]) {
    // Disable all logging during tests for clean output
    Noise::DisableAllLogging();
    return Catch::Session().run(argc, argv);
}
```

## Catch2 Resources

- [Catch2 Documentation](https://github.com/catchorg/Catch2/tree/devel/docs)
- [Assertion Macros](https://github.com/catchorg/Catch2/blob/devel/docs/assertions.md)
- [Test Cases and Sections](https://github.com/catchorg/Catch2/blob/devel/docs/test-cases-and-sections.md)

