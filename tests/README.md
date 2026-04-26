# NoisePQC++ Test Suite

This directory contains the comprehensive test suite for NoisePQC++ v0.9.0 using Catch2 v3.11.0.

**Total Test Coverage**: 200+ test cases with 500+ assertions across all Noise Protocol Framework components, including classical, post-quantum, and hybrid patterns.

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
├── test_handshakestate.cpp    # HandshakeState tests (all 57 classical patterns)
├── test_noise_pq.cpp          # Post-Quantum pattern tests (pqXX, pqNK, etc.)
├── test_hfs.cpp               # Hybrid Forward Secrecy tests (XXhfs, NKhfs, etc.)
├── test_example.cpp           # Example integration tests
└── test_vectors.cpp           # Noise Protocol specification test vectors
```

## Building Tests

**Note**: Catch2 v3.11.0 will be automatically downloaded via CMake FetchContent on first build if not found system-wide.

### Build All Tests

```bash
# From project root

# Configure with the appropriate toolchain file for your platform:
#   - macOS (Intel/Apple Silicon): cmake/clang18-macOS-toolchain.cmake
#   - Linux (Clang 18): cmake/clang18-linux-toolchain.cmake
#   - Linux (GCC 15): cmake/gcc15-linux-toolchain.cmake
#   - Raspberry Pi (ARM64): cmake/clang18-rasPi-toolchain.cmake
#   - Windows (MSVC): No toolchain file needed

# Example for macOS:
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-macOS-toolchain.cmake

# Example for Linux with Clang:
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-linux-toolchain.cmake

# Build all targets (Catch2 downloads automatically if needed)
cmake --build build

# Or build just the tests
cmake --build build --target test_cipher test_cipherstate test_dh test_hash \
  test_symmetricstate test_protocol test_pattern test_handshakestate \
  test_noise_pq test_hfs test_example test_vectors
```

## Running Tests

### Run All Tests via CTest

```bash
cd build
ctest --output-on-failure

# Or with verbose output
ctest -V

# Run tests in parallel (faster)
ctest -j$(nproc)
```

### Run Individual Test Executables

```bash
cd build

# Core module tests
./tests/test_cipher
./tests/test_cipherstate
./tests/test_dh
./tests/test_hash
./tests/test_symmetricstate
./tests/test_protocol
./tests/test_pattern

# Comprehensive tests
./tests/test_handshakestate      # All 57 classical Noise patterns
./tests/test_noise_pq            # Post-Quantum patterns (pqXX, pqNK, etc.)
./tests/test_hfs                 # Hybrid Forward Secrecy patterns
./tests/test_vectors             # Noise spec test vectors
./tests/test_example             # Integration examples
```

### Run Specific Tests via CTest

```bash
cd build

# Run tests matching a pattern
ctest -R test_cipher              # Only cipher tests
ctest -R test_handshake           # Only handshake tests
ctest -R test_                    # All tests (matches "test_" prefix)

# Run with detailed output
ctest -R test_dh --verbose
```

### Run Specific Test Cases
```bash
# Cipher module tests
./test_cipher "[encryption]"    # Run only encryption tests
./test_cipher "[chacha]"         # Run only ChaCha20 tests
./test_cipher "[aesgcm]"         # Run only AES-GCM tests
./test_cipher "[security]"       # Run security-related tests

# CipherState module tests
./test_cipherstate "[nonce]"     # Run nonce-related tests
./test_cipherstate "[rekey]"     # Run rekey tests
./test_cipherstate "[roundtrip]" # Run encryption/decryption roundtrip tests

# Dh module tests
./test_dh "[keygen]"             # Run key generation tests
./test_dh "[dh-operation]"       # Run DH operation tests
./test_dh "[x25519]"             # Run X25519 specific tests
./test_dh "[x448]"               # Run X448 specific tests

# Hash module tests
./test_hash "[hashing]"          # Run hashing tests
./test_hash "[sha256]"           # Run SHA-256 specific tests
./test_hash "[blake2b]"          # Run BLAKE2b specific tests
./test_hash "[test-vector]"      # Run known test vector tests

# SymmetricState module tests
./test_symmetricstate "[initialize]"  # Run initialization tests
./test_symmetricstate "[mixkey]"      # Run MixKey tests
./test_symmetricstate "[encrypt]"     # Run encryption tests
./test_symmetricstate "[split]"       # Run Split tests
./test_symmetricstate "[integration]" # Run integration tests

# List all test cases for a module
./test_cipher --list-tests
./test_dh --list-tests
./test_symmetricstate --list-tests

# List all tags
./test_cipher --list-tags
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
- ✅ Utility methods (String(), getAeadTagSize())

### CipherState Module Tests (`test_cipherstate.cpp`)
- ✅ Default, copy, and move constructors
- ✅ Key initialization and management
- ✅ Nonce management and incrementation
- ✅ Encryption and decryption with and without keys
- ✅ Associated data handling
- ✅ Rekey functionality with hash algorithm parameter
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

### Pattern Module Tests (`test_pattern.cpp`)
- ✅ Pattern name parsing and validation
- ✅ Pattern token structure verification
- ✅ All 57 Noise pattern definitions
- ✅ Pattern categories (one-way, interactive, deferred, PSK)
- ✅ Pattern token sequences (e, s, ee, es, se, ss, psk)
- ✅ Pre-message patterns (initiator/responder static keys)
- ✅ Message pattern structures
- ✅ Pattern modifiers (deferred patterns, PSK patterns)

### HandshakeState Module Tests (`test_handshakestate.cpp`)
- ✅ **All 57 Noise Protocol Patterns** (comprehensive coverage)
  - 3 one-way patterns (N, K, X)
  - 12 fundamental interactive patterns (NN, NK, NX, KN, KK, KX, XN, XK, XX, IN, IK, IX)
  - 21 deferred patterns (NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1, K1N, K1K, KK1, K1K1, K1X, KX1, K1X1, I1N, I1K, IK1, I1K1, I1X, IX1, I1X1)
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
# Run all 57 pattern tests
./tests/test_handshakestate

# Run specific pattern categories
./tests/test_handshakestate "[oneway]"      # All 3 one-way patterns
./tests/test_handshakestate "[deferred]"    # All 21 deferred patterns
./tests/test_handshakestate "[psk]"         # All 21 PSK patterns
./tests/test_handshakestate "[xx]"          # XX pattern only

# List all test cases
./tests/test_handshakestate --list-tests
```

### Post-Quantum Noise Tests (`test_noise_pq.cpp`)
- ✅ **PQNoise pattern execution** (pqNN, pqNK, pqNX, pqXN, pqXK, pqXX, pqKN, pqKK, pqKX, pqIN, pqIK, pqIX)
- ✅ **ML-KEM integration** with handshake state
- ✅ **KEM token handling** (ekem, skem)
- ✅ **Complete PQ handshake lifecycle**
- ✅ **Multi-message exchange validation**
- ✅ **Transport encryption after PQ handshake**
- ✅ **Various ML-KEM sizes** (M512, M768, M1024)
- ✅ **Mixed cipher/hash combinations** with KEM

**Running PQNoise Tests**:
```bash
./tests/test_noise_pq

# Run specific PQ pattern
./tests/test_noise_pq "[pqxx]"
./tests/test_noise_pq "[pqnk]"

# List all PQ test cases
./tests/test_noise_pq --list-tests
```

### Hybrid Forward Secrecy Tests (`test_hfs.cpp`)
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
./tests/test_hfs

# Run specific HFS pattern
./tests/test_hfs "[xxhfs]"
./tests/test_hfs "[nkhfs]"

# List all HFS test cases
./tests/test_hfs --list-tests
```

### Example Integration Tests (`test_example.cpp`)
- ✅ Complete handshake workflow examples
- ✅ Protocol construction from strings
- ✅ Keypair generation and management
- ✅ Full handshake execution (multiple patterns)
- ✅ Transport encryption after handshake
- ✅ Error handling examples
- ✅ Real-world usage patterns
- ✅ Integration of all modules

**Running Example Tests**:
```bash
./tests/test_example
```

### Noise Protocol Specification Test Vectors (`test_vectors.cpp`)
- ✅ Official Noise Protocol Framework test vectors (from noiseprotocol.org)
- ✅ Known-answer tests for cryptographic correctness
- ✅ Handshake pattern validation against specification
- ✅ Message payload encryption/decryption verification
- ✅ Handshake hash validation
- ✅ Multiple pattern test vectors (XX, IK, etc.)
- ✅ PSK pattern test vectors
- ✅ Ensures spec compliance and interoperability

**Running Test Vector Tests**:
```bash
./tests/test_vectors

# These tests validate against official Noise Protocol test vectors
# Ensures cryptographic correctness and specification compliance
```

## Adding New Tests

To add tests for a new module:

1. Create `test_<module>.cpp` in the `tests/` directory
2. Include Catch2 headers and import your module
3. Write test cases using Catch2 macros
4. Update `CMakeLists.txt` to add the new test target

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
    return Catch::Session().run(argc, argv);
}
```

## Catch2 Resources

- [Catch2 Documentation](https://github.com/catchorg/Catch2/tree/devel/docs)
- [Assertion Macros](https://github.com/catchorg/Catch2/blob/devel/docs/assertions.md)
- [Test Cases and Sections](https://github.com/catchorg/Catch2/blob/devel/docs/test-cases-and-sections.md)

