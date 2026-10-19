# API Reference

**Version**: 1.0.0
**Last Updated**: 2026-04-25

This document provides a comprehensive reference for the NoisePQC++ v1.0.0 public API, including classical, post-quantum (PQNoise), and hybrid forward secrecy (HFS) features.

## Table of Contents

- [Importing the Module](#importing-the-module)
- [Common Types](#common-types)
- [Logging Control](#logging-control)
- [Cipher](#cipher)
- [CipherState](#cipherstate)
- [Hash](#hash)
- [Dh](#dh)
- [SymmetricState](#symmetricstate)
- [Protocol](#protocol)
- [Pattern](#pattern)
- [HandshakeState](#handshakestate)

## Importing the Module

```cpp
import noise;
using namespace Noise;
```

## Common Types

### Algorithm Enums

The actual enums in code use simplified names:

```cpp
// Cipher algorithms
enum class CipherAlgo {
    ChaChaPoly,  // ChaCha20-Poly1305 (default)
    AESGCM       // AES-256-GCM
};

// Hash algorithms
enum class HashAlgo {
    SHA256,      // SHA-256 (default, 32 bytes)
    SHA512,      // SHA-512 (64 bytes)
    BLAKE2b,     // BLAKE2b (64 bytes)
    BLAKE2s      // BLAKE2s (32 bytes)
};

// DH and KEM algorithms
enum class KeyAlgo {
    X25519,      // Curve25519 (default, 32 bytes)
    X448,        // Curve448 (56 bytes)
    M512,        // ML-KEM-512 (800-byte public key, 768-byte ciphertext)
    M768,        // ML-KEM-768 (1184-byte public key, 1088-byte ciphertext) - Recommended
    M1024        // ML-KEM-1024 (1568-byte public key, 1568-byte ciphertext)
};
```

### String Constants

Algorithm names as `std::string_view` constants:

```cpp
// Hash algorithms
constexpr std::string_view SHA256 = "SHA256";
constexpr std::string_view SHA512 = "SHA512";
constexpr std::string_view BLAKE2b = "BLAKE2b";
constexpr std::string_view BLAKE2s = "BLAKE2s";

// Cipher algorithms
constexpr std::string_view AESGCM = "AESGCM";
constexpr std::string_view ChaChaPoly = "ChaChaPoly";

// DH algorithms
constexpr std::string_view X25519 = "25519";
constexpr std::string_view X448 = "448";

// KEM algorithms (Post-Quantum)
constexpr std::string_view M512 = "M512";
constexpr std::string_view M768 = "M768";
constexpr std::string_view M1024 = "M1024";
```

### Constants

```cpp
// Core Noise constants
constexpr std::uint8_t SYMMETRIC_KEY_SIZE = 32;  // 32 bytes
constexpr auto MAX_NONCE = std::numeric_limits<std::uint64_t>::max();
constexpr std::uint16_t NOISE_MAX_MESSAGE_SIZE = 65535;
constexpr std::string_view protocolPrefix = "Noise";

// ML-KEM public key sizes
constexpr std::size_t M512_PUBLIC_KEY_SIZE = 800;
constexpr std::size_t M768_PUBLIC_KEY_SIZE = 1184;
constexpr std::size_t M1024_PUBLIC_KEY_SIZE = 1568;

// ML-KEM ciphertext sizes
constexpr std::size_t M512_CIPHERTEXT_SIZE = 768;
constexpr std::size_t M768_CIPHERTEXT_SIZE = 1088;
constexpr std::size_t M1024_CIPHERTEXT_SIZE = 1568;
```

## Logging Control

**Note**: Logging functions are only available in debug builds (`-DNOISE_DEBUG_BUILD=ON`). In production builds, they are no-ops.

### Global Logging Control

```cpp
// Enable all logging (handshake + symmetric state)
void EnableAllLogging();

// Disable all logging
void DisableAllLogging();
```

### Granular Logging Control

```cpp
// Control handshake logging separately
void SetHandshakeLogging(bool enable);

// Control symmetric state logging separately
void SetSymmetricLogging(bool enable);
```

### Example

```cpp
import noise;
using namespace Noise;

int main() {
    // Enable debug logging
    EnableAllLogging();

    // ... perform handshake with full logging ...

    // Disable for performance-sensitive operations
    DisableAllLogging();

    return 0;
}
```

For detailed information on debug builds and logging, see [LoggingAndDebugging.md](LoggingAndDebugging.md).

---

## Cipher

AEAD (Authenticated Encryption with Associated Data) cipher operations.

**Supported Algorithms**:
- **ChaCha20-Poly1305** (default) - 12-byte nonce, 16-byte tag
- **AES-256-GCM** - 12-byte nonce, 16-byte tag

### Constructors

```cpp
// Default constructor (ChaCha20-Poly1305)
Cipher();

// From CipherAlgo enum
explicit Cipher(CipherAlgo algo);

// From algorithm name string
explicit Cipher(std::string_view cipher_name);

// Examples
Cipher cipher1;                      // ChaCha20-Poly1305 (default)
Cipher cipher2(CipherAlgo::AESGCM); // AES-256-GCM
Cipher cipher3(ChaChaPoly);          // Using string constant
Cipher cipher4("AESGCM");            // Direct string
```

**Note**: String names are mapped internally:
- `"ChaChaPoly"` → `"ChaCha20Poly1305"` (Botan name)
- `"AESGCM"` → `"AES-256/GCM"` (Botan name)

### Copy/Move Semantics

```cpp
Cipher(const Cipher& other);        // Copy constructor
Cipher(Cipher&& other) noexcept;    // Move constructor
Cipher& operator=(const Cipher&) = delete;   // No copy assignment
Cipher& operator=(Cipher&&) = delete;        // No move assignment
```

### Methods

#### Encrypt

```cpp
void Encrypt(
    std::vector<std::uint8_t>& dst,          // Output buffer (ciphertext appended)
    std::span<const std::uint8_t> k,         // 32-byte key
    std::uint64_t n,                         // 64-bit nonce
    std::span<const std::uint8_t> ad,        // Associated data
    std::span<const std::uint8_t> plaintext  // Data to encrypt
) const;
```

**Parameters**:
- `dst`: Buffer to which ciphertext (with appended tag) is written
- `k`: 32-byte symmetric key
- `n`: 64-bit nonce (encoded as 12 bytes with 4-byte zero prefix)
- `ad`: Associated data (authenticated but not encrypted)
- `plaintext`: Data to encrypt

**Behavior**: Appends `plaintext.size() + 16` bytes to `dst` (ciphertext + 16-byte tag).

**Nonce Encoding**:
- ChaCha20-Poly1305: 4 zero bytes + 8-byte little-endian counter
- AES-GCM: 4 zero bytes + 8-byte big-endian counter

#### Decrypt

```cpp
void Decrypt(
    std::vector<std::uint8_t>& dst,
    std::span<const std::uint8_t> k,
    std::uint64_t n,
    std::span<const std::uint8_t> ad,
    std::span<const std::uint8_t> ciphertext
) const;
```

**Parameters**: Same as `Encrypt`, but takes ciphertext with tag and appends decrypted plaintext to `dst`.

**Throws**: `Botan::Invalid_Authentication_Tag` on AEAD tag verification failure.

#### Utility Methods

```cpp
std::string_view String() const;     // Get algorithm name ("ChaChaPoly" or "AESGCM")
auto GetAeadTagSize() const;         // Get tag size (16 bytes)
void Reset() const;                  // Reset internal cipher state
```

---

## CipherState

Manages cipher state with automatic nonce handling and key initialization tracking.

### Constructor

```cpp
CipherState(Cipher cipher, std::uint32_t maxMessageSize);

// Example
Cipher cipher(ChaChaPoly);
CipherState state(std::move(cipher), NOISE_MAX_MESSAGE_SIZE);  // 65535
```

### Copy/Move Semantics

```cpp
CipherState(const CipherState&) = default;         // Copy constructor
CipherState(CipherState&&) noexcept = default;    // Move constructor
CipherState& operator=(const CipherState&) = delete;  // No copy assignment
CipherState& operator=(CipherState&&) = delete;       // No move assignment
```

### Public Members

```cpp
Cipher cipher;                                           // AEAD cipher instance
std::array<std::uint8_t, SYMMETRIC_KEY_SIZE> key;        // 32-byte key (zero-initialized)
std::uint64_t nonce;                                     // 8-byte nonce counter
std::size_t aeadOverhead;                                // AEAD tag size (16 bytes)
std::uint32_t maxMessageSize;                            // Max message size
bool hadKeyBefore;                                       // Track plaintext → encrypted transition
```

**Note**: `hadKeyBefore` tracks state transition from plaintext mode to encrypted mode, important for debug logging.

### Methods

#### InitializeKey

```cpp
void InitializeKey(std::span<const std::uint8_t> key);
```

**Description**: Sets the cipher key (must be 32 bytes) and resets nonce to 0.

**Parameters**: `key` - 32-byte key data

**Throws**: Error if `key.size() != 32`

**Behavior**: Tracks first key initialization via `hadKeyBefore` flag.

#### HasKey

```cpp
bool HasKey() const;
```

**Returns**: `true` if any byte in the key is non-zero

#### SetNonce

```cpp
void SetNonce(std::uint64_t nonce);
```

**Description**: Manually set the nonce value (for testing or specialized use cases)

#### EncryptWithAd

```cpp
[[nodiscard]] std::vector<std::uint8_t> EncryptWithAd(
    std::span<const std::uint8_t> ad,
    std::span<const std::uint8_t> plaintext
);
```

**Description**: Encrypts plaintext with associated data, returning ciphertext. Auto-increments nonce.

**Behavior**:
- If no key set: Returns plaintext unchanged (plaintext passthrough per Noise spec)
- If key set: Returns ciphertext with 16-byte tag appended

**Throws**: `NoiseError` if `nonce > MAX_NONCE`

**Note**: A buffer-appending overload exists privately and is used by `SymmetricState` (which is a friend of `CipherState`).

#### DecryptWithAd

```cpp
[[nodiscard]] std::vector<std::uint8_t> DecryptWithAd(
    std::span<const std::uint8_t> ad,
    std::span<const std::uint8_t> ciphertext
);
```

**Description**: Decrypts ciphertext with associated data, returning plaintext. Auto-increments nonce.

**Behavior**:
- If no key set: Returns ciphertext unchanged (plaintext passthrough per Noise spec)
- If key set: Returns decrypted plaintext

**Throws**: `NoiseError` if `nonce > MAX_NONCE`; `Botan::Invalid_Authentication_Tag` on tag verification failure.

#### Rekey

```cpp
void Rekey(std::string_view hash_algo = "HKDF(SHA-256)");
```

**Description**: Derives a new key from the current key using HKDF.

**Purpose**: Provides forward secrecy for long-lived connections.

**Behavior**: Does nothing if no key is set.

**Parameters**: `hash_algo` - KDF algorithm (default: HKDF with SHA-256)

#### Reset

```cpp
void Reset();
```

**Description**: Securely wipes the key using `Botan::secure_scrub_memory` and resets cipher state.

**Note**: Does NOT reset nonce (by Noise spec design).

---

## Hash

Cryptographic hash functions for key derivation and message authentication.

**Supported Algorithms**:
- **SHA-256** (default) - 32-byte output
- **SHA-512** - 64-byte output
- **BLAKE2b** - 64-byte output
- **BLAKE2s** - 32-byte output

### Constructors

```cpp
// Default constructor (SHA-256)
Hash();

// From HashAlgo enum
explicit Hash(HashAlgo algo);

// From algorithm name string
explicit Hash(std::string_view algo_name);

// Examples
Hash hash1;                      // SHA-256 (default)
Hash hash2(HashAlgo::BLAKE2b);  // BLAKE2b
Hash hash3(SHA256);              // Using string constant
Hash hash4("SHA512");            // Direct string
```

**Note**: String names are mapped internally:
- `"SHA256"` → `"SHA-256"` (Botan name)
- `"SHA512"` → `"SHA-512"` (Botan name)
- `"BLAKE2b"` and `"BLAKE2s"` pass through unchanged

### Copy/Move Semantics

```cpp
Hash(const Hash& other);              // Copy constructor
Hash(Hash&& other) noexcept;         // Move constructor
Hash& operator=(const Hash&) = delete;   // No copy assignment
Hash& operator=(Hash&&) = delete;        // No move assignment
```

### Public Members

```cpp
std::unique_ptr<Botan::HashFunction> hash_function;  // Botan hash instance
```

**Note**: Direct access to `hash_function` allows advanced usage with Botan's API.

### Methods

#### String

```cpp
std::string_view String() const;
```

**Returns**: Algorithm name (`"SHA256"`, `"SHA512"`, `"BLAKE2b"`, or `"BLAKE2s"`)

#### Size

```cpp
std::size_t Size() const;
```

**Returns**: Hash output length in bytes (32 or 64)

### Usage Pattern

The Hash class primarily wraps Botan's HashFunction for use by SymmetricState. Users typically access hash functions through the Botan API via the public `hash_function` member:

```cpp
Hash hasher(SHA256);

// One-shot hashing
auto digest = hasher.hash_function->process(data);

// Incremental hashing
hasher.hash_function->update(data1);
hasher.hash_function->update(data2);
auto digest = hasher.hash_function->final_stdvec();

// Reset for reuse
hasher.hash_function->clear();

// Get output size
auto size = hasher.hash_function->output_length();  // 32 for SHA-256
```

---

## Dh

Diffie-Hellman key exchange and Key Encapsulation Mechanism (KEM) operations.

**Supported DH Algorithms**:
- **X25519** (default) - 32-byte keys, based on Curve25519
- **X448** - 56-byte keys, based on Curve448

**Supported KEM Algorithms (Post-Quantum)**:
- **ML-KEM-512** - 800-byte public key, 768-byte ciphertext
- **ML-KEM-768** - 1184-byte public key, 1088-byte ciphertext (Recommended)
- **ML-KEM-1024** - 1568-byte public key, 1568-byte ciphertext

### Types

#### KeyPair

```cpp
using PrivateKey = std::vector<std::uint8_t>;
using PublicKey = std::vector<std::uint8_t>;

struct KeyPair {
    PrivateKey private_key;
    PublicKey public_key;

    bool IsEmpty() const;  // Returns true if both keys are empty
};
```

**Note**: Keys are stored as raw bytes (not ASN.1 encoded).

### Constructors

```cpp
// Default constructor (X25519)
Dh();

// From KeyAlgo enum
explicit Dh(KeyAlgo algo);

// From algorithm name string
explicit Dh(std::string_view algo_name);

// DH Examples
Dh dh1;                      // X25519 (default)
Dh dh2(KeyAlgo::X448);      // X448
Dh dh3(X25519);              // Using string constant "25519"
Dh dh4("448");               // Direct string for X448

// KEM Examples (Post-Quantum)
Dh kem1(KeyAlgo::M768);      // ML-KEM-768 (recommended)
Dh kem2("M512");             // ML-KEM-512
Dh kem3("M1024");            // ML-KEM-1024
```

**Note**: String names `"25519"` and `"448"` map to Botan names `"X25519"` and `"X448"`. KEM names `"M512"`, `"M768"`, `"M1024"` map to `"ML-KEM-512"`, etc.

### Copy/Move Semantics

```cpp
Dh(const Dh& other) = default;           // Copy constructor
Dh(Dh&& other) noexcept = default;      // Move constructor
Dh& operator=(const Dh&) = delete;      // No copy assignment
Dh& operator=(Dh&&) = delete;           // No move assignment
```

### Methods

#### GenerateKeypair

```cpp
KeyPair GenerateKeypair() const;
```

**Description**: Generates a new cryptographically-random public/private key pair.

**Returns**: `KeyPair` with raw key bytes:
- X25519: 32 bytes for both private and public keys
- X448: 56 bytes for both private and public keys

**Thread Safety**: Uses `Botan::System_RNG` which is thread-safe.

#### DH (span version)

```cpp
std::vector<std::uint8_t> DH(
    std::span<const std::uint8_t> my_raw_priv,
    std::span<const std::uint8_t> peer_raw_pub
) const;
```

**Description**: Performs Diffie-Hellman key agreement.

**Parameters**:
- `my_raw_priv`: Your private key (32 or 56 bytes)
- `peer_raw_pub`: Peer's public key (32 or 56 bytes)

**Returns**: Shared secret (same size as keys)

**Throws**: `NoiseError` if called on a KEM algorithm or key sizes don't match.

#### DH (KeyPair version)

```cpp
std::vector<std::uint8_t> DH(const KeyPair& me, const KeyPair& peer) const;
```

**Description**: Convenience overload that extracts keys from KeyPair structs.

**Parameters**:
- `me`: Your KeyPair (uses `private_key`)
- `peer`: Peer's KeyPair (uses `public_key`)

**Returns**: Shared secret

#### Size

```cpp
std::uint8_t Size() const;
```

**Returns**: Shared secret size in bytes:
- X25519: 32
- X448: 56
- ML-KEM-512/768/1024: 32 (uniform shared secret size for all ML-KEM variants)

#### PublicKeySize

```cpp
std::size_t PublicKeySize() const;
```

**Returns**: Public key size in bytes:
- X25519: 32
- X448: 56
- ML-KEM-512: 800
- ML-KEM-768: 1184
- ML-KEM-1024: 1568

#### CiphertextSize

```cpp
std::size_t CiphertextSize() const;
```

**Returns**: KEM ciphertext size in bytes:
- ML-KEM-512: 768
- ML-KEM-768: 1088
- ML-KEM-1024: 1568

**Throws**: `NoiseError` if called on a DH algorithm (X25519 or X448).

#### IsKEM

```cpp
bool IsKEM() const;
```

**Returns**: `true` if this is a KEM algorithm (M512, M768, M1024), `false` for DH algorithms

#### Encapsulate (KEM only)

```cpp
std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>
Encapsulate(std::span<const std::uint8_t> peer_public_key) const;
```

**Description**: Performs KEM encapsulation using the peer's public key.

**Parameters**: `peer_public_key` - Peer's KEM public key (800/1184/1568 bytes)

**Returns**: Pair of {ciphertext, shared_secret}
- `ciphertext` - Encapsulated key (768/1088/1568 bytes)
- `shared_secret` - Derived 32-byte shared secret

**Throws**: `NoiseError` if called on a DH algorithm.

**Example**:
```cpp
Dh kem(KeyAlgo::M768);
auto aliceKeys = kem.GenerateKeypair();
auto [ciphertext, sharedSecret] = kem.Encapsulate(aliceKeys.public_key);
```

#### Decapsulate (KEM only)

```cpp
std::vector<std::uint8_t> Decapsulate(
    std::span<const std::uint8_t> private_key,
    std::span<const std::uint8_t> ciphertext
) const;
```

**Description**: Performs KEM decapsulation using your private key.

**Parameters**:
- `private_key` - Your KEM private key
- `ciphertext` - Encapsulated key from peer

**Returns**: 32-byte shared secret (matches the sender's shared secret)

**Throws**: `NoiseError` if called on a DH algorithm.

**Example**:
```cpp
Dh kem(KeyAlgo::M768);
auto bobKeys = kem.GenerateKeypair();
// ... receive ciphertext from Alice ...
auto sharedSecret = kem.Decapsulate(bobKeys.private_key, ciphertext);
```

#### String

```cpp
std::string_view String() const;
```

**Returns**: Algorithm name (`"25519"`, `"448"`, `"M512"`, `"M768"`, or `"M1024"`)

#### PrintKeys (debug utility)

```cpp
void PrintKeys(const KeyPair& keypair) const;
```

**Description**: Prints keys in hexadecimal format to stdout (for debugging).

**Output Format**:
```
Algorithm: 25519
Private Key: a29e64e41f70ac061900d1a01ae6b9bc...
Public Key: 3850ea9104be4bf7235ff08985954b1a...
```

**Warning**: Only use for debugging. Never log private keys in production.

---

## SymmetricState

Manages symmetric cryptographic state during the Noise handshake, including the chaining key (`ck`), handshake hash (`h`), and embedded CipherState.

### Constructor

```cpp
SymmetricState(const Cipher& cipher, const Hash& hash);

// Example
Cipher cipher(ChaChaPoly);
Hash hash(SHA256);
SymmetricState ss(cipher, hash);
```

### Copy/Move Semantics

```cpp
SymmetricState(const SymmetricState&) = default;         // Copy constructor
SymmetricState(SymmetricState&&) noexcept;              // Move constructor
SymmetricState& operator=(const SymmetricState&) = delete;  // No copy assignment
SymmetricState& operator=(SymmetricState&&) = delete;       // No move assignment
```

### Public Members

```cpp
CipherState cs;                          // Embedded cipher state
std::vector<std::uint8_t> ck;           // Chaining key (HASHLEN bytes)
std::vector<std::uint8_t> h;            // Handshake hash (HASHLEN bytes)
std::size_t hashLen;                     // Hash output length (32 or 64)
```

**Note**: `ck` and `h` are resized during `InitializeSymmetric()` to match the hash algorithm's output length.

### Methods

#### InitializeSymmetric

```cpp
void InitializeSymmetric(std::span<const std::uint8_t> protocolName);
```

**Description**: Initializes symmetric state with the protocol name.

**Behavior**:
- If `protocolName.size() <= hashLen`: Copy directly to `h`, zero-pad if needed
- If `protocolName.size() > hashLen`: Hash the protocol name and use result as `h`
- Sets `ck = h`
- Initializes CipherState with zero-filled 32-byte key

**Example**:
```cpp
std::string protoName = "Noise_XX_25519_ChaChaPoly_SHA256";
ss.InitializeSymmetric(std::span<const uint8_t>(
    reinterpret_cast<const uint8_t*>(protoName.data()),
    protoName.size()
));
```

#### MixKey

```cpp
void MixKey(std::span<const std::uint8_t> input_km);
```

**Description**: Performs HKDF to derive new chaining key and cipher key from input key material.

**Operation**: `(ck, temp_k) = HKDF(ck, input_km, 2)`

**Behavior**:
- Derives 2 outputs using HKDF
- Updates `ck` with first output
- Initializes `cs` key with second output (truncated to 32 bytes if HASHLEN=64)

**Use Case**: Called after DH operations to mix shared secrets into the state.

#### MixHash

```cpp
void MixHash(std::span<const std::uint8_t> data);
```

**Description**: Updates handshake hash: `h = HASH(h || data)`

**Parameters**: `data` - Data to mix into handshake hash

**Use Case**: Called when transmitting/receiving public keys and ciphertext.

#### MixKeyAndHash

```cpp
void MixKeyAndHash(std::span<const std::uint8_t> input_km);
```

**Description**: Combines key and hash mixing for pre-shared keys.

**Operation**: `(ck, temp_h, temp_k) = HKDF(ck, input_km, 3)`

**Behavior**:
- Derives 3 outputs using HKDF
- Updates `ck` with first output
- Mixes second output into `h`
- Initializes `cs` key with third output

**Use Case**: Used for PSK patterns to mix pre-shared keys.

#### EncryptAndHash (buffer version)

```cpp
void EncryptAndHash(
    std::vector<std::uint8_t>& dst,
    std::span<const std::uint8_t> plaintext
);
```

**Description**: Encrypts plaintext using CipherState (with `h` as AD), appends to `dst`, then mixes ciphertext into hash.

**Critical Detail**: Mixes the NEW ciphertext (not entire `dst`) into hash.

#### DecryptAndHash (buffer version)

```cpp
void DecryptAndHash(
    std::vector<std::uint8_t>& dst,
    std::span<const std::uint8_t> ciphertext
);
```

**Description**: Mixes ciphertext into hash BEFORE decryption, then decrypts and appends to `dst`.

**Critical Detail**: Uses saved copy of `h` as AD for decryption (since `h` is modified before decryption).

#### GetHandshakeHash

```cpp
auto GetHandshakeHash() const;
```

**Returns**: Current handshake hash `h` (as `std::vector<std::uint8_t>`)

**Use Case**: Retrieved after handshake completion for channel binding or verification.

#### Split

```cpp
std::pair<CipherState, CipherState> Split() const;
```

**Description**: Derives two transport CipherStates for post-handshake communication.

**Operation**: `(k1, k2) = HKDF(ck, "", 2)`

**Returns**: `std::pair<CipherState, CipherState>` - (initiator TX, initiator RX) = (responder RX, responder TX)

**Use Case**: Called after handshake completion to get transport encryption keys.

---

## Protocol

Defines a complete Noise protocol by combining a handshake pattern with cryptographic primitives. Supports classical, post-quantum (PQ), and hybrid forward secrecy (HFS) protocols.

### Constructors

```cpp
// Classical: From individual components
Protocol(
    HandshakePattern pattern,
    std::string_view dh_name,
    std::string_view cipher_name,
    std::string_view hash_name
);

// HFS: With both DH and KEM
Protocol(
    HandshakePattern pattern,
    std::string_view dh_name,
    std::string_view kem_name,
    std::string_view cipher_name,
    std::string_view hash_name
);

// From protocol string (auto-detects classical, PQ, or HFS)
explicit Protocol(const std::string_view& pr_string);

// Classical Examples
Protocol proto1(XX, X25519, ChaChaPoly, SHA256);
Protocol proto2("Noise_XX_25519_ChaChaPoly_SHA256");

// Post-Quantum Examples
Protocol proto3("Noise_pqXX_M768_ChaChaPoly_SHA256");

// HFS Examples (DH + KEM hybrid)
Protocol proto4("Noise_XXhfs_25519+M768_ChaChaPoly_SHA256");
```

**Protocol String Formats**:
- Classical: `Noise_PATTERN_DH_CIPHER_HASH`
- Post-Quantum: `Noise_pqPATTERN_KEM_CIPHER_HASH`
- HFS: `Noise_PATTERNhfs_DH+KEM_CIPHER_HASH`

**Examples**:
- `"Noise_XX_25519_ChaChaPoly_SHA256"` - Classical XX
- `"Noise_IK_448_AESGCM_BLAKE2b"` - Classical IK with X448
- `"Noise_NNpsk0_25519_ChaChaPoly_SHA512"` - PSK pattern
- `"Noise_pqXX_M768_ChaChaPoly_BLAKE2s"` - Post-Quantum pqXX
- `"Noise_XXhfs_25519+M768_ChaChaPoly_SHA256"` - HFS with X25519 + ML-KEM-768
- `"Noise_XXhfs_448+M1024_AESGCM_SHA512"` - HFS with X448 + ML-KEM-1024

### Public Members

```cpp
const HandshakePattern pattern;  // Handshake pattern (XX, pqXX, XXhfs, etc.)
const Dh dh;                     // DH algorithm (X25519 or X448)
const std::optional<Dh> kem;     // KEM algorithm (M512, M768, M1024) - for HFS only
const Cipher cipher;             // AEAD cipher (ChaCha20-Poly1305 or AES-GCM)
const Hash hash;                 // Hash function (SHA-256, SHA-512, BLAKE2b, BLAKE2s)
```

**Note**: All members are `const` and immutable after construction, ensuring protocol parameters cannot be changed.

### Methods

#### String

```cpp
std::string String() const;
```

**Returns**: Full protocol name in Noise specification format.

**Examples**:
- `"Noise_XX_25519_ChaChaPoly_SHA256"`
- `"Noise_pqXX_M768_ChaChaPoly_SHA256"`
- `"Noise_XXhfs_25519+M768_ChaChaPoly_SHA256"`

**Use Case**: For logging, debugging, or protocol negotiation.

#### IsHFS

```cpp
bool IsHFS() const;
```

**Returns**: `true` if this protocol uses Hybrid Forward Secrecy (has both DH and KEM).

**Use Case**: To check if the protocol requires both DH and KEM keys.

### Pattern Access

To access pattern details:

```cpp
Protocol proto("Noise_XX_25519_ChaChaPoly_SHA256");

// Get pattern name
std::string patternName = proto.pattern.String();  // "XX"

// Check if pattern has PSK
bool hasPsk = proto.pattern.numPSKs > 0;

// Get message patterns
auto& messages = proto.pattern.messages;
```

See [Pattern](#pattern) section for HandshakePattern API.

---

## Pattern

Defines handshake patterns and message flows according to the Noise Protocol specification.

**NoisePQC++ implements all Noise patterns including PQ and HFS**:
- 3 one-way patterns (N, K, X)
- 12 fundamental interactive patterns (NN, NK, NX, etc.)
- 21 deferred patterns (with "1" suffix)
- 21 PSK patterns (with "psk" modifier)
- 13 Post-Quantum patterns (pqN, pqNN, pqNK, pqXX, etc.)
- 12+ HFS patterns (NNhfs, NKhfs, XXhfs, etc.)

For complete pattern details, see [PatternGuide.md](PatternGuide.md).

### HandshakePattern Structure

```cpp
struct HandshakePattern {
    std::string m_patternName;              // Pattern name, e.g., "XX", "pqXX", "XXhfs"
    std::vector<Token> pre_initiator;       // Initiator's pre-message tokens
    std::vector<Token> pre_responder;       // Responder's pre-message tokens
    std::vector<MessagePattern> messages;   // Ordered handshake message sequences
    bool isOneWay{false};                   // True for one-way patterns (N, K, X)
    std::uint8_t numPSKs{};                 // Number of pre-shared keys required

    [[nodiscard]] std::string_view String() const;
    void describe(std::ostream& os) const;
};
```

### Pattern Tokens

```cpp
enum class Token : std::uint8_t {
    Token_invalid,  // Invalid/sentinel token

    // Classical DH tokens
    Token_e,        // Generate and send ephemeral public key
    Token_s,        // Send static public key (encrypted if key established)
    Token_ee,       // DH(e, re) — ephemeral-ephemeral
    Token_es,       // DH(e, rs) or DH(s, re)
    Token_se,       // DH(s, re) or DH(e, rs)
    Token_ss,       // DH(s, rs) — static-static

    // PQNoise KEM tokens
    Token_ekem,     // KEM encapsulation to peer's ephemeral key (ML-KEM)
    Token_skem,     // KEM encapsulation to peer's static key (ML-KEM)

    // HFS tokens
    Token_e1,       // Generate and send KEM ephemeral public key
    Token_ekem1,    // KEM encapsulation to peer's e1 key

    Token_psk       // Mix pre-shared symmetric key
};
```

### MessagePattern

```cpp
struct MessagePattern {
    std::vector<Token> tokens;
};
```

### Pattern Examples

**One-Way Patterns:**

**N Pattern** (pre-message: `<- s`):
```
-> e, es
```

**K Pattern** (pre-messages: `-> s`, `<- s`):
```
-> e, es, ss
```

**X Pattern** (pre-message: `<- s`):
```
-> e, es, s, ss
```

**Two-Message Interactive Patterns:**

**NN Pattern**:
```
-> e
<- e, ee
```

**NK Pattern** (pre-message: `<- s`):
```
-> e, es
<- e, ee
```

**NX Pattern**:
```
-> e
<- e, ee, s, es
```

**KN Pattern** (pre-message: `-> s`):
```
-> e
<- e, ee, se
```

**KK Pattern** (pre-messages: `-> s`, `<- s`):
```
-> e, es, ss
<- e, ee, se
```

**IN Pattern**:
```
-> e, s
<- e, ee, se
```

**IK Pattern** (pre-message: `<- s`):
```
-> e, es, s, ss
<- e, ee, se
```

**IX Pattern**:
```
-> e, s
<- e, ee, se, s, es
```

**Three-Message Interactive Patterns:**

**XN Pattern**:
```
-> e
<- e, ee
-> s, se
```

**XK Pattern** (pre-message: `<- s`):
```
-> e, es
<- e, ee
-> s, se
```

**XX Pattern**:
```
-> e
<- e, ee, s, es
-> s, se
```

---

## HandshakeState

Manages the complete Noise handshake state machine.

### HandshakeConfig

Configuration for initializing a handshake.

```cpp
class HandshakeConfig {
public:
    const Protocol& protocol;                    // Protocol specification
    bool isInitiator = false;                    // True if initiator, false if responder
    std::vector<std::uint8_t> prologue = {};     // Optional prologue data
    KeyPair localStatic = {};                    // Local static keypair (if needed)
    KeyPair localEphemeral = {};                 // Optional pre-generated ephemeral keypair
    PublicKey remoteStatic = {};                 // Remote static key (if known)
    PublicKey remoteEphemeral = {};              // Remote ephemeral key (if known)
    std::vector<std::array<std::uint8_t, SYMMETRIC_KEY_SIZE>> preSharedKeys = {};  // PSKs
    HandshakeObserver* observer = nullptr;       // Optional key validation observer
    int maxMessageSize = 0;                      // 0 = NOISE_MAX_MESSAGE_SIZE (65535),
                                                 // positive = custom limit,
                                                 // negative = no limit

    [[nodiscard]] int GetMaxMessageSize() const;
};
```

**Fields:**

- **`protocol`**: Reference to the protocol specification (pattern, DH, cipher, hash)
- **`isInitiator`**: Role in handshake (true = initiator, false = responder)
- **`prologue`**: Optional application-specific data mixed into handshake hash
- **`localStatic`**: Your long-term static keypair (required for patterns using `s`)
- **`localEphemeral`**: Optional pre-generated ephemeral keypair (auto-generated if empty)
- **`remoteStatic`**: Peer's static public key (required for patterns with pre-message `<- s` or `-> s`)
- **`remoteEphemeral`**: Peer's ephemeral public key (rarely pre-known)
- **`preSharedKeys`**: Array of 32-byte PSKs for PSK patterns (must match pattern's `numPSKs`)
- **`observer`**: Optional callback for validating peer public keys as they're received
- **`maxMessageSize`**: Message size limit (0 uses default 65535 bytes)

**Notes:**
- PSK validation: Number of PSKs must exactly match `protocol.pattern.numPSKs`
- Each PSK must be exactly `SYMMETRIC_KEY_SIZE` (32) bytes
- Missing required keys will throw `MissingKeyError` during handshake

### HandshakeStatus

Current status of the handshake.

```cpp
class HandshakeStatus {
public:
    // Error status (nullptr = in progress, HandshakeDoneError = complete, other = failure)
    std::exception_ptr err{nullptr};

    // Public keys discovered during handshake
    PublicKey localEphemeral{};
    PublicKey remoteStatic{};
    PublicKey remoteEphemeral{};

    // Resulting cipher states after completion (cs1, cs2)
    std::optional<std::pair<CipherState, CipherState>> cipherStates{};

    // Handshake hash (set on completion)
    std::vector<std::uint8_t> handshakeHash{};

    [[nodiscard]] bool IsComplete() const;
    [[nodiscard]] bool HasError() const;
};
```

**Fields:**

- **`err`**: Exception pointer indicating handshake state:
  - `nullptr` = handshake in progress
  - `HandshakeDoneError` = handshake completed successfully
  - Any other exception = handshake failed
- **`localEphemeral`**: Your ephemeral public key (set after first message with `e` token)
- **`remoteStatic`**: Peer's static public key (set when received or from config)
- **`remoteEphemeral`**: Peer's ephemeral public key (set when received)
- **`cipherStates`**: Transport cipher states after completion (`cs1`, `cs2`)
  - Initiator: `cs1` for sending, `cs2` for receiving
  - Responder: `cs1` for receiving, `cs2` for sending
  - One-way patterns: Only `cs1` is valid (cs2 is cleared)
- **`handshakeHash`**: Final handshake hash (available after completion)

**Methods:**

- **`IsComplete()`**: Returns `true` if handshake completed successfully (err is HandshakeDoneError)
- **`HasError()`**: Returns `true` if handshake failed with an error (err is not nullptr and not HandshakeDoneError)

### HandshakeObserver

Optional observer interface for validating peer public keys as they are received during the handshake.

```cpp
class HandshakeObserver {
public:
    virtual ~HandshakeObserver() = default;

    // Called when a public key is received from the peer
    // Returns std::nullopt to accept, or error string to reject and abort
    virtual std::optional<std::string> OnPeerPublicKey(
        Token token,
        const PublicKey& pubKey
    ) = 0;
};
```

**Purpose**: Allows real-time validation of peer public keys during handshake.

**Callback Parameters:**
- **`token`**: The token type (`Token::Token_e` for ephemeral, `Token::Token_s` for static)
- **`pubKey`**: The peer's public key being received

**Return Value:**
- `std::nullopt`: Accept the key, continue handshake
- `std::optional<std::string>` with error message: Reject the key, abort handshake

**Use Cases:**
- Key pinning (verify against known trusted keys)
- Certificate/credential validation
- Rate limiting based on peer identity
- Real-time blocklisting

### Constructor

```cpp
explicit HandshakeState(const HandshakeConfig& cfg);
```

**Parameters:**
- **`cfg`**: Handshake configuration (protocol, role, keys, observer, etc.)

**Throws:**
- `MissingPSKError`: If number of PSKs doesn't match `protocol.pattern.numPSKs`
- `BadPSKError`: If any PSK is not exactly `SYMMETRIC_KEY_SIZE` (32) bytes
- `PreMessageError`: If required pre-message keys are missing

**Initialization Steps:**
1. Validates PSK count and size
2. Initializes symmetric state with protocol name
3. Mixes prologue into handshake hash
4. Processes pre-message patterns (if any)
5. Sets initial handshake status with known remote keys

**Notes:**
- HandshakeState is non-copyable and non-movable
- Stores reference to config - config must outlive HandshakeState
- Automatically handles pre-messages based on pattern

### Methods

#### WriteMessage

```cpp
std::vector<std::uint8_t> WriteMessage(std::span<const std::uint8_t> payload);
```

**Purpose**: Processes a write step of the handshake protocol.

**Parameters:**
- **`payload`**: Application payload to include in this handshake message (can be empty)

**Returns**: Complete handshake message (tokens + encrypted payload)

**Throws:**
- `OutOfOrderError`: If called when it's the peer's turn to write
- `MessageSizeError`: If message exceeds `maxMessageSize`
- `MissingKeyError`: If required key (e.g., static) is not available
- `InvalidTokenError`: If pattern contains invalid token
- `HandshakeDoneError`: When handshake completes (after returning final message)
- Any error from observer's `OnPeerPublicKey` (if observer returns error)

**Behavior:**
1. Checks for existing errors or out-of-order calls
2. Processes pattern tokens (e, s, ee, es, se, ss, psk) for current message
3. Auto-generates ephemeral key if needed (first `e` token)
4. Encrypts payload using `SymmetricState.EncryptAndHash`
5. If last message in pattern, completes handshake:
   - Splits symmetric state into `cs1` and `cs2`
   - Sets `cipherStates` in status
   - Sets `handshakeHash` in status
   - Clears sensitive data via `Reset()`
   - Throws `HandshakeDoneError` (after returning message)

**Notes:**
- Call alternates with `ReadMessage` based on pattern
- Initiator always writes first message (for non-one-way patterns)
- After completion, use `GetStatus().cipherStates` for transport encryption

#### ReadMessage

```cpp
std::vector<std::uint8_t> ReadMessage(std::span<const std::uint8_t> message);
```

**Purpose**: Processes a read step of the handshake protocol.

**Parameters:**
- **`message`**: Complete handshake message received from peer

**Returns**: Decrypted application payload from the message

**Throws:**
- `OutOfOrderError`: If called when it's your turn to write
- `MessageSizeError`: If message exceeds `maxMessageSize`
- `TruncatedMessageError`: If message is too short for expected tokens
- `DecryptError`: If authentication fails during `DecryptAndHash`
- `NoiseError`: If observer rejects a peer public key
- `HandshakeDoneError`: When handshake completes (after returning payload)

**Behavior:**
1. Checks message size and turn order
2. Processes pattern tokens for current message:
   - Reads `e` token: Extracts peer ephemeral key, calls observer if present
   - Reads `s` token: Decrypts and extracts peer static key, calls observer if present
   - Processes DH tokens (ee, es, se, ss)
   - Processes PSK tokens if applicable
3. Decrypts payload using `SymmetricState.DecryptAndHash`
4. If last message in pattern, completes handshake (same as WriteMessage)

**Notes:**
- Peer public keys are available in status immediately after extraction
- Observer is called synchronously before continuing handshake
- Authentication failure throws `DecryptError` (MAC verification failed)

#### GetStatus

```cpp
[[nodiscard]] const HandshakeStatus& GetStatus() const;
```

**Purpose**: Returns current handshake status.

**Returns**: Reference to `HandshakeStatus` containing:
- Error state (`err`)
- Public keys discovered during handshake
- Cipher states (if complete)
- Handshake hash (if complete)

**Use Cases:**
- Check completion: `GetStatus().IsComplete()`
- Check for errors: `GetStatus().HasError()`
- Access peer keys: `GetStatus().remoteStatic`
- Get transport ciphers: `GetStatus().cipherStates`

#### GetSymmetricState

```cpp
[[nodiscard]] const SymmetricState& GetSymmetricState() const;
```

**Purpose**: Returns reference to internal symmetric state.

**Returns**: Const reference to the `SymmetricState` managing handshake encryption

**Use Cases:**
- Advanced debugging and logging
- Accessing intermediate handshake hash (`ss.h`)
- Inspecting chaining key (`ss.ck`)
- Understanding state machine progression

**Note**: For normal use, access final handshake hash via `GetStatus().handshakeHash` after completion.

#### GetConfig

```cpp
[[nodiscard]] const HandshakeConfig& GetConfig() const;
```

**Purpose**: Returns reference to the configuration used to create this handshake.

**Returns**: Const reference to `HandshakeConfig`

#### IsInitiator

```cpp
[[nodiscard]] bool IsInitiator() const;
```

**Purpose**: Returns the role in this handshake.

**Returns**: `true` if initiator, `false` if responder

#### Reset

```cpp
void Reset();
```

**Purpose**: Clears all sensitive handshake state (automatically called on completion).

**Behavior:**
- Clears symmetric state (chaining key, handshake hash)
- Securely erases ephemeral private key (if generated)
- Clears cipher state

**Note**: Typically not called manually - automatically invoked on handshake completion or destruction.

### Usage Example

```cpp
// Setup
Protocol protocol(XX, X25519, ChaChaPoly, SHA256);
auto aliceStatic = protocol.dh.GenerateKeypair();
auto bobStatic = protocol.dh.GenerateKeypair();

// Alice (initiator)
HandshakeConfig aliceCfg{
    .protocol = protocol,
    .isInitiator = true,
    .localStatic = aliceStatic
};
HandshakeState aliceHs(aliceCfg);

// Bob (responder)
HandshakeConfig bobCfg{
    .protocol = protocol,
    .isInitiator = false,
    .localStatic = bobStatic
};
HandshakeState bobHs(bobCfg);

// Handshake flow (XX pattern)
// Message 1: Alice -> Bob
auto msg1 = aliceHs.WriteMessage({'h','e','l','l','o'});
auto recv1 = bobHs.ReadMessage(msg1);

// Message 2: Bob -> Alice
auto msg2 = bobHs.WriteMessage({});
auto recv2 = aliceHs.ReadMessage(msg2);

// Message 3: Alice -> Bob (completes handshake)
auto msg3 = aliceHs.WriteMessage({});
auto recv3 = bobHs.ReadMessage(msg3);

// Check completion
if (aliceHs.GetStatus().IsComplete() && bobHs.GetStatus().IsComplete()) {
    // Get transport cipher states
    auto [aliceTx, aliceRx] = *aliceHs.GetStatus().cipherStates;
    auto [bobRx, bobTx] = *bobHs.GetStatus().cipherStates;

    // Use for post-handshake encryption
    auto ciphertext = aliceTx.EncryptWithAd({}, plaintext);
    auto decrypted = bobRx.DecryptWithAd({}, ciphertext);
}
```

---

## Usage Examples

### Basic Encryption

```cpp
import noise;
using namespace Noise;

// Create cipher and state
Cipher cipher(ChaChaPoly);
CipherState state(std::move(cipher), 65535);

// Initialize key
std::array<std::uint8_t, 32> key = {/* ... */};
state.InitializeKey(key);

// Encrypt
std::vector<std::uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
std::vector<std::uint8_t> ad;
auto ciphertext = state.EncryptWithAd(ad, plaintext);

// Decrypt
auto decrypted = state.DecryptWithAd(ad, ciphertext);
```

### Diffie-Hellman Key Exchange

```cpp
Dh dh(X25519);

// Alice generates keypair
auto alice_kp = dh.GenerateKeypair();

// Bob generates keypair
auto bob_kp = dh.GenerateKeypair();

// Both compute shared secret
auto alice_shared = dh.DH(alice_kp.private_key, bob_kp.public_key);
auto bob_shared = dh.DH(bob_kp.private_key, alice_kp.public_key);

// alice_shared == bob_shared
```

### Handshake Simulation

```cpp
// Initialize symmetric states (cipher/hash passed by const reference)
Cipher cipher(ChaChaPoly);
Hash hash(SHA256);
SymmetricState init_ss(cipher, hash);
SymmetricState resp_ss(cipher, hash);

// Initialize with protocol name as a byte span
std::string protocol = "Noise_XX_25519_ChaChaPoly_SHA256";
std::span<const std::uint8_t> protoBytes(
    reinterpret_cast<const std::uint8_t*>(protocol.data()), protocol.size());
init_ss.InitializeSymmetric(protoBytes);
resp_ss.InitializeSymmetric(protoBytes);

// Perform handshake...
// (See tests/test_symmetricstate.cpp for complete example)

// Split into transport keys
auto [init_c1, init_c2] = init_ss.Split();
auto [resp_c1, resp_c2] = resp_ss.Split();

// Now use init_c1 ↔ resp_c2 and init_c2 ↔ resp_c1
```

### PSK Pattern Example

```cpp
import noise;
using namespace Noise;

// Create PSK pattern (NNpsk0) — PSK pattern names are looked up via the registry,
// so use the string-based constructor.
Protocol protocol("Noise_NNpsk0_25519_ChaChaPoly_SHA256");

// Generate pre-shared key (32 bytes)
std::array<std::uint8_t, SYMMETRIC_KEY_SIZE> psk{};
// ... fill PSK from secure source (e.g., previous handshake, secure channel)

// Alice (initiator)
HandshakeConfig aliceCfg{
    .protocol = protocol,
    .isInitiator = true,
    .preSharedKeys = {psk}  // Vector of PSKs
};
HandshakeState aliceHs(aliceCfg);

// Bob (responder)
HandshakeConfig bobCfg{
    .protocol = protocol,
    .isInitiator = false,
    .preSharedKeys = {psk}  // Must match Alice's PSK
};
HandshakeState bobHs(bobCfg);

// Execute handshake (NNpsk0 is 2 messages)
auto msg1 = aliceHs.WriteMessage({});
bobHs.ReadMessage(msg1);

auto msg2 = bobHs.WriteMessage({});
aliceHs.ReadMessage(msg2);

// Both sides now have matching transport keys
```

### HandshakeObserver Example (Key Pinning)

```cpp
import noise;
using namespace Noise;

// Observer implementation for key pinning
class KeyPinningObserver : public HandshakeObserver {
public:
    KeyPinningObserver(const PublicKey& trustedKey)
        : m_trustedKey(trustedKey) {}

    std::optional<std::string> OnPeerPublicKey(
        Token token,
        const PublicKey& pubKey
    ) override {
        // Only validate static keys, not ephemeral
        if (token != Token::Token_s) {
            return std::nullopt;  // Accept ephemeral keys
        }

        // Verify against pinned key
        if (pubKey != m_trustedKey) {
            return "Key pinning failed: untrusted static key";
        }

        return std::nullopt;  // Accept trusted key
    }

private:
    PublicKey m_trustedKey;
};

// Usage
Protocol protocol(IK, X25519, ChaChaPoly, SHA256);
auto aliceStatic = protocol.dh.GenerateKeypair();
auto bobStatic = protocol.dh.GenerateKeypair();

// Alice knows Bob's static key and pins it
KeyPinningObserver aliceObserver(bobStatic.public_key);

HandshakeConfig aliceCfg{
    .protocol = protocol,
    .isInitiator = true,
    .localStatic = aliceStatic,
    .remoteStatic = bobStatic.public_key,  // Pre-message
    .observer = &aliceObserver  // Will validate Bob's key
};
HandshakeState aliceHs(aliceCfg);

// Bob's side (no observer needed)
HandshakeConfig bobCfg{
    .protocol = protocol,
    .isInitiator = false,
    .localStatic = bobStatic
};
HandshakeState bobHs(bobCfg);

// Execute IK handshake
try {
    auto msg1 = aliceHs.WriteMessage({});
    bobHs.ReadMessage(msg1);

    auto msg2 = bobHs.WriteMessage({});
    aliceHs.ReadMessage(msg2);  // Observer validates here
} catch (const NoiseError& e) {
    // Key pinning failed
    std::println("Handshake failed: {}", e.what());
}
```

### One-Way Pattern Example

```cpp
import noise;
using namespace Noise;

// One-way pattern (N pattern)
Protocol protocol(N, X25519, ChaChaPoly, SHA256);

// Bob (responder) has static key known to Alice
auto bobStatic = protocol.dh.GenerateKeypair();

// Alice (initiator) sends single message to Bob
HandshakeConfig aliceCfg{
    .protocol = protocol,
    .isInitiator = true,
    .remoteStatic = bobStatic.public_key  // Pre-message: <- s
};
HandshakeState aliceHs(aliceCfg);

// Bob (responder) receives message
HandshakeConfig bobCfg{
    .protocol = protocol,
    .isInitiator = false,
    .localStatic = bobStatic
};
HandshakeState bobHs(bobCfg);

// Single message completes handshake
auto msg = aliceHs.WriteMessage({'h','e','l','l','o'});
auto payload = bobHs.ReadMessage(msg);

// Only one transport key is valid (cs1)
auto [aliceTx, _] = *aliceHs.GetStatus().cipherStates;
auto [bobRx, __] = *bobHs.GetStatus().cipherStates;

// Alice can send encrypted messages to Bob
auto encrypted = aliceTx.EncryptWithAd({}, {'d','a','t','a'});
auto decrypted = bobRx.DecryptWithAd({}, encrypted);

// Note: Bob cannot send encrypted messages back (one-way)
```

### Protocol String Parsing Example

```cpp
import noise;
using namespace Noise;

// Parse from string
Protocol protocol1("Noise_XX_25519_ChaChaPoly_SHA256");
std::println("{}", protocol1.String());  // Noise_XX_25519_ChaChaPoly_SHA256

// Equivalent manual construction
Protocol protocol2(XX, X25519, ChaChaPoly, SHA256);

// Access components
std::println("Pattern: {}", protocol1.pattern.String());  // XX
std::println("DH: X25519, Size: {}", protocol1.dh.Size());  // 32
std::println("Cipher: ChaChaPoly");
std::println("Hash: SHA256, Output size: {}", protocol1.hash.Size());  // 32
```

## Error Handling

NoisePQC++ uses exceptions for error reporting. All NoisePQC++-specific exceptions derive from `NoiseError`, which extends `std::runtime_error`.

### NoisePQC++ Exception Types

**Base Exception:**
```cpp
struct NoiseError : std::runtime_error;
```

**Handshake Errors:**
- **`HandshakeDoneError`**: Thrown when handshake completes successfully (signals completion)
- **`OutOfOrderError`**: Called `WriteMessage` when it's peer's turn, or vice versa
- **`MessageSizeError`**: Message exceeds configured `maxMessageSize`
- **`TruncatedMessageError`**: Message too short for expected tokens
- **`MissingKeyError`**: Required key (static or ephemeral) not available
- **`InvalidTokenError`**: Pattern contains unsupported or invalid token

**Configuration Errors:**
- **`MissingPSKError`**: Number of PSKs doesn't match `pattern.numPSKs`
- **`BadPSKError`**: PSK is not exactly 32 bytes
- **`PreMessageError`**: Required pre-message key missing (e.g., `localStatic` for pattern with `-> s`)
- **`ProtocolNotSupportedError`**: Invalid protocol string or unsupported algorithm combination

**Botan Exceptions:**

In addition to NoisePQC++ exceptions, Botan may throw:
- **`Botan::Invalid_Authentication_Tag`**: AEAD decryption failed (MAC verification failed)
- **`Botan::Invalid_Key_Length`**: Key size doesn't match algorithm requirements
- **`Botan::Lookup_Error`**: Algorithm not available in Botan build
- **`Botan::Exception`**: Base class for all Botan exceptions

### Error Handling Patterns

**Basic Exception Handling:**
```cpp
try {
    auto msg = aliceHs.WriteMessage(payload);
    auto response = bobHs.ReadMessage(msg);
} catch (const HandshakeDoneError&) {
    // Expected - handshake completed successfully
    auto [tx, rx] = *aliceHs.GetStatus().cipherStates;
} catch (const OutOfOrderError& e) {
    std::println("Protocol error: {}", e.what());
} catch (const Botan::Invalid_Authentication_Tag& e) {
    std::println("Authentication failed: {}", e.what());
} catch (const NoiseError& e) {
    std::println("Noise error: {}", e.what());
} catch (const std::exception& e) {
    std::println("Unexpected error: {}", e.what());
}
```

**Checking Status Instead of Catching:**
```cpp
auto msg = aliceHs.WriteMessage(payload);

if (aliceHs.GetStatus().IsComplete()) {
    // Handshake complete - get cipher states
    auto [tx, rx] = *aliceHs.GetStatus().cipherStates;
} else if (aliceHs.GetStatus().HasError()) {
    // Error occurred
    try {
        std::rethrow_exception(aliceHs.GetStatus().err);
    } catch (const std::exception& e) {
        std::println("Error: {}", e.what());
    }
}
```

**Observer Rejection:**
```cpp
class ValidatingObserver : public HandshakeObserver {
    std::optional<std::string> OnPeerPublicKey(
        Token token,
        const PublicKey& pubKey
    ) override {
        if (!IsKeyTrusted(pubKey)) {
            return "Untrusted key";  // Causes NoiseError to be thrown
        }
        return std::nullopt;  // Accept
    }
};

try {
    auto msg = bobHs.ReadMessage(incomingMsg);
} catch (const NoiseError& e) {
    // Observer rejected the key
    std::println("Key validation failed: {}", e.what());
}
```

## Thread Safety

NoisePQC++ is **not thread-safe**. Each state object should be used by a single thread.

## See Also

- [Pattern Guide](PatternGuide.md) - Complete guide to all 57 Noise patterns with selection guide and use cases
- [Architecture Documentation](Architecture.md) - System architecture and design principles
- [Build Guide](BuildGuide.md) - Platform-specific build instructions and testing
- [Logging and Debugging Guide](LoggingAndDebugging.md) - Debug builds and handshake state logging
- [Noise Protocol Specification](https://noiseprotocol.org/noise.html) - Official specification