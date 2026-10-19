# NoisePQC++ ASIO Networking Examples

This directory contains TCP client/server examples demonstrating NoisePQC++ with the ASIO networking library.

## Overview

These examples show how to integrate the Noise Protocol Framework with real network communication, supporting:

- **Classical mode (XX)**: X25519 Diffie-Hellman key exchange
- **Post-Quantum mode (pqXX)**: ML-KEM-768/1024 key encapsulation
- **Hybrid mode (XXhfs)**: Combined DH + KEM for defense-in-depth

## Available Examples

| Example | Description |
|---------|-------------|
| `noise_server.cpp` | Basic server using XX handshake pattern |
| `noise_client.cpp` | Basic client connecting to noise_server |
| `noise_server_multi.cpp` | Multi-mode server (XX, pqXX, XXhfs) |
| `noise_client_multi.cpp` | Multi-mode client with mode selection |
| `alice.cpp` | Quote exchange server (X448/M1024, AESGCM, SHA512) |
| `bob.cpp` | Quote exchange client matching alice |

## Prerequisites

- NoisePQC++ library built with ASIO support
- CMake 4.3+
- C++23 compatible compiler (Clang 21+, GCC 15.2+, MSVC 19.44+)

## Building

```bash
# From project root, configure and build
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-macOS-toolchain.cmake

cmake --build build

# Examples are located in:
# build/examples/asio/   (or bin/examples/asio/)
```

## Running the Examples

### Basic Client/Server (XX Pattern)

```bash
# Terminal 1: Start the server
cd build/examples/asio
./noise_server

# Terminal 2: Connect with client
./noise_client
```

Expected flow:
1. Server generates static keypair and waits for connections
2. Client connects and initiates XX handshake
3. Three handshake messages are exchanged
4. Both sides derive matching transport keys
5. Encrypted messages can be exchanged

### Multi-Mode Client/Server

The multi-mode examples support runtime mode selection via command-line arguments.

```bash
# Classical mode (X25519 DH)
./noise_server_multi xx
./noise_client_multi xx

# Post-Quantum mode (ML-KEM-768)
./noise_server_multi pqxx
./noise_client_multi pqxx

# Hybrid Forward Secrecy (X25519 + ML-KEM-768)
./noise_server_multi xxhfs
./noise_client_multi xxhfs
```

**Mode Enforcement**: The server and client must use matching modes. Mode matching is enforced through the Noise prologue, ensuring cryptographic binding.

### Alice & Bob Quote Exchange

A practical example demonstrating:
- JSON-based quote storage
- Bidirectional encrypted message exchange
- Quote verification between peers
- Uses stronger algorithms: X448, ML-KEM-1024, AESGCM, SHA512

```bash
# Terminal 1: Start Alice (server/responder)
./alice xx      # or: ./alice pqxx, ./alice xxhfs

# Terminal 2: Start Bob (client/initiator)
./bob xx        # Must match Alice's mode

# Watch the quote exchange in both terminals
```

Alice and Bob exchange quotes, each verifying that received quotes match their expected list.

## Mode Details

### Classical Mode (`xx`)

```
Protocol: Noise_XX_25519_ChaChaPoly_BLAKE2s
```

- Uses X25519 Elliptic Curve Diffie-Hellman
- Standard Noise XX three-message handshake
- Secure against classical computers

### Post-Quantum Mode (`pqxx`)

```
Protocol: Noise_pqXX_M768_ChaChaPoly_BLAKE2s
```

- Uses ML-KEM-768 (CRYSTALS-Kyber) for key exchange
- Quantum-resistant key encapsulation
- Replaces DH operations with KEM encapsulation/decapsulation

### Hybrid Forward Secrecy Mode (`xxhfs`)

```
Protocol: Noise_XXhfs_25519+M768_ChaChaPoly_BLAKE2s
```

- Combines X25519 DH with ML-KEM-768 KEM
- Provides security against both classical and quantum adversaries
- "Harvest now, decrypt later" attack resistant

## Protocol Configurations

### Multi-Mode Examples

| Mode | Pattern | DH/KEM | Cipher | Hash |
|------|---------|--------|--------|------|
| `xx` | XX | X25519 | ChaChaPoly | BLAKE2s |
| `pqxx` | pqXX | M768 | ChaChaPoly | BLAKE2s |
| `xxhfs` | XXhfs | 25519+M768 | ChaChaPoly | BLAKE2s |

### Alice/Bob Examples

| Mode | Pattern | DH/KEM | Cipher | Hash |
|------|---------|--------|--------|------|
| `xx` | XX | X448 | AESGCM | SHA512 |
| `pqxx` | pqXX | M1024 | AESGCM | SHA512 |
| `xxhfs` | XXhfs | 448+M1024 | AESGCM | SHA512 |

## Prologue Mode Binding

All examples use Noise prologues to cryptographically bind the mode:

```cpp
// Multi-mode examples
std::string prologue = "NOISEPQC_MODE:pqxx";

// Alice/Bob examples
std::string prologue = "ALICE_BOB_MODE:pqxx";
```

This ensures that if client and server disagree on mode, the handshake will fail during message decryption (handshake hash mismatch).

## Common Header

All examples share `asio_common.hpp` which provides:

- ASIO integration utilities
- Byte conversion helpers
- Hex printing functions
- Message framing for TCP
- Standard includes and namespace setup

## Troubleshooting

### Connection Refused

Ensure the server is running before starting the client:
```bash
./noise_server &  # Start server in background
sleep 1
./noise_client    # Connect
```

### Mode Mismatch

If you see decryption errors, verify both sides use the same mode:
```bash
# Both must match
./noise_server_multi pqxx   # Server in pqxx mode
./noise_client_multi pqxx   # Client must also be pqxx
```

### Port Already in Use

The default port is 12345. If it's in use:
```bash
# Wait for port to be released, or change the port in the source
lsof -i :12345
```

## Security Considerations

- These examples are for **demonstration purposes**
- For production use, consider:
  - Proper certificate/key management
  - Secure key storage
  - Rate limiting and connection management
  - Error handling and logging
  - TLS for additional transport security if needed

## Additional Resources

- [Main Examples README](../README.md)
- [API Documentation](../../docs/API.md)
- [Pattern Guide](../../docs/PatternGuide.md)
- [ASIO Documentation](https://think-async.com/Asio/)
- [Noise Protocol Specification](https://noiseprotocol.org/noise.html)

---

**Version**: NoisePQC++ v1.0.0
