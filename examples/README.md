# NoisePQC++ Examples

This directory contains comprehensive examples demonstrating the NoisePQC++ v1.0.0 API, including classical, post-quantum, and hybrid Noise Protocol patterns.

## Overview

The examples are designed to help you learn and understand the Noise Protocol Framework implementation:

### Classical Examples
- **[example_test.cpp](#example_testcpp)** - Complete API walkthrough with detailed explanations
- **[pattern_zoo.cpp](#pattern_zoocpp)** - Interactive explorer for all Noise patterns

### Post-Quantum Examples
- **[example_test_pq.cpp](#example_test_pqcpp)** - PQNoise API demonstration with ML-KEM-768
- **[mlkem_sandbox.cpp](#other-examples)** - ML-KEM integration exploration

### Networking Examples
- **[asio-networking/](#asio-networking-examples)** - TCP client/server with Noise Protocol

### Exploration Tools
- **[dh_sandbox.cpp](#other-examples)** - Diffie-Hellman and KEM operations
- **[hs_sandbox.cpp](#other-examples)** - HandshakeState experimentation
- **[protocol_sandbox.cpp](#other-examples)** - Protocol parsing and construction

## Building Examples

**Note**: Catch2 v3.11.0 will be automatically downloaded via CMake FetchContent on first build if not found system-wide.

```bash
# From project root

# Configure with the appropriate toolchain file for your platform:
#   - macOS (Apple Silicon; Intel untested): cmake/clang21-macOS-toolchain.cmake
#   - Linux incl. Raspberry Pi 5 (Clang 21): cmake/clang21-linux-toolchain.cmake
#   - Linux (GCC 15.2+): cmake/gcc15-linux-toolchain.cmake
#   - Windows (MSVC): No toolchain file needed

# Example for macOS:
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-macOS-toolchain.cmake

# Example for Linux with Clang:
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang21-linux-toolchain.cmake

# Build all examples
cmake --build build

# Build specific example
cmake --build build --target example_test
cmake --build build --target pattern_zoo
```

**Why use toolchain files?**
- Ensures correct compiler (Clang 21 or GCC 15.2+) is used
- Configures the appropriate C++ standard library (libc++ for Clang, libstdc++ for GCC)
- Sets proper include paths for headers
- Configures linker flags and rpath for standard library
- Enables `import std;` support automatically

Examples will be located in `build/examples/`.

## example_test.cpp

**Purpose**: Comprehensive walkthrough of the complete NoisePQC++ API

This example demonstrates the full lifecycle of a Noise Protocol handshake with detailed logging and explanations.

### What It Demonstrates

1. **Protocol Construction**
   - Creating protocols from strings (e.g., `"Noise_XX_25519_ChaChaPoly_SHA256"`)
   - Manual protocol construction with individual components
   - Protocol validation and string conversion

2. **Keypair Generation**
   - Generating static keypairs for both parties
   - Key size verification for different DH algorithms

3. **Handshake State Creation**
   - Configuring initiator and responder
   - Setting up static and ephemeral keys
   - Handshake initialization

4. **Full XX Handshake Execution**
   - Message 1: Initiator → Responder (ephemeral key + payload)
   - Message 2: Responder → Initiator (ephemeral + static keys)
   - Message 3: Initiator → Responder (static key, handshake complete)

5. **Handshake Status Verification**
   - Checking completion status
   - Verifying handshake hash matches
   - Retrieving cipher states

6. **Post-Handshake Transport Encryption**
   - Using split cipher states for secure communication
   - Encrypting and decrypting transport messages
   - Demonstrating bidirectional communication

### Running

```bash
cd build/examples

# Run the complete API demonstration
./example_test
```

### Expected Output

```
================================================================================
     NOISE PROTOCOL FRAMEWORK - API EXAMPLE
================================================================================
This example demonstrates the complete Noise API:
  1. Protocol construction (from string and manual)
  2. Keypair generation
  3. Handshake state creation and configuration
  4. Full XX handshake execution (3 messages)
  5. Handshake status verification
  6. Post-handshake encrypted transport
================================================================================

--------------------------------------------------------------------------------
     SECTION 1: Protocol Construction
--------------------------------------------------------------------------------

1.1 Creating protocol from string:
Protocol: Noise_XX_25519_ChaChaPoly_SHA256
  ✓ Successfully created protocol from string

[... detailed output continues ...]
```

### Use Cases

- **Learning the API**: Perfect starting point for new users
- **Integration Reference**: Copy patterns for your own applications
- **Debugging**: Detailed logging helps understand handshake flow
- **Testing**: Verify your understanding of the protocol

---

## pattern_zoo.cpp

**Purpose**: Interactive explorer for all 57 Noise Protocol patterns

This tool allows you to run and observe any of the 57 Noise patterns or entire categories of patterns.

### What It Demonstrates

- All Noise handshake patterns (classical, PQ, HFS)
- Pattern-specific message flows
- Pre-message patterns (static key knowledge)
- Message patterns (tokens: e, s, ee, es, se, ss, psk, ekem, skem, e1, ekem1)
- Pattern categories:
  - **One-Way** (3 patterns): N, K, X
  - **Fundamental Interactive** (12 patterns): NN, NK, NX, KN, KK, KX, XN, XK, XX, IN, IK, IX
  - **Deferred** (21 patterns): NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1, K1N, K1K, KK1, K1K1, K1X, KX1, K1X1, I1N, I1K, IK1, I1K1, I1X, IX1, I1X1
  - **PSK** (21 patterns): Npsk0, Kpsk0, Xpsk1, NNpsk0, NNpsk2, NKpsk0, NKpsk2, NXpsk2, XNpsk3, XKpsk3, XXpsk3, KNpsk0, KNpsk2, KKpsk0, KKpsk2, KXpsk2, INpsk1, INpsk2, IKpsk1, IKpsk2, IXpsk2
  - **Post-Quantum** (13 patterns): pqN, pqNN, pqNK, pqNX, pqXN, pqXK, pqXX, pqKN, pqKK, pqKX, pqIN, pqIK, pqIX
  - **HFS** (12+ patterns): NNhfs, NKhfs, NXhfs, XXhfs, and all other interactive patterns with HFS modifier

### Usage

```bash
cd build/examples

# Run a specific pattern
./pattern_zoo XX              # XX pattern
./pattern_zoo NNpsk0          # NNpsk0 pattern
./pattern_zoo IK              # IK pattern
./pattern_zoo pqXX            # Post-Quantum XX pattern
./pattern_zoo XXhfs           # Hybrid Forward Secrecy XX pattern

# Run all patterns in a category
./pattern_zoo ONEWAY          # All 3 one-way patterns
./pattern_zoo BASIC           # All 12 fundamental interactive patterns
./pattern_zoo DEFER           # All 21 deferred patterns
./pattern_zoo PSK             # All 21 PSK patterns
./pattern_zoo PQ              # All PQ patterns
./pattern_zoo HFS             # All HFS patterns

# Show usage help
./pattern_zoo
```

### Example: Running XX Pattern

```bash
./pattern_zoo XX
```

**Output**:
```
================================================================================
     NOISE PATTERN ZOO - PATTERN EXPLORER
================================================================================
Testing Pattern: XX
================================================================================

Pattern: XX
  Pre-message pattern (initiator):
    (none)
  Pre-message pattern (responder):
    (none)
  Message patterns:
    -> e
    <- e, ee, s, es
    -> s, se

[... detailed handshake execution with state transitions ...]

✓ XX pattern completed successfully
  - Messages exchanged: 3
  - Handshake complete: Yes
  - Transport keys generated: Yes
```

### Example: Running All PSK Patterns

```bash
./pattern_zoo PSK
```

This will sequentially execute all 21 PSK patterns, showing the handshake flow for each.

### Use Cases

- **Learning Patterns**: Understand how different patterns work
- **Pattern Selection**: Compare patterns to choose the right one for your use case
- **Debugging**: Verify pattern-specific behavior
- **Education**: Demonstrate Noise Protocol concepts
- **Testing**: Validate all patterns are working correctly

### Pattern Selection Guide

| Pattern Category | Use Case | Examples |
|-----------------|----------|----------|
| **One-Way** | No response needed, anonymous sender | N, K, X |
| **Interactive** | Full mutual authentication | XX, IK, IX |
| **Deferred** | Delayed identity transmission | NK1, XX1, IK1 |
| **PSK** | Pre-shared secret for additional security | NNpsk0, XXpsk3, IKpsk2 |

See [docs/PatternGuide.md](../docs/PatternGuide.md) for detailed pattern selection guidance.

---

## example_test_pq.cpp

**Purpose**: Post-Quantum Noise API demonstration with ML-KEM-768

This example demonstrates the complete PQNoise API, showing how to use post-quantum key encapsulation mechanisms.

### What It Demonstrates

1. **PQ Protocol Construction**
   - Creating protocols with ML-KEM-768 (`"Noise_pqXX_M768_ChaChaPoly_SHA256"`)
   - KEM algorithm selection (M512, M768, M1024)

2. **KEM Operations**
   - ML-KEM keypair generation
   - Public key and ciphertext sizes
   - KEM-based key exchange

3. **PQ Handshake Execution**
   - pqXX pattern with KEM tokens (ekem, skem)
   - Complete handshake lifecycle
   - Transport encryption

### Running

```bash
cd build/examples

# Run the PQ API demonstration
./example_test_pq
```

### Use Cases

- **Quantum-Resistant Applications**: Future-proof your communications
- **Learning PQNoise**: Understand KEM integration with Noise
- **Hybrid Systems**: Combine with HFS for defense-in-depth

---

## ASIO Networking Examples

The **[asio-networking/](asio-networking/)** directory contains TCP client/server examples using the ASIO library with NoisePQC++.

### Available Examples

| Example | Description |
|---------|-------------|
| `noise_server.cpp` + `noise_client.cpp` | Basic client/server with XX handshake |
| `noise_server_multi.cpp` + `noise_client_multi.cpp` | Multi-mode support (XX, pqXX, XXhfs) |
| `alice.cpp` + `bob.cpp` | Quote exchange application |

### Quick Start

```bash
cd build/examples/asio

# Terminal 1: Start server
./noise_server

# Terminal 2: Connect client
./noise_client
```

### Multi-Mode Example

```bash
# Server with PQ mode
./noise_server_multi --mode pqxx

# Client connecting with matching mode
./noise_client_multi --mode pqxx
```

For detailed documentation, see **[asio-networking/README.md](asio-networking/README.md)**.

---

## Other Examples

### dh_sandbox.cpp

Demonstrates Diffie-Hellman and KEM operations:
- Key generation for X25519, X448, and ML-KEM
- DH operation execution
- KEM encapsulation/decapsulation
- Shared secret computation

```bash
./dh_sandbox
```

### mlkem_sandbox.cpp

ML-KEM integration exploration:
- ML-KEM-512/768/1024 operations
- Benchmarking and performance testing
- Integration with Botan library

```bash
./mlkem_sandbox
```

### hs_sandbox.cpp

HandshakeState experimentation sandbox:
- Creating and configuring handshake states
- Executing custom handshakes
- Exploring handshake internals

```bash
./hs_sandbox
```

### protocol_sandbox.cpp

Protocol parsing and construction demonstrations:
- Parsing protocol strings
- Manual protocol construction
- Protocol validation

```bash
./protocol_sandbox
```

---

## Example Code Patterns

### Basic XX Handshake

```cpp
import noise;
using namespace Noise;

// Create protocol
Protocol protocol(XX, X25519, ChaChaPoly, SHA256);

// Generate keys
auto aliceKeys = protocol.dh.GenerateKeypair();
auto bobKeys = protocol.dh.GenerateKeypair();

// Setup Alice (initiator)
HandshakeConfig aliceCfg{
    .protocol = protocol,
    .isInitiator = true,
    .localStatic = aliceKeys
};
HandshakeState aliceHs(aliceCfg);

// Setup Bob (responder)
HandshakeConfig bobCfg{
    .protocol = protocol,
    .isInitiator = false,
    .localStatic = bobKeys
};
HandshakeState bobHs(bobCfg);

// Execute handshake
auto msg1 = aliceHs.WriteMessage({'h', 'e', 'l', 'l', 'o'});
bobHs.ReadMessage(msg1);

auto msg2 = bobHs.WriteMessage({});
aliceHs.ReadMessage(msg2);

auto msg3 = aliceHs.WriteMessage({});
bobHs.ReadMessage(msg3);

// Get transport cipher states
auto [aliceTx, aliceRx] = *aliceHs.GetStatus().cipherStates;
auto [bobRx, bobTx] = *bobHs.GetStatus().cipherStates;
```

### Creating Protocols

```cpp
// From string
Protocol p1("Noise_XX_25519_ChaChaPoly_SHA256");

// Manual construction
Protocol p2(XX, X25519, ChaChaPoly, SHA256);

// With different algorithms
Protocol p3(IK, X448, AESGCM, BLAKE2b);

// Post-Quantum protocol
Protocol p4("Noise_pqXX_M768_ChaChaPoly_SHA256");

// Hybrid Forward Secrecy (DH + KEM)
Protocol p5("Noise_XXhfs_25519+M768_ChaChaPoly_SHA256");
```

### Using PSK Patterns

```cpp
// Create protocol with PSK
Protocol protocol(NNpsk0, X25519, ChaChaPoly, SHA256);

// Generate PSK (32 bytes for ChaChaPoly/AESGCM)
std::vector<uint8_t> psk(32);
// ... fill with shared secret ...

// Configure with PSK
HandshakeConfig cfg{
    .protocol = protocol,
    .isInitiator = true,
    .psk = psk
};
HandshakeState hs(cfg);
```

---

## Learning Path

**Recommended order for learning NoisePQC++**:

1. **Start with example_test.cpp**
   - Read the source code with comments
   - Run it and observe the output
   - Understand the complete handshake flow

2. **Explore with pattern_zoo.cpp**
   - Try different patterns (start with XX, NN, NK)
   - Run pattern categories (ONEWAY, BASIC, PQ, HFS)
   - Compare message flows between patterns

3. **Learn Post-Quantum with example_test_pq.cpp**
   - Understand KEM operations and ML-KEM integration
   - Run pqXX handshakes
   - Explore HFS patterns for hybrid security

4. **Try ASIO networking examples**
   - Run noise_server and noise_client
   - Experiment with multi-mode (XX, pqXX, XXhfs)
   - See Alice/Bob quote exchange for real-world patterns

5. **Read the documentation**
   - [API.md](../docs/API.md) - Detailed API reference
   - [PatternGuide.md](../docs/PatternGuide.md) - Pattern selection guide
   - [Architecture.md](../docs/Architecture.md) - System design

6. **Experiment with sandboxes**
   - Modify dh_sandbox.cpp for key exchange experiments
   - Use mlkem_sandbox.cpp for KEM exploration
   - Try protocol_sandbox.cpp for protocol combinations

7. **Build your application**
   - Copy patterns from examples
   - Refer to API documentation
   - Run tests for verification

---

## Performance Benchmarking

For performance benchmarking and optimization:
- **Benchmarks**: [../benchmarks/README.md](../benchmarks/README.md) - Comprehensive performance benchmarks
- **Handshake Performance**: Measure local handshake latency and throughput
- **Network Performance**: Real-world TCP benchmarks with concurrent connections
- **Analysis Tools**: Jupyter notebooks and scripts for visualizing performance data

## Additional Resources

- **Main Documentation**: [../docs/](../docs/)
- **Test Suite**: [../tests/README.md](../tests/README.md)
- **Benchmarks**: [../benchmarks/README.md](../benchmarks/README.md)
- **Build Guide**: [../docs/BuildGuide.md](../docs/BuildGuide.md)
- **Noise Protocol Spec**: https://noiseprotocol.org/noise.html

---

## Troubleshooting

### Build Issues

**Problem**: Examples won't compile
**Solution**: Ensure you're using C++23 compiler (Clang 21+, GCC 15.2+, or MSVC 19.44+)

```bash
cmake -B build -S . -G Ninja -DCMAKE_CXX_COMPILER=clang++-18
```

**Problem**: Catch2 not found
**Solution**: It will auto-download. Ensure you have internet connection on first build.

### Runtime Issues

**Problem**: pattern_zoo shows "Invalid pattern"
**Solution**: Pattern names are case-sensitive. Use exact names: `XX`, not `xx`

**Problem**: Handshake fails
**Solution**: Check that both parties are configured correctly (one initiator, one responder)

---

**Version**: NoisePQC++ v1.0.0
**Last Updated**: 2026-04-25
**Botan Version**: 3.13.0
**Catch2 Version**: 3.11.0
