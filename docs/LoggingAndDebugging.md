# Logging and Debugging Guide

**Version**: 0.9.0
**Last Updated**: 2026-04-25

This guide explains how to build and use the debug version of NoisePQC++ to observe detailed state transitions during Noise Protocol handshakes, including classical, post-quantum (PQ), and hybrid forward secrecy (HFS) patterns.

## Table of Contents

- [Overview](#overview)
- [Debug vs Production Builds](#debug-vs-production-builds)
- [Building in Debug Mode](#building-in-debug-mode)
- [Logging Control API](#logging-control-api)
- [Understanding Debug Output](#understanding-debug-output)
- [Example Debug Session](#example-debug-session)
- [Color-Coded Output](#color-coded-output)
- [Capturing Debug Output in HTML, Markdown, or PNG](#capturing-debug-output-in-html-markdown-or-png)
- [Performance Considerations](#performance-considerations)
- [Troubleshooting](#troubleshooting)

---

## Overview

NoisePQC++ provides a comprehensive debug logging system that allows you to observe the internal state transitions of handshakes in real-time. This is invaluable for:

- **Learning**: Understanding how Noise Protocol patterns work step-by-step
- **Debugging**: Identifying where handshakes fail or behave unexpectedly
- **Development**: Verifying custom implementations against the protocol
- **Training**: Teaching cryptographic protocols with visual feedback
- **Auditing**: Examining cryptographic operations for security analysis

The debug system uses **color-coded, hierarchical logging** that clearly shows:
- Role identification (Initiator vs Responder)
- Token processing:
  - Classical: e, s, ee, es, se, ss, psk
  - Post-Quantum: ekem, skem (KEM encapsulation/decapsulation)
  - Hybrid Forward Secrecy: e1, ekem1 (additional KEM operations)
- State transitions (plaintext → encrypted mode)
- Key exchanges and cryptographic operations (DH and KEM)
- Message flows and sizes
- Handshake progression

---

## Debug vs Production Builds

NoisePQC++ supports two build modes controlled by the `NOISE_DEBUG_BUILD` CMake option:

### Debug Build (`NOISE_DEBUG_BUILD=ON`)

**Features**:
- Uses debug-enabled module files: `CipherState.debug.cppm`, `SymmetricState.debug.cppm`, `HandshakeState.debug.cppm`
- Compiles with `NOISE_DEBUG_BUILD` preprocessor definition
- Includes comprehensive logging statements throughout the handshake process
- Provides runtime control via `EnableAllLogging()` / `DisableAllLogging()` functions
- Shows color-coded output for different roles and operations
- Displays detailed state information (keys, nonces, message sizes, DH operations)

**Use Cases**:
- Development and testing
- Training demonstrations
- Protocol verification
- Debugging handshake issues
- Learning Noise Protocol patterns

**Performance Impact**:
- Moderate overhead from logging conditionals
- Console I/O can slow down high-throughput applications
- Recommended for development, **not** for production

### Production Build (`NOISE_DEBUG_BUILD=OFF`, default)

**Features**:
- Uses optimized module files: `CipherState.cppm`, `SymmetricState.cppm`, `HandshakeState.cppm`
- Logging functions become inline no-ops (zero runtime cost)
- No debug code compiled into binaries
- Minimal binary size
- Maximum performance

**Use Cases**:
- Production deployments
- Performance-critical applications
- Embedded systems
- Library distribution

**Performance Impact**:
- Zero overhead (logging calls are eliminated by compiler)
- Optimal for production use

---

## Building in Debug Mode

### Quick Start

```bash
# Configure debug build
cmake -B build-debug -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-macOS-toolchain.cmake \
  -DNOISE_DEBUG_BUILD=ON

# Build
cmake --build build-debug

# Run an example with debug output
cd build-debug/examples
./example_test
```

### Platform-Specific Debug Builds

#### Linux (Clang 18)

```bash
cmake -B build-debug -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-linux-toolchain.cmake \
  -DNOISE_DEBUG_BUILD=ON

cmake --build build-debug
```

#### Linux (GCC 15.2)

```bash
cmake -B build-debug -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/gcc15-linux-toolchain.cmake \
  -DNOISE_DEBUG_BUILD=ON

cmake --build build-debug
```

#### Raspberry Pi (ARM64)

```bash
cmake -B build-debug -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-rasPi-toolchain.cmake \
  -DNOISE_DEBUG_BUILD=ON

# Use fewer parallel jobs to avoid memory issues
cmake --build build-debug -j2
```

#### macOS (Intel/Apple Silicon)

```bash
cmake -B build-debug -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/clang18-macOS-toolchain.cmake \
  -DNOISE_DEBUG_BUILD=ON

cmake --build build-debug
```

#### Windows (MSVC)

```powershell
# Open Developer Command Prompt for VS 2022

cmake -B build-debug -S . -G Ninja `
  -DNOISE_DEBUG_BUILD=ON

cmake --build build-debug
```

### Verification

After building, verify debug mode is active:

```bash
# You should see this message during configuration:
"NoisePQC++: Debug build with logging ENABLED"

# If you see this instead, logging is disabled:
"NoisePQC++: Production build with logging DISABLED"
```

---

## Logging Control API

When built in debug mode, you can control logging at runtime using the following functions from the `Noise` namespace:

### Global Control

```cpp
import noise;
using namespace Noise;

// Enable all logging (handshake + symmetric state)
EnableAllLogging();

// Disable all logging
DisableAllLogging();
```

### Granular Control

```cpp
// Enable/disable handshake logging only
SetHandshakeLogging(true);   // Enable
SetHandshakeLogging(false);  // Disable

// Enable/disable symmetric state logging only
SetSymmetricLogging(true);   // Enable
SetSymmetricLogging(false);  // Disable
```

### Example Usage

```cpp
import noise;
using namespace Noise;

int main() {
    // Start with logging enabled
    EnableAllLogging();

    // ... create protocol, generate keys ...

    // Perform first handshake message with full logging
    auto msg1 = aliceHs.WriteMessage(payload1);
    bobHs.ReadMessage(msg1);

    // Disable logging for subsequent messages
    DisableAllLogging();

    auto msg2 = bobHs.WriteMessage(payload2);
    aliceHs.ReadMessage(msg2);

    // Re-enable to see final message
    EnableAllLogging();

    auto msg3 = aliceHs.WriteMessage(payload3);
    bobHs.ReadMessage(msg3);

    return 0;
}
```

### Production Build Behavior

**Important**: In production builds (`NOISE_DEBUG_BUILD=OFF`), these functions are **no-ops** (inline empty functions). They will not generate any warnings or errors, allowing you to leave logging control code in your application without any runtime cost.

```cpp
// This code works in both debug and production builds:
EnableAllLogging();  // Does nothing in production (no overhead)

// Handshake executes without logging in production
auto msg = hs.WriteMessage(payload);
```

---

## Understanding Debug Output

Debug output is organized hierarchically with color-coding and clear role identification.

### Log Entry Format

```
[ROLE] OPERATION: Message
```

**Components**:
- `[ROLE]`: `[INITIATOR]` (cyan) or `[RESPONDER]` (magenta)
- `OPERATION`: Function name and context (color-coded by operation type)
- `Message`: Detailed information about the operation

### Operation Colors

| Color | Operation Type | Example |
|-------|---------------|---------|
| **Green** (`[92m`) | High-level function entry | `WriteMessage: ENTER` |
| **Bright Cyan** (`[38;5;81m`) | High-level function entry (responder) | `ReadMessage: ENTER` |
| **Blue** | Read operations | `ReadMessage: Processing tokens` |
| **Cyan** | State operations | `WriteMessage: Processing tokens` |
| **Yellow** | Token processing | `Token e: Writing ephemeral key` |
| **White** | Detailed information | Sizes, states, results |
| **Gray** (`[97m`) | Pattern progression | `Pattern index incremented to 1` |

### Role Identification

- **`[INITIATOR]`**: Cyan text - party that starts the handshake
- **`[RESPONDER]`**: Magenta text - party that responds to the initiator

### Common Log Messages

#### Handshake Initialization

```
[INITIATOR] No pre-messages to process
```
- Indicates the pattern has no pre-message keys (like NK's `<- s`)

#### Token Processing

```
[INITIATOR]   Token e: Writing ephemeral key
[INITIATOR]   Generating new ephemeral keypair
[INITIATOR]   Ephemeral public key size: 32 bytes
[INITIATOR]   Mixed ephemeral key into handshake hash
[INITIATOR]   Appended 32 bytes to message (total: 32 bytes)
```

**Classical Tokens**:
- **e**: Ephemeral key generation/transmission
- **s**: Static key transmission
- **ee**: Ephemeral-ephemeral DH
- **es**: Ephemeral-static DH
- **se**: Static-ephemeral DH
- **ss**: Static-static DH
- **psk**: Pre-shared key mixing

**Post-Quantum (KEM) Tokens**:
- **ekem**: KEM encapsulation to remote ephemeral key (replaces ee)
- **skem**: KEM encapsulation to remote static key (replaces es/se/ss)

**Hybrid Forward Secrecy (HFS) Tokens**:
- **e1**: Additional ephemeral KEM key generation/transmission
- **ekem1**: KEM encapsulation to remote e1 key

#### State Transitions

```
[CIPHER] State transition: PLAINTEXT -> ENCRYPTED mode
```
- Critical moment when handshake establishes encryption
- Occurs after the first DH operation (typically `ee`)

#### Encryption/Decryption

```
[CIPHER] EncryptWithAd: Encrypting 32 bytes with nonce 0 (ad: 32 bytes, dst size before: 64)
[CIPHER]   Result: 48 bytes appended to dst (overhead: 16 bytes, new nonce: 1, dst size after: 112)
```

**Details**:
- `nonce`: Current nonce value (auto-increments)
- `ad`: Associated data size
- `overhead`: Authentication tag (16 bytes for ChaCha20-Poly1305/AES-GCM)
- `dst`: Destination buffer

#### Pattern Progression

```
[INITIATOR] Pattern index incremented to 1
[INITIATOR] More patterns remaining (2/3)
```
- Shows progress through the handshake pattern
- Indicates how many message patterns remain

---

## Example Debug Session

Here's a complete example of debug output from an XX handshake:

### Setup

```cpp
import noise;
using namespace Noise;

int main() {
    EnableAllLogging();

    // Create protocol: Noise_XX_25519_AESGCM_BLAKE2s
    Protocol protocol("Noise_XX_25519_AESGCM_BLAKE2s");

    // Generate keys
    auto aliceKeys = protocol.dh.GenerateKeypair();
    auto bobKeys = protocol.dh.GenerateKeypair();

    // Configure handshakes
    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceKeys
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobKeys
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    // Execute XX handshake
    auto msg1 = aliceHs.WriteMessage({'h', 'e', 'l', 'l', 'o'});
    auto payload1 = bobHs.ReadMessage(msg1);

    auto msg2 = bobHs.WriteMessage({'w', 'o', 'r', 'l', 'd'});
    aliceHs.ReadMessage(msg2);

    auto msg3 = aliceHs.WriteMessage({});
    bobHs.ReadMessage(msg3);

    return 0;
}
```

### Output (Excerpt)

```
[INITIATOR] WriteMessage: ENTER (pattern index: 0, payload size: 5 bytes)
[INITIATOR] WriteMessage: Processing 1 tokens from pattern
[INITIATOR]   Token e: Writing ephemeral key
[INITIATOR]   Generating new ephemeral keypair
[INITIATOR]   Ephemeral public key size: 32 bytes
[INITIATOR]   Mixed ephemeral key into handshake hash
[INITIATOR]   Appended 32 bytes to message (total: 32 bytes)
[INITIATOR] WriteMessage: Encrypting payload (5 bytes)
[SYMMETRIC] EncryptAndHash: Processing 5 bytes (dst size before: 32)
[CIPHER] EncryptWithAd: Plaintext passthrough (no key) - appending 5 bytes (nonce: 0, ad: 32 bytes)
[SYMMETRIC]   Mixing new ciphertext (5 bytes) into handshake hash (dst size after: 37)
[INITIATOR] WriteMessage: Total message size after encryption: 37 bytes
[INITIATOR] WriteMessage: Total message size: 37 bytes
[INITIATOR] Pattern index incremented to 1
[INITIATOR] More patterns remaining (2/3)

[RESPONDER] ReadMessage: ENTER (pattern index: 0, message size: 37 bytes)
[RESPONDER] ReadMessage: Processing 1 tokens from pattern
[RESPONDER]   Token e: Reading ephemeral key
[RESPONDER]   Read 32 bytes of ephemeral key
[RESPONDER]   Stored remote ephemeral key
[RESPONDER]   Mixed ephemeral key into handshake hash
[RESPONDER]   5 bytes remaining in message
[RESPONDER] ReadMessage: Decrypting payload (5 bytes remaining)
[SYMMETRIC] DecryptAndHash: Processing 5 bytes (dst size before: 0)
[SYMMETRIC]   Mixing ciphertext (5 bytes) into handshake hash BEFORE decryption
[CIPHER] DecryptWithAd: Plaintext passthrough (no key) - appending 5 bytes (nonce: 0, ad: 32 bytes)
[SYMMETRIC]   Decryption complete (dst size after: 5)
[RESPONDER] ReadMessage: Decrypted payload size: 5 bytes
[RESPONDER] Pattern index incremented to 1
[RESPONDER] More patterns remaining (2/3)
[RESPONDER] ReadMessage: EXIT

[RESPONDER] WriteMessage: ENTER (pattern index: 1, payload size: 5 bytes)
[RESPONDER] WriteMessage: Processing 4 tokens from pattern
[RESPONDER]   Token e: Writing ephemeral key
[RESPONDER]   Generating new ephemeral keypair
[RESPONDER]   Ephemeral public key size: 32 bytes
[RESPONDER]   Mixed ephemeral key into handshake hash
[RESPONDER]   Appended 32 bytes to message (total: 32 bytes)
[RESPONDER]   Token ee: Performing DH(e, re)
[RESPONDER]   Computing ephemeral-ephemeral DH
[RESPONDER]   DH result: 32 bytes
[CIPHER] State transition: PLAINTEXT -> ENCRYPTED mode
[RESPONDER]   Mixed DH result into chaining key
[RESPONDER]   Token s: Writing static key
[RESPONDER]   Static public key size: 32 bytes
[RESPONDER]   dst size before encryption: 32 bytes
[SYMMETRIC] EncryptAndHash: Processing 32 bytes (dst size before: 32)
[CIPHER] EncryptWithAd: Encrypting 32 bytes with nonce 0 (ad: 32 bytes, dst size before: 32)
[CIPHER]   Result: 48 bytes appended to dst (overhead: 16 bytes, new nonce: 1, dst size after: 80)
[SYMMETRIC]   Mixing new ciphertext (48 bytes) into handshake hash (dst size after: 80)
[RESPONDER]   Encrypted static key appended (total: 80 bytes)
[RESPONDER]   Token es: Performing DH(e, rs)
[RESPONDER]   Computing ephemeral-static DH
[RESPONDER]   DH result: 32 bytes
[RESPONDER]   Mixed DH result into chaining key
[RESPONDER] WriteMessage: Encrypting payload (5 bytes)
[SYMMETRIC] EncryptAndHash: Processing 5 bytes (dst size before: 80)
[CIPHER] EncryptWithAd: Encrypting 5 bytes with nonce 1 (ad: 80 bytes, dst size before: 80)
[CIPHER]   Result: 21 bytes appended to dst (overhead: 16 bytes, new nonce: 2, dst size after: 101)
[SYMMETRIC]   Mixing new ciphertext (21 bytes) into handshake hash (dst size after: 101)
[RESPONDER] WriteMessage: Total message size after encryption: 101 bytes
[RESPONDER] WriteMessage: Total message size: 101 bytes
[RESPONDER] Pattern index incremented to 2
[RESPONDER] More patterns remaining (1/3)

... (Message 3 processing continues) ...
```

### Key Observations

1. **Message 1** (`-> e`):
   - Alice generates ephemeral key
   - Payload sent in plaintext (no encryption yet)
   - Message size: 32 (ephemeral) + 5 (payload) = 37 bytes

2. **Message 2** (`<- e, ee, s, es`):
   - Bob generates ephemeral key
   - **Critical moment**: `ee` DH creates shared secret → **PLAINTEXT → ENCRYPTED transition**
   - Bob's static key now encrypted (48 bytes with 16-byte tag)
   - Payload also encrypted
   - Message size: 32 (ephemeral) + 48 (encrypted static) + 21 (encrypted payload with tag) = 101 bytes

3. **Message 3** (`-> s, se`):
   - Alice sends encrypted static key
   - Final DH operation (`se`)
   - Handshake completes

### Post-Quantum (pqXX) Debug Output

When using PQ patterns like `pqXX`, the debug output shows KEM operations:

```cpp
// Setup pqXX pattern with ML-KEM-768
Protocol protocol("Noise_pqXX_M768_ChaChaPoly_BLAKE2s");
```

**Key Differences from Classical XX**:

```
[INITIATOR]   Token e: Writing ephemeral key
[INITIATOR]   Generating new ephemeral KEM keypair (ML-KEM-768)
[INITIATOR]   Ephemeral public key size: 1184 bytes
...

[RESPONDER]   Token ekem: Performing KEM encapsulation to re
[RESPONDER]   Encapsulating to remote ephemeral key
[RESPONDER]   Ciphertext size: 1088 bytes
[RESPONDER]   Shared secret: 32 bytes
[CIPHER] State transition: PLAINTEXT -> ENCRYPTED mode
[RESPONDER]   Mixed KEM result into chaining key
```

**Observations**:
- **Token `e`**: Generates ML-KEM keypair (public key: 1184 bytes for M768)
- **Token `ekem`**: Encapsulates to remote ephemeral (ciphertext: 1088 bytes)
- **Token `skem`**: Encapsulates to remote static key (similar to `ekem`)
- Message sizes are larger due to KEM public keys and ciphertexts

### Hybrid Forward Secrecy (XXhfs) Debug Output

HFS patterns combine DH and KEM operations:

```cpp
// Setup XXhfs pattern
Protocol protocol("Noise_XXhfs_25519+M768_ChaChaPoly_BLAKE2s");
```

**HFS Token Processing**:

```
[INITIATOR]   Token e: Writing DH ephemeral key
[INITIATOR]   Generating new ephemeral keypair (X25519)
[INITIATOR]   Ephemeral public key size: 32 bytes
[INITIATOR]   Token e1: Writing KEM ephemeral key
[INITIATOR]   Generating new ephemeral KEM keypair (ML-KEM-768)
[INITIATOR]   KEM ephemeral public key size: 1184 bytes
...

[RESPONDER]   Token ee: Performing DH(e, re)
[RESPONDER]   Computing ephemeral-ephemeral DH
[RESPONDER]   DH result: 32 bytes
[RESPONDER]   Token ekem1: Performing KEM encapsulation to e1
[RESPONDER]   Encapsulating to remote e1 key
[RESPONDER]   Ciphertext size: 1088 bytes
[RESPONDER]   Shared secret: 32 bytes
[CIPHER] State transition: PLAINTEXT -> ENCRYPTED mode
[RESPONDER]   Mixed DH and KEM results into chaining key
```

**Observations**:
- **Token `e`**: Standard DH ephemeral (32 bytes for X25519)
- **Token `e1`**: Additional KEM ephemeral (1184 bytes for M768)
- **Token `ee`**: DH operation
- **Token `ekem1`**: KEM encapsulation to e1 key
- Both DH and KEM secrets contribute to the chaining key
- Message sizes include both DH and KEM components

---

## Color-Coded Output

Debug output uses ANSI color codes for better readability. Colors may vary by terminal.

### Color Scheme

**Role Colors**:
- **Cyan** (`\033[96m`): `[INITIATOR]`
- **Magenta** (`\033[95m`): `[RESPONDER]`
- **Cyan** (`\033[36m`): `[CIPHER]`, `[SYMMETRIC]`

**Operation Colors**:
- **Green** (`\033[92m`): Entry/Exit markers
- **Bright Cyan** (`\033[38;5;81m`): High-level operations (responder)
- **Blue** (`\033[34m`): Read operations
- **Cyan** (`\033[32m`): Write operations
- **Yellow** (`\033[33m`): Token processing
- **White** (`\033[37m`): Detail messages
- **Gray** (`\033[97m`): State changes

### Terminal Compatibility

**Supported**:
- macOS Terminal
- iTerm2
- Linux gnome-terminal
- Linux konsole
- Windows Terminal
- VS Code integrated terminal

**Limited Support**:
- Windows Command Prompt (partial ANSI support)
- Windows PowerShell (partial ANSI support)

**Tip**: Use a modern terminal with full ANSI color support for the best experience.

---

## Capturing Debug Output in HTML, Markdown, or PNG

The debug logging colors are optimized for dark terminal backgrounds. When you need to include debug output in documents, papers, or presentations with white backgrounds, use the provided capture script. It runs `pattern_zoo`, remaps all ANSI colors to high-contrast variants suitable for light backgrounds, and produces styled HTML, Markdown and PNG.

### Prerequisites

- A debug build with `pattern_zoo` compiled (see [Building in Debug Mode](#building-in-debug-mode))
- **aha** (Ansi HTML Adapter): `brew install aha`
- **Google Chrome** (only required for `--png` output)
- **ImageMagick** (optional, auto-trims PNG whitespace): `brew install imagemagick`

### Usage

```bash
# From the project root:
./scripts/capture_debug_output.sh [--html] [--md] [--png] <PATTERN>
```

By default, the script outputs **both** HTML and Markdown. Use flags to select specific formats (flags can be combined):

```bash
# Both HTML and Markdown (default)
./scripts/capture_debug_output.sh XXhfs

# HTML only
./scripts/capture_debug_output.sh --html pqXX

# Markdown only
./scripts/capture_debug_output.sh --md XX

# PNG only (requires Google Chrome)
./scripts/capture_debug_output.sh --png XXhfs

# HTML + PNG
./scripts/capture_debug_output.sh --html --png XX
```

The script accepts any of the 82 individual pattern names or 6 category keywords supported by `pattern_zoo`:

```bash
# Category keywords (captures all patterns in the category)
./scripts/capture_debug_output.sh HFS
./scripts/capture_debug_output.sh PQC
./scripts/capture_debug_output.sh BASIC
```

Output files are written to `output/debug-logs/`:

```
output/debug-logs/debug_xxhfs.html
output/debug-logs/debug_xxhfs.md
output/debug-logs/debug_xxhfs.png
```

The script validates the pattern name before running and will exit with an error if the pattern is not recognized, if `aha` is not installed, if the debug `pattern_zoo` binary has not been built, or (for `--png`) if Google Chrome is not found.

### Output Formats

**HTML** — A standalone HTML document with inline color styles. Open in any browser. Ideal for printing to PDF.

**Markdown** — A Markdown file with a heading and a `<pre>` block containing inline `<span style="color:...">` tags. Renders with colors in Markdown viewers that support inline HTML (VS Code preview, CLion, Pandoc). Note: GitHub strips inline `style` attributes for security, so colors will not render on GitHub — use PNG for that purpose.

**PNG** — A screenshot rendered via Chrome headless mode. Preserves colors exactly as they appear in HTML. Ideal for embedding in GitHub READMEs, presentations, and papers. Requires Google Chrome installed at the standard macOS path.

### White-Background Color Remapping

The script automatically remaps terminal colors to darker, high-contrast equivalents for both output formats:

| Role / Operation | Terminal Color | Remapped Color |
|---|---|---|
| `[INITIATOR]` | Bright Cyan | Dark Teal |
| `[RESPONDER]` | Bright Magenta | Dark Purple |
| Entry/Exit markers | Bright Green | Dark Green |
| Token processing | Bright Yellow | Dark Orange |
| State changes | Bright White | Dark Gray |
| Detail messages | White | Medium Gray |
| `[CIPHER]` / `[SYMMETRIC]` | Cyan | Blue-Cyan |
| Read operations | Bright Blue | Dark Blue |

### Converting to PDF

To produce a PDF from the HTML output:

1. Open the HTML file in a browser
2. **Print** (Cmd+P) → **Save as PDF**
3. Adjust scale and font size in print settings to fit your target layout

---

## Performance Considerations

### Debug Build Performance

Debug builds have performance characteristics you should be aware of:

**Overhead Sources**:
1. **Logging Conditionals**: Even when disabled, there's a small cost to check `if (g_EnableHandshakeLogging)`
2. **Console I/O**: `std::println` is relatively slow, especially with colors
3. **String Formatting**: `std::format` has overhead for constructing log messages
4. **Binary Size**: Debug modules are larger due to logging code

**Measurements** (approximate):
- Handshake latency increase: **5-15%** with logging **disabled** at runtime
- Handshake latency increase: **200-500%** with logging **enabled**
- Binary size increase: **20-40%**

### Recommendations

**Development**:
- Use debug builds freely during development
- Enable logging selectively for specific operations
- Disable logging for performance-sensitive loops

**Testing**:
- Use debug builds for functional tests
- Use production builds for performance benchmarks
- Use production builds for load/stress testing

**Production**:
- **Always use production builds** (`NOISE_DEBUG_BUILD=OFF`)
- Zero overhead from disabled logging
- Optimal performance and binary size

### Selective Logging Example

```cpp
// High-volume operation - disable logging
DisableAllLogging();

for (int i = 0; i < 10000; i++) {
    auto msg = hs.WriteMessage(payload);
    // ... transmit msg ...
}

// Re-enable for verification
EnableAllLogging();
auto finalMsg = hs.WriteMessage(finalPayload);
```

---

## Troubleshooting

### No Debug Output Appearing

**Problem**: Running a debug build but seeing no logging output.

**Solutions**:

1. **Verify debug build**:
   ```bash
   # Check CMake configuration output:
   cmake -B build-debug -S . -DNOISE_DEBUG_BUILD=ON
   # Should see: "NoisePQC++: Debug build with logging ENABLED"
   ```

2. **Enable logging explicitly**:
   ```cpp
   import noise;
   using namespace Noise;

   int main() {
       EnableAllLogging();  // Add this at the start
       // ... your code ...
   }
   ```

3. **Check logging was not disabled**:
   ```cpp
   // Make sure you didn't call this somewhere:
   DisableAllLogging();
   ```

4. **Rebuild completely**:
   ```bash
   rm -rf build-debug
   cmake -B build-debug -S . -G Ninja -DNOISE_DEBUG_BUILD=ON
   cmake --build build-debug
   ```

### Garbled Output / No Colors

**Problem**: Seeing escape codes like `[96m` instead of colors.

**Solutions**:

1. **Use a compatible terminal**: Windows CMD has limited ANSI support. Use Windows Terminal, PowerShell 7+, or WSL.

2. **On Windows**, enable ANSI colors:
   ```cpp
   #include <windows.h>

   // Call this before any output:
   HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
   DWORD mode;
   GetConsoleMode(hConsole, &mode);
   SetConsoleMode(hConsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
   ```

3. **Redirect to file** to strip colors:
   ```bash
   ./example_test 2>&1 | cat > output.txt
   ```

### Excessive Output

**Problem**: Too much logging making it hard to see specific operations.

**Solutions**:

1. **Disable symmetric state logging**:
   ```cpp
   SetSymmetricLogging(false);  // Only show handshake operations
   ```

2. **Pipe through grep**:
   ```bash
   ./example_test 2>&1 | grep "Token"
   ./example_test 2>&1 | grep "INITIATOR"
   ```

3. **Log specific operations only**:
   ```cpp
   DisableAllLogging();

   // ... setup ...

   EnableAllLogging();
   auto msg1 = alice.WriteMessage(payload);  // Log this
   DisableAllLogging();

   bob.ReadMessage(msg1);  // Don't log this
   ```

### Build Fails After Switching Modes

**Problem**: Build errors after switching between debug and production modes.

**Solution**: Clean build directory and reconfigure:

```bash
rm -rf build-debug
cmake -B build-debug -S . -G Ninja -DNOISE_DEBUG_BUILD=ON
cmake --build build-debug
```

**Reason**: CMake caches module file selections. A clean rebuild ensures correct module files are used.

---

## Advanced Usage

### Capturing Debug Output to File

For quick terminal-based captures (without color remapping, see [Capturing Debug Output in HTML, Markdown, or PNG](#capturing-debug-output-in-html-markdown-or-png)):

```bash
# Capture with colors (for viewing in terminal later)
./bin/Debug/examples/example_test > debug_output.log 2>&1

# Capture without colors (for text processing)
./bin/Debug/examples/example_test 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > debug_output_clean.txt
```

### Analyzing Handshake Patterns

Use debug output to verify pattern implementations:

```bash
# Run pattern zoo with specific pattern
./bin/Debug/examples/pattern_zoo XX > xx_debug.log 2>&1

# Analyze token sequence
grep "Token" xx_debug.log

# Verify message sizes
grep "message size" xx_debug.log
```

### Training Use

Debug mode is excellent for training:

```cpp
// Demo script for teaching XX pattern
EnableAllLogging();
std::println("\n=== Demonstrating XX Handshake Pattern ===\n");

std::println("Message 1: Initiator sends ephemeral key");
auto msg1 = alice.WriteMessage({'h','e','l','l','o'});

std::println("\nMessage 2: Responder sends ephemeral, establishes encryption");
auto msg2 = bob.WriteMessage({'w','o','r','l','d'});

std::println("\nMessage 3: Initiator completes handshake");
auto msg3 = alice.WriteMessage({});

std::println("\n=== Handshake Complete ===\n");
```

---

## Summary

The NoisePQC++ debug logging system provides:

✅ **Real-time visibility** into handshake state transitions
✅ **Color-coded, role-based** output for clarity
✅ **Runtime control** over logging granularity
✅ **Zero overhead** in production builds
✅ **Training value** for learning Noise Protocol
✅ **Debugging power** for troubleshooting implementations
✅ **Presentation-ready capture** via `scripts/capture_debug_output.sh`

**Key Takeaways**:
- Use **debug builds** (`-DNOISE_DEBUG_BUILD=ON`) during development
- Use **production builds** (`-DNOISE_DEBUG_BUILD=OFF`, default) for deployment
- Control logging at **runtime** with `Enable/DisableAllLogging()`
- Debug output is **hierarchical** and **color-coded** for readability
- Logging shows **token processing**, **DH operations**, **state transitions**, and **message flows**
- Use `scripts/capture_debug_output.sh` to produce white-background HTML, Markdown, or PNG for presentations

---

**For More Information**:
- [Build Guide](BuildGuide.md) - Complete build instructions
- [API Reference](API.md) - Full API documentation
- [Pattern Guide](PatternGuide.md) - Noise pattern selection guide
- [examples/README.md](../examples/README.md) - Example programs

**Version**: NoisePQC++ v0.9.0
**Botan**: 3.10.0
**Catch2**: v3.11.0
