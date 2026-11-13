# Noise Protocol Patterns Reference

**Version**: 1.1.0
**Last Updated**: 2026-11-13

## Overview
This document lists all Noise Protocol patterns implemented in NoisePQC++, including:

- **Classical patterns** (59: 3 one-way + 12 interactive + 23 deferred + 21 PSK): Based on the [Noise Protocol Framework Specification (Revision 34)](https://noiseprotocol.org/noise.html)
- **Post-Quantum (PQ) patterns** (13: 1 one-way + 12 interactive): Using KEM (Key Encapsulation Mechanism) for quantum resistance
- **Hybrid Forward Secrecy (HFS) patterns** (35: 12 interactive + 23 deferred): Combining DH and KEM for defense-in-depth

## Pattern Notation
- `<- s` or `-> s`: Pre-message patterns (keys known before handshake)
- `-> e, es`: Initiator sends ephemeral key and performs DH
- `<- e, ee`: Responder sends ephemeral key and performs DH

### Classical Tokens (DH-based)
- **e**: Ephemeral key generation/transmission
- **s**: Static key transmission (encrypted after shared secret established)
- **ee**: DH between ephemeral keys
- **es**: DH between ephemeral-static keys
- **se**: DH between static-ephemeral keys
- **ss**: DH between static keys
- **psk**: Pre-shared symmetric key mixing

### Post-Quantum Tokens (KEM-based)
- **ekem**: KEM encapsulation to remote ephemeral key (replaces ee in PQ patterns)
- **skem**: KEM encapsulation to remote static key (replaces es/se/ss in PQ patterns)

### Hybrid Forward Secrecy Tokens
- **e1**: Additional ephemeral KEM key generation/transmission
- **ekem1**: KEM encapsulation to remote e1 key (provides additional forward secrecy)

## Implemented Patterns

### One-Way Patterns (Section 7.4)
Single-message patterns for scenarios where only one party sends data.

| Pattern | Pre-Messages | Messages | Use Case |
|---------|-------------|----------|----------|
| **N** | `<- s` | `-> e, es` | Anonymous sender, known responder (e.g., querying a server) |
| **K** | `-> s, <- s` | `-> e, es, ss` | Known sender and responder (e.g., cached credentials) |
| **X** | `<- s` | `-> e, es, s, ss` | Sender authenticates to known responder |

**Security Properties:**
- **N**: Provides encryption and forward secrecy for sender compromise only, but no sender authentication
- **K**: Provides mutual authentication and forward secrecy for sender compromise only
- **X**: Provides sender authentication and forward secrecy for sender compromise only

---

### Fundamental Interactive Patterns (Section 7.5)
Two or three message patterns for full interactive handshakes.

#### Patterns with No Pre-Messages

| Pattern | Messages | Authentication | Use Case |
|---------|----------|----------------|----------|
| **NN** | `-> e`<br>`<- e, ee` | None → None | Fully anonymous (e.g., Tor-like) |
| **NX** | `-> e`<br>`<- e, ee, s, es` | None → Responder | Anonymous initiator learns responder identity |
| **XN** | `-> e`<br>`<- e, ee`<br>`-> s, se` | Initiator → None | Initiator authenticates to anonymous responder |
| **XX** | `-> e`<br>`<- e, ee, s, es`<br>`-> s, se` | Initiator → Responder | Full mutual authentication (most common) |
| **IN** | `-> e, s`<br>`<- e, ee, se` | Initiator → None | Immediate initiator authentication |
| **IX** | `-> e, s`<br>`<- e, ee, se, s, es` | Initiator → Responder | Immediate mutual authentication |

#### Patterns with Initiator Pre-Message `-> s`

| Pattern | Pre-Messages | Messages | Authentication | Use Case |
|---------|-------------|----------|----------------|----------|
| **KN** | `-> s` | `-> e`<br>`<- e, ee, se` | Known Initiator → None | Server knows client's static key |
| **KK** | `-> s, <- s` | `-> e, es, ss`<br>`<- e, ee, se` | Initiator ↔ Responder | Both know each other's keys (cached) |
| **KX** | `-> s` | `-> e`<br>`<- e, ee, se, s, es` | Known Initiator → Responder | Client known to server, server authenticates |

#### Patterns with Responder Pre-Message `<- s`

| Pattern | Pre-Messages | Messages | Authentication | Use Case |
|---------|-------------|----------|----------------|----------|
| **NK** | `<- s` | `-> e, es`<br>`<- e, ee` | None → Known Responder | Client knows server's public key |
| **XK** | `<- s` | `-> e, es`<br>`<- e, ee`<br>`-> s, se` | Initiator → Known Responder | Server's key pinned, client authenticates |
| **IK** | `<- s` | `-> e, es, s, ss`<br>`<- e, ee, se` | Initiator → Known Responder | Immediate client auth to known server |

---

## Pattern Selection Guide

### By Authentication Requirements

| Need | Recommended Patterns |
|------|---------------------|
| No authentication | **NN**, **pqNN**, **NNhfs** |
| Server authentication only | **NK**, **NX**, **pqNK**, **pqNX**, **NKhfs**, **NXhfs** |
| Client authentication only | **KN**, **XN**, **IN**, **pqKN**, **pqXN**, **pqIN** |
| Mutual authentication | **XX**, **KK**, **IK**, **IX**, **pqXX**, **pqKK**, **XXhfs**, **KKhfs** |
| Pre-shared keys on both sides | **KK**, **K**, or any **PSK pattern** |
| One-way message | **N**, **K**, **X**, **pqN** |
| Delayed static key reveal | Use **deferred patterns** (NK1, XX1, etc.) |
| Quantum resistance (pure PQ) | **pqXX**, **pqIK**, **pqNK** (KEM-only) |
| Quantum + classical safety | **XXhfs**, **IKhfs**, **NKhfs** (DH + KEM hybrid) |

### By Message Count (one-way and fundamental patterns)

| Messages | Patterns |
|----------|----------|
| 1 | **N**, **K**, **X** |
| 2 | **NN**, **NK**, **KN**, **KK**, **NX**, **KX**, **IN**, **IK**, **IX** |
| 3 | **XN**, **XK**, **XX** |

PQ variants do not always share their classical base's message count (see the note under the PQ table); HFS variants always do.

### By Use Case

| Use Case | Pattern | Reason |
|----------|---------|--------|
| Web TLS-like (most common) | **XX** | Mutual authentication, no pre-shared keys |
| Client knows server's key | **NK** or **XK** | Simpler, prevents MITM if key is correct |
| Server knows client's key | **KN** or **KX** | Useful for returning clients |
| Both have cached keys | **KK** | Minimal handshake, maximum security |
| Anonymous sender to server | **N** | Single message, forward secrecy |
| IoT device to server | **IK** | Quick mutual auth with known server |
| Tor-like anonymity | **NN** | No identity revealed by either party |
| Quantum-safe communications | **pqXX** | Post-quantum key exchange |
| Future-proof security | **XXhfs** | Hybrid protection against quantum threats |
| High-security environments | **KKhfs** | Both keys known + hybrid protection |
| Long-term data protection | **pqIK**, **IKhfs** | Immediate auth + quantum resistance |

---

## Security Considerations

### Forward Secrecy
All interactive patterns provide forward secrecy (via ephemeral keys; one-way patterns: sender compromise only), meaning:
- Past messages remain secure even if long-term keys are compromised
- Ephemeral keys are destroyed after handshake

### Identity Hiding

| Pattern Category | Initiator Identity | Responder Identity |
|-----------------|-------------------|-------------------|
| **N, NN, NK, NX** | Hidden | Varies |
| **K, KN, KK, KX** | Known (pre-message) | Varies |
| **X, XN, XK, XX** | Encrypted in handshake | Varies |
| **IK** | Encrypted in first msg | Varies |
| **IN, IX** | Sent in clear in first msg | Varies |

### Resistance to Key Compromise

- Patterns with **ss** (static-static DH): More resistant to key compromise
- Patterns with pre-messages: Vulnerable if those keys are compromised before handshake

---

### Deferred Patterns (Section 7.6)
Deferred patterns delay static key transmission to later messages for improved privacy.

| Pattern | Pre-Messages | Messages | Use Case |
|---------|-------------|----------|----------|
| **NK1** | `<- s` | `-> e`<br>`<- e, ee, es` | NK with responder static delayed |
| **NX1** | | `-> e`<br>`<- e, ee, s`<br>`-> es` | NX with responder static delayed, es deferred |
| **X1N** | | `-> e`<br>`<- e, ee`<br>`-> s`<br>`<- se` | XN with the `se` DH deferred to a fourth message |
| **X1K** | `<- s` | `-> e, es`<br>`<- e, ee`<br>`-> s`<br>`<- se` | XK with initiator static and `se` deferred |
| **XK1** | `<- s` | `-> e`<br>`<- e, ee, es`<br>`-> s, se` | XK with responder DH delayed |
| **X1K1** | `<- s` | `-> e`<br>`<- e, ee, es`<br>`-> s`<br>`<- se` | XK with both delays |
| **X1X** | | `-> e`<br>`<- e, ee, s, es`<br>`-> s`<br>`<- se` | XX with the `se` DH deferred |
| **XX1** | | `-> e`<br>`<- e, ee, s`<br>`-> es, s, se` | XX with responder DH delayed |
| **X1X1** | | `-> e`<br>`<- e, ee, s`<br>`-> es, s`<br>`<- se` | XX with both delays |
| **K1N** | `-> s` | `-> e`<br>`<- e, ee`<br>`-> se` | KN with initiator DH delayed |
| **K1K** | `-> s, <- s` | `-> e, es`<br>`<- e, ee`<br>`-> se` | KK with initiator DH delayed |
| **KK1** | `-> s, <- s` | `-> e`<br>`<- e, ee, se, es` | KK with responder DH delayed |
| **K1K1** | `-> s, <- s` | `-> e`<br>`<- e, ee, es`<br>`-> se` | KK with both delays |
| **K1X** | `-> s` | `-> e`<br>`<- e, ee, s, es`<br>`-> se` | KX with initiator DH delayed |
| **KX1** | `-> s` | `-> e`<br>`<- e, ee, se, s`<br>`-> es` | KX with responder DH delayed |
| **K1X1** | `-> s` | `-> e`<br>`<- e, ee, s`<br>`-> se, es` | KX with both delays |
| **I1N** | | `-> e, s`<br>`<- e, ee`<br>`-> se` | IN with initiator DH delayed |
| **I1K** | `<- s` | `-> e, es, s`<br>`<- e, ee`<br>`-> se` | IK with initiator DH delayed |
| **IK1** | `<- s` | `-> e, s`<br>`<- e, ee, se, es` | IK with responder DH delayed |
| **I1K1** | `<- s` | `-> e, s`<br>`<- e, ee, es`<br>`-> se` | IK with both delays |
| **I1X** | | `-> e, s`<br>`<- e, ee, s, es`<br>`-> se` | IX with initiator DH delayed |
| **IX1** | | `-> e, s`<br>`<- e, ee, se, s`<br>`-> es` | IX with responder DH delayed |
| **I1X1** | | `-> e, s`<br>`<- e, ee, s`<br>`-> se, es` | IX with both delays |

**Deferred Pattern Benefits:**
- Improved identity hiding by delaying static key transmission
- More flexible key agreement timing
- Better protection against active attacks during early handshake

---

### PSK (Pre-Shared Key) Patterns
PSK patterns incorporate pre-shared symmetric keys for additional security.

#### One-Way PSK Patterns
| Pattern | Pre-Messages | Messages | PSK Location |
|---------|-------------|----------|--------------|
| **Npsk0** | `<- s` | `-> psk, e, es` | Start of message 1 |
| **Kpsk0** | `-> s, <- s` | `-> psk, e, es, ss` | Start of message 1 |
| **Xpsk1** | `<- s` | `-> e, es, s, ss, psk` | End of message 1 |

#### Interactive PSK Patterns
| Pattern | Base | Messages | PSK Location |
|---------|------|----------|--------------|
| **NNpsk0** | NN | 2 | Start of msg 1 |
| **NNpsk2** | NN | 2 | After ee (end of msg 2) |
| **NKpsk0** | NK | 2 | Start of msg 1 |
| **NKpsk2** | NK | 2 | End of msg 2 |
| **NXpsk2** | NX | 2 | End of msg 2 |
| **XNpsk3** | XN | 3 | End of msg 3 |
| **XKpsk3** | XK | 3 | End of msg 3 |
| **XXpsk3** | XX | 3 | End of msg 3 |
| **KNpsk0** | KN | 2 | Start of msg 1 |
| **KNpsk2** | KN | 2 | End of msg 2 |
| **KKpsk0** | KK | 2 | Start of msg 1 |
| **KKpsk2** | KK | 2 | End of msg 2 |
| **KXpsk2** | KX | 2 | End of msg 2 |
| **INpsk1** | IN | 2 | End of msg 1 |
| **INpsk2** | IN | 2 | End of msg 2 |
| **IKpsk1** | IK | 2 | End of msg 1 |
| **IKpsk2** | IK | 2 | End of msg 2 |
| **IXpsk2** | IX | 2 | End of msg 2 |

**PSK Pattern Benefits:**
- Confidentiality that holds even if DH is broken (for example by a future quantum computer), as long as the PSK stays secret
- Additional layer of authentication
- Useful for known-device scenarios
- Can mitigate key compromise

---

## Post-Quantum (PQ) Patterns

Post-Quantum patterns replace DH operations with KEM (Key Encapsulation Mechanism) operations using ML-KEM (CRYSTALS-Kyber). These patterns provide resistance against quantum computer attacks.

### Protocol String Format

```
Noise_pqXX_M768_ChaChaPoly_SHA256
      ^^^^  ^^^^
      |     |
      |     +-- KEM algorithm: M512, M768, or M1024
      +-------- PQ pattern name (prefixed with "pq")
```

### PQ One-Way Patterns

| Pattern | Pre-Messages | Messages | Classical Equivalent |
|---------|-------------|----------|---------------------|
| **pqN** | `<- s` | `-> skem` | N |

### PQ Interactive Patterns

| Pattern | Pre-Messages | Messages | Classical Equivalent | Use Case |
|---------|-------------|----------|---------------------|----------|
| **pqNN** | | `-> e`<br>`<- ekem` | NN | Fully anonymous, quantum-resistant |
| **pqNK** | `<- s` | `-> skem, e`<br>`<- ekem` | NK | Client knows server's KEM key |
| **pqNX** | | `-> e`<br>`<- ekem, s`<br>`-> skem` | NX | Quantum-resistant server auth |
| **pqXN** | | `-> e`<br>`<- ekem`<br>`-> s`<br>`<- skem` | XN | Quantum-resistant client auth |
| **pqXK** | `<- s` | `-> skem, e`<br>`<- ekem`<br>`-> s`<br>`<- skem` | XK | Client authenticates to known server |
| **pqXX** | | `-> e`<br>`<- ekem, s`<br>`-> skem, s`<br>`<- skem` | XX | Full mutual auth (most common PQ) |
| **pqKN** | `-> s` | `-> e`<br>`<- ekem, skem` | KN | Server knows client's KEM key |
| **pqKK** | `-> s, <- s` | `-> skem, e`<br>`<- ekem, skem` | KK | Both have cached KEM keys |
| **pqKX** | `-> s` | `-> e`<br>`<- ekem, skem, s`<br>`-> skem` | KX | Client known, server authenticates |
| **pqIN** | | `-> e, s`<br>`<- ekem, skem` | IN | Immediate client auth |
| **pqIK** | `<- s` | `-> skem, e, s`<br>`<- ekem, skem` | IK | Immediate auth to known server |
| **pqIX** | | `-> e, s`<br>`<- ekem, skem, s`<br>`-> skem` | IX | Immediate mutual auth |

**Note**: unlike their classical equivalents, PQ patterns are not simply "classical with `ee` → `ekem`". The responder does not transmit an ephemeral key — it encapsulates to the initiator's. Where a classical pattern lets the responder piggyback its authentication on message 2, the PQ variant needs a further round trip, so `pqXX`, `pqXK` and `pqXN` are four-message patterns and `pqNX`, `pqKX` and `pqIX` are three-message patterns.

### PQ Token Semantics

| Token | Operation | Direction |
|-------|-----------|-----------|
| **ekem** | Encapsulate to remote ephemeral | Writer encapsulates to reader's `e` |
| **skem** | Encapsulate to remote static | Writer encapsulates to reader's `s` |

**Key Differences from Classical**:
- `e` token: Sends KEM public key (1184 bytes for M768) instead of DH public key
- `ekem` replaces `ee`: Encapsulates to remote ephemeral
- `skem` replaces `es`, `se`, `ss`: Encapsulates to remote static

### PQ Pattern Example

```cpp
import noise;
using namespace Noise;

// Create PQ protocol
Protocol protocol("Noise_pqXX_M768_ChaChaPoly_BLAKE2s");
// Or: Protocol protocol(pqXX, M768, ChaChaPoly, BLAKE2s);

// Generate KEM keypairs
auto aliceStatic = protocol.dh.GenerateKeypair();  // ML-KEM-768 keypair
auto bobStatic = protocol.dh.GenerateKeypair();

// Configure handshakes (same API as classical)
HandshakeConfig aliceCfg{.protocol = protocol, .isInitiator = true, .localStatic = aliceStatic};
HandshakeConfig bobCfg{.protocol = protocol, .isInitiator = false, .localStatic = bobStatic};

// Execute pqXX handshake (4 messages — one more than classical XX)
HandshakeState aliceHs(aliceCfg), bobHs(bobCfg);

auto msg1 = aliceHs.WriteMessage({});      // -> e
bobHs.ReadMessage(msg1);

auto msg2 = bobHs.WriteMessage({});        // <- ekem, s
aliceHs.ReadMessage(msg2);

auto msg3 = aliceHs.WriteMessage({});      // -> skem, s
bobHs.ReadMessage(msg3);

auto msg4 = bobHs.WriteMessage({});        // <- skem
aliceHs.ReadMessage(msg4);

// Handshake complete - quantum-resistant transport
```

---

## Hybrid Forward Secrecy (HFS) Patterns

HFS patterns combine classical DH with KEM for defense-in-depth. They provide:
- Forward secrecy from both DH and KEM
- Protection if either primitive is broken
- "Harvest now, decrypt later" attack resistance

### Protocol String Format

```
Noise_XXhfs_25519+M768_ChaChaPoly_SHA256
      ^^^^^  ^^^^^^^^^^
      |      |
      |      +-- Combined DH+KEM: 25519+M768, 448+M1024, etc.
      +--------- HFS pattern name (suffixed with "hfs")
```

### HFS Interactive Patterns

| Pattern | Pre-Messages | Messages | Classical Base | Use Case |
|---------|-------------|----------|----------------|----------|
| **NNhfs** | | `-> e, e1`<br>`<- e, ee, ekem1` | NN | Anonymous hybrid |
| **NKhfs** | `<- s` | `-> e, es, e1`<br>`<- e, ee, ekem1` | NK | Hybrid server auth |
| **NXhfs** | | `-> e, e1`<br>`<- e, ee, ekem1, s, es` | NX | Hybrid responder auth |
| **XNhfs** | | `-> e, e1`<br>`<- e, ee, ekem1`<br>`-> s, se` | XN | Hybrid initiator auth |
| **XKhfs** | `<- s` | `-> e, es, e1`<br>`<- e, ee, ekem1`<br>`-> s, se` | XK | Hybrid mutual (known server) |
| **XXhfs** | | `-> e, e1`<br>`<- e, ee, ekem1, s, es`<br>`-> s, se` | XX | Hybrid mutual auth |
| **KNhfs** | `-> s` | `-> e, e1`<br>`<- e, ee, ekem1, se` | KN | Hybrid (known initiator) |
| **KKhfs** | `-> s, <- s` | `-> e, es, ss, e1`<br>`<- e, ee, ekem1, se` | KK | Hybrid (both known) |
| **KXhfs** | `-> s` | `-> e, e1`<br>`<- e, ee, ekem1, se, s, es` | KX | Hybrid (known initiator) |
| **INhfs** | | `-> e, e1, s`<br>`<- e, ee, ekem1, se` | IN | Immediate hybrid initiator |
| **IKhfs** | `<- s` | `-> e, es, s, ss, e1`<br>`<- e, ee, ekem1, se` | IK | Immediate hybrid mutual |
| **IXhfs** | | `-> e, e1, s`<br>`<- e, ee, ekem1, se, s, es` | IX | Immediate hybrid responder |

The 23 deferred patterns take the `hfs` modifier by the same two rules, for example **XX1hfs**: `-> e, e1` / `<- e, ee, ekem1, s` / `-> es, s, se`.

### HFS Token Semantics

| Token | Operation | Key Type |
|-------|-----------|----------|
| **e** | DH ephemeral key | X25519 or X448 |
| **e1** | KEM ephemeral key | ML-KEM-512/768/1024 |
| **ee** | DH between ephemerals | DH shared secret |
| **ekem1** | KEM encapsulation to e1 | KEM shared secret |

- **`e1` is sent once, by the initiator only.** The responder replies with `ekem1`; it does not send an `e1` of its own.
- **`e1` placement**: `e1` follows the initiator's `e`, except when that same message also performs a DH operation, in which case `e1` follows the last DH in the message (compare `NNhfs` message 1, `-> e, e1`, with `NKhfs` message 1, `-> e, es, e1`).

**Key Insight**: HFS patterns mix **both** DH and KEM secrets into the chaining key, ensuring security even if one primitive is broken.

### HFS Pattern Example

```cpp
import noise;
using namespace Noise;

// Create HFS protocol (DH + KEM)
Protocol protocol("Noise_XXhfs_25519+M768_ChaChaPoly_BLAKE2s");

// Generate static keypairs (DH only for static keys in XXhfs)
auto aliceStatic = protocol.dh.GenerateKeypair();
auto bobStatic = protocol.dh.GenerateKeypair();

// Configure handshakes
HandshakeConfig aliceCfg{.protocol = protocol, .isInitiator = true, .localStatic = aliceStatic};
HandshakeConfig bobCfg{.protocol = protocol, .isInitiator = false, .localStatic = bobStatic};

// Execute XXhfs handshake
HandshakeState aliceHs(aliceCfg), bobHs(bobCfg);

auto msg1 = aliceHs.WriteMessage({});      // -> e, e1 (DH + KEM ephemerals)
bobHs.ReadMessage(msg1);

auto msg2 = bobHs.WriteMessage({});        // <- e, ee, ekem1, s, es
aliceHs.ReadMessage(msg2);

auto msg3 = aliceHs.WriteMessage({});      // -> s, se
bobHs.ReadMessage(msg3);

// Hybrid-secured transport
```

---

## Pattern Comparison

### Classical vs PQ vs HFS

| Aspect | Classical (XX) | Post-Quantum (pqXX) | Hybrid (XXhfs) |
|--------|---------------|---------------------|----------------|
| **Ephemeral size** | 32 bytes | 1184 bytes (M768) | 32 + 1184 bytes |
| **Key exchange** | DH only | KEM only | DH + KEM |
| **Quantum safe** | ❌ | ✅ | ✅ |
| **Classical safe** | ✅ | ✅ (assumed) | ✅ |
| **Message overhead** | Low | Higher | Highest |
| **Use case** | General purpose | Quantum preparation | Defense-in-depth |

### Protocol String Examples

```
Classical: Noise_XX_25519_ChaChaPoly_BLAKE2s
PQ:        Noise_pqXX_M768_ChaChaPoly_BLAKE2s
HFS:       Noise_XXhfs_25519+M768_ChaChaPoly_BLAKE2s
```

---

## Implementation Status

✅ **Fully Implemented** (107 patterns):

### Classical Patterns (59)
- One-way: N, K, X (3 patterns)
- Fundamental Interactive: NN, NK, NX, KN, KK, KX, XN, XK, XX, IN, IK, IX (12 patterns)
- Deferred: NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1, K1N, K1K, KK1, K1K1, K1X, KX1, K1X1, I1N, I1K, IK1, I1K1, I1X, IX1, I1X1 (23 patterns)
- PSK: Npsk0, Kpsk0, Xpsk1, NNpsk0, NNpsk2, NKpsk0, NKpsk2, NXpsk2, XNpsk3, XKpsk3, XXpsk3, KNpsk0, KNpsk2, KKpsk0, KKpsk2, KXpsk2, INpsk1, INpsk2, IKpsk1, IKpsk2, IXpsk2 (21 patterns)

### Post-Quantum Patterns (13)
- One-way: pqN (1 pattern)
- Interactive: pqNN, pqNK, pqNX, pqXN, pqXK, pqXX, pqKN, pqKK, pqKX, pqIN, pqIK, pqIX (12 patterns)

### Hybrid Forward Secrecy Patterns (35)
- Interactive: NNhfs, NKhfs, NXhfs, XNhfs, XKhfs, XXhfs, KNhfs, KKhfs, KXhfs, INhfs, IKhfs, IXhfs (12 patterns)
- Deferred: NK1hfs, NX1hfs, X1Nhfs, X1Khfs, XK1hfs, X1K1hfs, X1Xhfs, XX1hfs, X1X1hfs, K1Nhfs, K1Khfs, KK1hfs, K1K1hfs, K1Xhfs, KX1hfs, K1X1hfs, I1Nhfs, I1Khfs, IK1hfs, I1K1hfs, I1Xhfs, IX1hfs, I1X1hfs (23 patterns)

⏳ **Future Extensions**:
- Fallback patterns (maybe)
- Deferred PQ variants

---

## Testing Matrix

All 107 patterns are fully tested with comprehensive test coverage (374 test cases).

| Pattern | Unit Test | Integration Test | Interop Test | File Location |
|---------|-----------|------------------|--------------|---------------|
| **One-Way Patterns** |
| N | ✅ | ✅ | ✅ | test_handshakestate.cpp |
| K | ✅ | ✅ | ✅ | test_handshakestate.cpp |
| X | ✅ | ✅ | ✅ | test_handshakestate.cpp |
| **Two-Message Interactive** |
| NN | ✅ | ✅ | ✅ | test_handshakestate.cpp (complete) |
| NK | ✅ | ✅ | ✅ | test_handshakestate.cpp (complete) |
| NX | ✅ | ✅ | ✅ | test_handshakestate.cpp |
| KN | ✅ | ✅ | ✅ | test_handshakestate.cpp |
| KK | ✅ | ✅ | ✅ | test_handshakestate.cpp (complete) |
| KX | ✅ | ✅ | ✅ | test_handshakestate.cpp |
| IN | ✅ | ✅ | ✅ | test_handshakestate.cpp |
| IK | ✅ | ✅ | ✅ | test_handshakestate.cpp |
| IX | ✅ | ✅ | ✅ | test_handshakestate.cpp |
| **Three-Message Interactive** |
| XN | ✅ | ✅ | ✅ | test_handshakestate.cpp |
| XK | ✅ | ✅ | ✅ | test_handshakestate.cpp |
| XX | ✅ | ✅ | ✅ | test_handshakestate.cpp (complete) |
| **Deferred Patterns** (23 total) |
| All deferred | ✅ | ✅ | ✅ | test_handshakestate.cpp |
| **PSK Patterns** (21 total) |
| All PSK | ✅ | ✅ | ✅ | test_handshakestate.cpp |
| **Post-Quantum Patterns** (13 total) |
| pqN | ✅ | ✅ | ⏳ | test_noise_pq.cpp |
| pqNN, pqNK, pqNX | ✅ | ✅ | ⏳ | test_noise_pq.cpp |
| pqXN, pqXK, pqXX | ✅ | ✅ | ⏳ | test_noise_pq.cpp |
| pqKN, pqKK, pqKX | ✅ | ✅ | ⏳ | test_noise_pq.cpp |
| pqIN, pqIK, pqIX | ✅ | ✅ | ⏳ | test_noise_pq.cpp |
| **HFS Patterns** (35 total) |
| NNhfs, NKhfs, NXhfs | ✅ | ✅ | ⏳ | test_hfs.cpp |
| XNhfs, XKhfs, XXhfs | ✅ | ✅ | ⏳ | test_hfs.cpp |
| KNhfs, KKhfs, KXhfs | ✅ | ✅ | ⏳ | test_hfs.cpp |
| INhfs, IKhfs, IXhfs | ✅ | ✅ | ⏳ | test_hfs.cpp |
| Deferred: NK1hfs … I1X1hfs | ✅ | ✅ | ⏳ | test_hfs.cpp |

**Interop**: the classical rows are checked against the Cacophony vectors (`testdata/cacophony.json`, run by `test_vectors.cpp`).

**Test Coverage Details**:
- ✅ Pattern-specific handshake execution
- ✅ Key configuration validation
- ✅ Message flow verification
- ✅ Completion status checks
- ✅ Handshake hash matching
- ✅ Cipher state generation
- ✅ Error handling (truncation, out-of-order, size limits)
- ✅ Observer pattern callbacks
- ✅ Prologue handling
- ✅ Multiple algorithm combinations (X448, AESGCM, BLAKE2b)
- ✅ KEM encapsulation/decapsulation (ML-KEM-512/768/1024)
- ✅ Hybrid DH+KEM key mixing

**Running Tests**:
```bash
# Run all handshake tests (classical patterns)
./build/bin/tests/test_handshakestate

# Run Post-Quantum pattern tests
./build/bin/tests/test_noise_pq

# Run Hybrid Forward Secrecy tests
./build/bin/tests/test_hfs

# Run specific pattern tests
./build/bin/tests/test_handshakestate "[oneway]"       # All one-way patterns
./build/bin/tests/test_handshakestate "[interactive]"  # NX, KN, KX, XN, XK, IN, IK and IX
./build/bin/tests/test_handshakestate "[deferred]"     # All 23 deferred patterns
./build/bin/tests/test_handshakestate "[psk]"          # All 21 PSK patterns
./build/bin/tests/test_handshakestate "[xx]"           # XX pattern only
./build/bin/tests/test_noise_pq "[pqxx]"               # pqXX pattern only
./build/bin/tests/test_hfs "[xxhfs]"                   # XXhfs pattern only

# List all test cases
./build/bin/tests/test_handshakestate --list-tests
./build/bin/tests/test_noise_pq --list-tests
./build/bin/tests/test_hfs --list-tests
```

---

## References

1. [Noise Protocol Framework Specification](https://noiseprotocol.org/noise.html) - Official specification (Revision 34+)
2. [Noise Explorer](https://noiseexplorer.com/) - Pattern analysis and visualization
3. [nyquist (Go)](https://gitlab.com/yawning/nyquist) - Reference implementation
4. [WireGuard](https://www.wireguard.com/papers/wireguard.pdf) - Uses Noise IK pattern

---

## Quick Start

### Example: XX Handshake

```cpp
import noise;
using namespace Noise;

// Create protocol: Noise_XX_25519_ChaChaPoly_SHA256
Protocol protocol(XX, X25519, ChaChaPoly, SHA256);

// Generate static keys
auto aliceStatic = protocol.dh.GenerateKeypair();
auto bobStatic = protocol.dh.GenerateKeypair();

// Configure handshake states
HandshakeConfig aliceCfg{.protocol = protocol, .isInitiator = true, .localStatic = aliceStatic};
HandshakeConfig bobCfg{.protocol = protocol, .isInitiator = false, .localStatic = bobStatic};

HandshakeState aliceHs(aliceCfg);
HandshakeState bobHs(bobCfg);

// Execute 3-message handshake
std::vector<std::uint8_t> hello{'h', 'e', 'l', 'l', 'o'};
auto msg1 = aliceHs.WriteMessage(hello);
auto recv1 = bobHs.ReadMessage(msg1);

auto msg2 = bobHs.WriteMessage({});
aliceHs.ReadMessage(msg2);

auto msg3 = aliceHs.WriteMessage({});
bobHs.ReadMessage(msg3);

// Handshake complete! Both have cipher states for transport encryption: take them
// (moved out of the HandshakeState, not copied)
auto aliceStates = aliceHs.TakeCipherStates();   // std::optional<std::pair<CipherState, CipherState>>
auto& [aliceTx, aliceRx] = *aliceStates;          // initiator: cs1 sends, cs2 receives
```

See [examples/example_test.cpp](../examples/example_test.cpp) for complete working examples.

---

**Last Updated**: 2026-11-13
**Pattern Count**: 107 patterns (59 classical + 13 PQ + 35 HFS, all tested)
**Test Coverage**: 374 test cases
**Specification Version**: Revision 34+ (with PQNoise and HFS extensions)