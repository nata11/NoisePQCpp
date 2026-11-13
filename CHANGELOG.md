# Changelog

All notable changes to NoisePQC++ will be documented in this file.

## [1.1.0] - 2026-11-13

NoisePQC++ 1.1.0 follows a complete review of the library code in
`src/`, for memory safety, error handling and performance, and a
build-configuration optimization pass on top of Botan 3.13.0. The build
changes touch no library, test, example or benchmark source; the
review's fixes change `src/`, `tests/`, `examples/` and the scripts, as
listed below. 1.1.0 has breaking changes, listed first.

### Breaking changes
- AEAD failures throw `DecryptionError` (a `NoiseError`) instead of
  `Botan::Invalid_Authentication_Tag` or `Botan::Invalid_Argument`.
  `Cipher::Encrypt`/`Decrypt` translate every other `Botan::Exception`
  into a `NoiseError`, so application code that caught Botan types for
  the AEAD path must catch `DecryptionError`/`NoiseError` instead
- The reserved nonce 2^64 - 1 (Noise spec Section 5.1) throws
  `NonceExhaustedError` (a `NoiseError`) from `CipherState::EncryptWithAd`
  and `DecryptWithAd`
- `MessageSizeError::what()` reads `noisepqc++: message size exceeded`
  (the `HandshakeState` prefix is gone, because transport messages now
  throw it too)
- DH/KEM failures throw `InvalidPublicKeyError` (a `NoiseError`) or
  `NoiseError` instead of `Botan::Invalid_Argument` or
  `Botan::Decoding_Error`: a low-order X25519/X448 point and an ML-KEM
  encapsulation key that fails the FIPS 203 Section 7.2 check are
  `InvalidPublicKeyError`; every other failure in `Dh::GenerateKeypair`,
  `DH`, `Encapsulate` and `Decapsulate` is a `NoiseError`
- `Dh::DH` rejects keys of the wrong length for the algorithm: a wrong
  public-key length is `InvalidPublicKeyError`, a wrong private-key
  length is `NoiseError` (the old check only required the two lengths
  to be equal)
- Only the Noise cipher and hash names are accepted (`ChaChaPoly`,
  `AESGCM`; `SHA256`, `SHA512`, `BLAKE2b`, `BLAKE2s`), case-sensitive,
  resolved through the `Common` tables before any Botan call. Other
  Botan algorithm strings used to construct, including truncated-tag
  AEADs such as `AES-256/GCM(8)` and non-Noise hashes; they now throw
  `ProtocolNotSupportedError`, and a Botan factory failure is a
  `NoiseError`
- HFS protocol names must be one of the 35 registered `hfs` patterns;
  the parser no longer derives an `hfs` variant of any registered base
  (`Noise_Nhfs_…`, `Noise_NNpsk0hfs_…`, `Noise_pqXXhfs_…` are rejected)
- Incompatible pattern/algorithm combinations throw
  `ProtocolNotSupportedError` from the `Protocol` constructors (DH tokens
  with a KEM, KEM tokens with a DH, `e1`/`ekem1` without an HFS KEM or an
  HFS KEM that is not an ML-KEM) instead of failing mid-handshake
- An unknown DH/KEM name throws `ProtocolNotSupportedError` (a
  `NoiseError`, as before) instead of a plain `NoiseError`
- `CipherState::Rekey()` takes no argument and computes Noise spec
  Section 4.2's default REKEY: the first 32 bytes of
  `ENCRYPT(k, 2^64 - 1, zerolen, zeros)` with the state's own AEAD. The
  nonce is unchanged. 1.0.0 derived the key with a caller-selectable
  HKDF (`Rekey(hash_algo)`), so the output changes: peers that rekey must
  both run 1.1.0 or later. The HKDF path was the last place a Botan
  exception (`Botan::Lookup_Error`) could escape; `Rekey` now throws
  `NoiseError` like the rest of the AEAD path
- The exported `HkdfResult` struct is removed. It was an implementation
  detail of `SymmetricState`'s HKDF (undocumented; used nowhere outside
  the library), which is now computed in place without it
- `HandshakeState(HandshakeConfig&&)` is deleted: a `HandshakeState` keeps
  a reference to its config (and, through it, to the `Protocol`), so a
  temporary config dangled at the end of the full expression. Passing a
  temporary no longer compiles; the config and its `Protocol` must outlive
  the state
- `SymmetricState::InitializeSymmetric` takes the protocol name as
  `std::string_view`; the `std::span<const std::uint8_t>` overload is
  removed (a Noise protocol name is an ASCII string, Noise spec
  Section 8). Callers that built a byte span from the name pass the
  string itself
- Intel macOS (x86_64) is no longer supported; macOS builds are Apple
  Silicon only. The `plat_mac_x86` Botan sources
  (`third_party/botan/plat_mac_x86/`) are removed, and configuring on an
  Intel Mac stops with an error
- Default builds require a newer CPU: x86-64-v3 (AVX2) on x86_64 Linux,
  AVX2 on Windows, and Cortex-A76 (ARMv8.2-A) on arm64 Linux, so a
  Raspberry Pi 4 no longer runs a default build. macOS builds are tied
  to the build host's CPU generation. `-DNOISE_BOTAN_ARCH_FLAGS=<flags>`
  overrides the baseline (see Toolchain & Build System)
- `HandshakeDoneError` is renamed `HandshakeComplete`. It marks a completed
  handshake and is not an error: it is stored in `HandshakeStatus::err`
  when the handshake completes and thrown only by a `WriteMessage`/
  `ReadMessage` call made after completion. Code that catches or compares
  the old name must use the new one; there is no alias

### Added
- `Dh::ValidatePublicKey`: length check for DH keys; length plus the
  FIPS 203 Section 7.2 modulus check for ML-KEM encapsulation keys, via
  Botan's key decoder, without keeping a key object
- `HandshakeState::TakeCipherStates()` moves the two transport
  `CipherState` objects out of the status after completion (`std::nullopt`
  before completion or on a second call; `GetStatus().cipherStates` is
  empty afterwards). `HandshakeStatus::state` (`InProgress`, `Done`,
  `Failed`) records the handshake's progress next to `err`, which keeps
  its documented tri-state; `IsComplete()` and `HasError()` read it and
  never throw
- `Noise::DhPrivateKey`, a move-only handle that owns a loaded X25519 or
  X448 key agreement object, with `Dh::LoadPrivateKey(raw)`,
  `Dh::GenerateKeypairWithKey()` (the keypair and its handle from one
  key object) and `Dh::DH(const DhPrivateKey&, peer)`, which costs one
  scalar multiplication instead of the two of `DH(raw_priv, peer)`
  (Botan derives the public key whenever it loads a raw scalar). The
  handle exposes no key bytes and is constructible only by `Dh`. The raw
  overloads stay, reimplemented on the handle
- `Noise::KemPublicKey`, a move-only handle that owns a decoded ML-KEM
  encapsulation key, with `Dh::LoadPublicKey(raw)` (exactly
  `ValidatePublicKey`'s checks, keeping the decoded key) and
  `Dh::Encapsulate(const KemPublicKey&)`, which spends no decode. The
  handle exposes no Botan type and is constructible only by `Dh`. The raw
  `Encapsulate(span)` stays, reimplemented on the handle
- `CMakePresets.json` with Windows-only presets for MSVC and Ninja:
  `windows-release`, `windows-debug` and `windows-release-mt` (the
  static MSVC runtime), each with build and test presets, and a
  `windows-release` workflow (`cmake --workflow --preset
  windows-release` configures, builds and tests). The presets apply
  only on a Windows host; Linux and macOS builds are unchanged

### Changed
- `Protocol::String()` returns `const std::string&` to a name built once
  at construction instead of a new `std::string` from a `stringstream` on
  every call. Callers compile unchanged (`std::string s = p.String();`
  copies as before; `auto` deduces `std::string`)
- `src/` compiles warning-free under a strict warning set (`-Wall
  -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
  -Wold-style-cast -Wcast-align -Wnull-dereference -Wdouble-promotion
  -Wimplicit-fallthrough -Woverloaded-virtual -Wnon-virtual-dtor`, plus
  `-Wunsafe-buffer-usage` on Clang and `-Wduplicated-cond
  -Wduplicated-branches -Wlogical-op -Wuseless-cast
  -Wdangling-reference` on GCC) on Clang 21 and GCC 15. Constructor and
  setter parameters that shadowed public members are renamed
  (`CipherState`, `Protocol`); no public name changes
- `Cipher(CipherAlgo)`, `Hash(HashAlgo)` and `Dh(KeyAlgo)` store the enum
  directly, validated against the `Common` tables, and the name
  constructors delegate to them; an out-of-range enum value still throws
  `ProtocolNotSupportedError`
- `MakePSK` rejects a non-digit index suffix (`"psk1x"`), which
  `std::from_chars` used to accept; the index is 1-3 decimal digits
- `SymmetricState::InitializeSymmetric` hashes a name longer than HASHLEN
  in place (`update` and `final` into `h`, as `MixHash` does) instead of
  through `process()`: one temporary fewer per initialization. Most
  registered names are longer than 32 bytes
  (`Noise_XX_25519_ChaChaPoly_BLAKE2s` is 33)
- `scripts/run_benchmarks.sh` builds in its own directory
  (`out/bench-<toolchain>`), configured on every run with
  `-DNOISE_DEBUG_BUILD=OFF`, instead of reusing an IDE build directory
  and its cached options. It picks the toolchain file by host (macOS,
  Linux Clang 21, Linux GCC 15) and runs on Linux as well as macOS. It
  writes results to a new `out/bench-results/<timestamp>-<host>`
  directory, and to the tracked `analysis/data/` only when that is
  passed as `--out-dir`. `system_info.txt` records the commit, the
  compiler, the toolchain file and the build options. New options:
  `--toolchain`, `--build-dir`, `--out-dir`, `--build-only`, `--help`
- The examples (`examples/`, including the six `asio-networking` programs,
  `example_test`, `example_test_pq` and `pattern_zoo`) take the transport
  `CipherState`s with `HandshakeState::TakeCipherStates()` instead of
  copying `GetStatus().cipherStates`, so no second AEAD object is built.
  `examples/README.md` shows the same call. The benchmarks are unchanged.
  `examples/mlkem_sandbox.cpp` keeps the keypairs its timing loops generate
  in a `[[maybe_unused]]` variable, so a default build has no
  `-Wunused-result` warning from the project's own code
- `analysis/scripts/render_results.py` resolves its paths from the
  repository root and writes under `out/render/<data-dir name>/` by default
  (`figures/` and `BENCHMARK_RESULTS.md`), instead of the tracked
  `analysis/figures/` and an absolute path outside the repository. The
  tracked figures are written only when `analysis/figures` is passed as
  `--figures-dir`

### Fixed
- `scripts/run_benchmarks.sh` no longer aborts while waiting for a server
  that is still running: `(( elapsed++ ))` evaluated to 0 on the first
  wait, which `set -e` treats as a failure on bash 4 and later (Linux);
  macOS's bash 3.2 did not stop there
- The two malformed protocol-name forms `Noise_XX_25519+M768_…` (a `+`
  without the `hfs` modifier) and `Noise_XXhfs_25519_…` (`hfs` without
  a `+`) throw `ProtocolNotSupportedError`, as the constructor documents,
  instead of a plain `NoiseError`
- Nonce exhaustion now fires. The check compared against the largest
  `uint64_t` with `>`, so it could never be true: the reserved nonce was
  used as a real nonce and the counter then wrapped to 0, reusing nonces
  under the same key
- Transport messages over `maxMessageSize` are rejected by
  `CipherState::EncryptWithAd` (plaintext plus tag) and `DecryptWithAd`
  (ciphertext) with `MessageSizeError`; the limit was stored but never
  checked. `SymmetricState` passes 65535, the Noise spec Section 3 bound
- A ciphertext shorter than the AEAD tag is rejected with
  `DecryptionError` before it reaches Botan
- A failed `Cipher::Decrypt`/`Encrypt` leaves the destination buffer as
  it was on entry; the nonce is unchanged on every failure
- An ML-KEM key that fails the FIPS 203 check is rejected by the
  `ReadMessage` that carries it (`e`, `s` and HFS `e1` tokens), before
  the observer sees it, instead of by the next `WriteMessage`
- A malformed cipher name such as `ChaChaPoly/)` can no longer raise
  `std::out_of_range` from Botan's algorithm-name parser (found by
  fuzzing); no user string reaches that parser
- AES-GCM's big-endian nonce now follows the algorithm, not the exact
  spelling `AESGCM` (the Botan spelling `AES-256/GCM`, which is no longer
  accepted, used to get a little-endian nonce)
- Transport `CipherState`s and the `SymmetricState` chaining key are
  scrubbed on destruction (`Botan::secure_scrub_memory`); a moved-from
  `CipherState` scrubs its copy of the key too. Before, the final
  chaining key and both transport keys stayed in freed memory and dead
  stack frames
- DH and KEM shared secrets (`ee`, `es`, `se`, `ss`, `ekem`, `skem`,
  `ekem1`) are scrubbed as soon as they have been mixed into the
  chaining key, also when the token handler unwinds
- `HandshakeState::Reset()` scrubs the chaining key before clearing it
  and scrubs all three local keypairs: the library's copies of
  config-provided static and ephemeral keys, and the HFS `e1`
  decapsulation key, which was never wiped. `Reset()` no longer reads
  the `HandshakeConfig`; the caller's keys are untouched
- Handshakes built from one `Protocol` no longer share one Botan hash
  object: every `SymmetricState` owns a clone of the protocol's hash
  (one extra allocation per `HandshakeState`), so a `Protocol` can be
  shared across threads. Before, two concurrent handshakes from the
  same `Protocol` raced on `Hash::hash_function`'s internal buffer
  (ThreadSanitizer reports; mismatched handshake hashes in the new
  two-thread test). The unused `SymmetricState` cipher reference is gone
- `pqN` is one-way like N, K and X (Noise spec Section 7.4): after the
  handshake both sides' second `CipherState` is reset, and the handshake
  decides one-way from the message count rather than the pattern's flag.
  Before, `pqN` was declared without the flag, so both transport
  directions stayed keyed. A pqN application that used the
  responder-to-initiator direction must move to a two-way pattern
- `HandshakePattern::IsValid` rejects an `isOneWay` flag that disagrees
  with the message count (the old check compared the message count with
  itself and could never fail)
- The AEAD nonce encoding no longer depends on the host's byte order: the
  counter bytes are produced by shifting instead of `std::bit_cast`
  (latent on big-endian hosts; the bytes are unchanged on every supported
  platform, and both layouts are pinned by `static_assert`). The
  `std::function` nonce encoder is gone
- Copying a moved-from `SymmetricState` throws `NoiseError` instead of
  dereferencing a null hash object
- On a failed `Cipher::Encrypt`/`Decrypt` the scratch region of the
  destination is scrubbed before the buffer is restored; `Cipher`
  rejects a key that is not 32 bytes with `NoiseError` before it
  touches the output buffer; and `HandshakeState::Reset()` also clears
  the HMAC's keyed state and the HKDF buffers
- In debug builds (`NOISE_DEBUG_BUILD=ON`, the default), the
  `HandshakeObserver` is no longer also called for the `ekem` and `skem`
  tokens; both builds call it for `e`, `s` and `e1` only, as documented
- `pattern_zoo`: the usage text and the DEFER banners report the 23
  deferred patterns it runs (they said 21) and its 84 patterns (it said
  82), and a name it can't run, such as `XX1hfs`, is rejected with the
  usage text instead of a fatal error

### Known issues
- The bundled Botan build does not detect CPU features at run time on
  Linux arm64 (Raspberry Pi 5, AWS Graviton and other aarch64 Linux
  hosts), so it uses its portable code paths there: ChaCha20 without
  NEON, and AES, GHASH and SHA-2 without the ARMv8 instructions. See
  [ISA baseline, optimization and linking](docs/BuildGuide.md#isa-baseline-optimization-and-linking)

### Performance
Measured on an Apple M5 Mac (macOS 26, arm64, Clang 21, Release build)
with measurement harnesses that are not part of this repository.
*Instructions* are instructions retired per benchmark iteration, from
the operating system's per-process counter, over the 41
`bench_handshake` registrations (36 handshakes and 5 key-generation
controls); a row counts as changed only when its change is larger than
0.1 % and clearly larger than the run-to-run spread. *Transport* figures
are instructions per `CipherState::EncryptWithAd`/`DecryptWithAd` call.
*Allocations* are `operator new` calls per operation in the steady
state; Linux x86_64 gives the same counts. Wall time is not reported.

- AEAD encrypt and decrypt work in place: Botan's `finish` sees only the
  16-byte tag, so the two whole-buffer copies per call are gone. A 64 B
  transport encrypt goes from 2 allocations / 192 B to 1 / 80 B; 4
  handshake rows need fewer instructions (largest `PQ/pqXX/M1024`
  −0.48 %), none more
- HKDF is computed in `SymmetricState` as Noise spec Section 4.3 writes
  it, with one HMAC object owned by the state, instead of rebuilding
  Botan's HKDF for every derivation. A SHA-256 `MixKey` goes from 13
  allocations to none, an XX/X25519 handshake pair from 304 to 178; all
  36 handshake rows need fewer instructions (0.4 % to 3.5 %)
- Handshake completion no longer throws and catches an exception
  internally, status polls no longer rethrow `err`, and `Split()` builds
  its pair in place. An XX/X25519 pair goes from 178 to 149 allocations;
  all 36 handshake rows need fewer instructions (0.5 % to 14.1 %, about
  205,000 to 269,000 per pair)
- Every DH token costs one scalar multiplication instead of two, through
  `DhPrivateKey` handles for the ephemeral and static keys: XX goes from
  14 to 10 multiplications per pair, IK and KK from 18 to 12, and the 24
  DH-based rows need 13.4 % to 32.9 % fewer instructions. The raw
  `DH(priv, peer)` overload costs one more allocation
- `Cipher` keys its AEAD once per key instead of once per message:
  AESGCM at 64 B goes from 13,746 to 4,617 transport instructions per
  call (−66 %), ChaChaPoly from 5,073 to 3,840 (−24 %); the handshake
  rows are flat
- Handshake, parse and `Dh` cleanups (no pattern or received-key copies,
  one name resolution per `Dh`, a cached protocol name): parsing a
  protocol name goes from 30 allocations to 16, an XX/X25519 handshake
  pair from 137 to 120
- Each received ML-KEM public key is decoded once, at the `ReadMessage`
  that carries it, and kept for the token that encapsulates to it: the
  28 PQ and HFS handshake rows need 0.27 % to 3.35 % fewer instructions,
  with 11 to 12 fewer allocations per received key

### Documentation
- `docs/BuildGuide.md` gains "ISA baseline, optimization and linking":
  the `NOISE_BOTAN_ARCH_FLAGS` defaults per toolchain and the CPU each
  requires, the `-DNOISE_BOTAN_ARCH_FLAGS=<flags>` override (a Raspberry
  Pi 4 needs `-mcpu=cortex-a72`), the optimization defaults, the static
  C++ runtime on Linux and the per-build-tree outputs. `README.md` lists
  the minimum CPU under Prerequisites
- The docs' own handshake snippets (`README.md`, `docs/API.md`,
  `docs/PatternGuide.md`) take the transport states with
  `TakeCipherStates()`. `docs/API.md`'s exception-handling example no
  longer takes the states inside a `HandshakeComplete` handler: since
  the completing call returns normally, it takes them after
  `IsComplete()`, and the handler marks a call made after completion
- `examples/README.md` and `examples/asio-networking/README.md`: the
  multi-mode programs take the mode as their first argument
  (`noise_server_multi pqxx`, not `--mode pqxx`), and the binaries are
  under `build/bin/examples/asio/`. `docs/BenchmarkingGuide.md` counts
  41 `bench_handshake` registrations and names the 12 network modes, 6 of
  which the automated run covers
- `docs/BuildGuide.md`'s Windows instructions are corrected and tested
  on Windows 11 with Visual Studio 2022 17.14 (MSVC 19.44): configure
  with `-G Ninja` (CMake cannot build `import std` with the Visual
  Studio generator), MSVC 19.44 needs Visual Studio 2022 17.14 rather
  than 17.12, CMake 4.3+ from cmake.org and Ninja are separate installs,
  and the x64 Native Tools Command Prompt sets up the compiler. A new
  "Runtime library" section covers the dynamic MSVC runtime and the
  `-DCMAKE_MSVC_RUNTIME_LIBRARY` option for a static one
- The dependency notes (`README.md`, `docs/BuildGuide.md`,
  `examples/README.md`, `tests/README.md`) no longer say Catch2, asio
  and Google Benchmark are downloaded only "if not found system-wide":
  FetchContent always downloads them. `docs/Architecture.md` no longer
  calls asio header-only; the build compiles it into a static library
- `benchmarks/README.md`'s network-benchmark commands use the programs'
  real options (`--mode`, `--count`, `--iterations`, `--clients`,
  `--output`) and default port (12346, also in its Troubleshooting), and it and
  `docs/BenchmarkingGuide.md` say which network modes are supported: the
  six IK and KK modes need the responder's static key before the
  handshake, which the programs don't send yet

### Toolchain & Build System
- **Raised minimum CPU.** Each toolchain now sets an ISA baseline
  (`NOISE_BOTAN_ARCH_FLAGS`), applied project-wide to every C++
  compile and link in every config, so it sets the floor for every
  binary:
  - Linux x86_64 (Clang 21 and GCC 15): `-march=x86-64-v3`, so
    binaries require an AVX2-class (x86-64-v3) CPU
  - Linux arm64 / Raspberry Pi 5: `-mcpu=cortex-a76`, so binaries
    require a Cortex-A76 / ARMv8.2-A CPU (a Raspberry Pi 4 no longer
    qualifies)
  - macOS Apple Silicon: `-mcpu=native`, so binaries are tied to the
    build host's CPU generation
  - Windows MSVC: `/arch:AVX2`
- The ISA baseline is a configure-time cache default, overridable on
  every platform with `-DNOISE_BOTAN_ARCH_FLAGS=<flags>`, e.g. for an
  older CPU such as a Raspberry Pi 4 (`-mcpu=cortex-a72`)
- Linux executables link the C++ runtime statically (libc++ and
  libc++abi with Clang 21, libstdc++ with GCC 15) and need only glibc
  and `libgcc_s` at run time. macOS is unchanged. Existing build dirs
  need a fresh configure, because `*_LINKER_FLAGS_INIT` only seeds a
  new cache
- `botan_static` is always optimized, independent of the build type:
  `-O3` with `-ffunction-sections -fdata-sections` and `NDEBUG` in
  every config (MSVC: `/O2` outside Debug, `/Gy`). Debug test binaries
  run up to about 11x faster
- Link-time optimization (IPO/LTO; ThinLTO on Clang) for Release and
  RelWithDebInfo on `botan_static`, `noisepqc`, and all executables.
  The toolchain files set bitcode-aware archivers (`llvm-ar`/
  `llvm-ranlib` for Clang 21, `gcc-ar-15`/`gcc-ranlib-15` for GCC 15)
- Executables are linked with a dead-strip in every config except
  Debug (`-dead_strip` on macOS, `--gc-sections` on Linux, `/OPT:REF
  /OPT:ICF` on MSVC). Together with LTO, Release executables compared
  with 1.0.0 are 38-64% smaller on macOS; on Linux, with the static C++
  runtime, they range from about 24% smaller to 4% larger
- Benchmark targets and Google Benchmark are no longer built in the
  Ninja Multi-Config Debug config (`--config Debug --target <bench>`
  still builds one on demand)
- Build outputs moved from the source tree to each build tree:
  `NOISEPQC_BIN_DIR` defaults to `${CMAKE_BINARY_DIR}/bin` and can be
  overridden at configure time. Separate build dirs (`build/`, CLion's
  `cmake-build-*`) no longer overwrite each other's binaries
- New `:1.1.0` Docker images, `ghcr.io/nata11/noisepqcpp-clang21-ubuntu26`
  (amd64 and arm64) and `ghcr.io/nata11/noisepqcpp-gcc15-ubuntu26` (amd64
  only), rebuilt from the same Dockerfiles for the new toolchain files (the
  ISA baseline, LTO with bitcode archivers, the static C++ runtime). Their
  tool versions are unchanged: Ubuntu 26.04, Clang 21.1.8, GCC 15.2.0,
  CMake 4.3.5 and Ninja 1.13.2. The earlier images and their digests stay
  published; the 1.1.0 digests are in `docs/DockerGuide.md`
- Updated the dependencies that CMake fetches: Catch2 v3.11.0 to
  v3.16.1, Google Benchmark v1.9.1 to v1.10.0, and asio 1.36.0 to
  1.39.0. FetchContent downloads them on the first configure of each
  build tree and builds them with the project's toolchain

### Testing
- Before release, the library was checked with AddressSanitizer and
  UndefinedBehaviorSanitizer (Debug and Release; Clang 21 on Ubuntu
  26.04 x86_64 and arm64 and on Debian 13 on a Raspberry Pi 5,
  AddressSanitizer with GCC 15) over the full test suite, the examples
  and a replay of 828 seed inputs per host and configuration. It was
  also checked with ThreadSanitizer over the test suite (except the
  three tests that replace the global `operator new`, which cannot link
  with ThreadSanitizer's runtime), and fuzzed with libFuzzer for 15
  minutes per target: protocol names, handshake messages and transport
  messages. No sanitizer report, no fuzz crash, and no exception other
  than `NoiseError` and its subclasses; the 24,085 crash inputs from the
  earlier fuzz runs all end in a `NoiseError`
- Catch2 test discovery uses `PRE_TEST` mode, so under Ninja
  Multi-Config `ctest -C <Config>` runs that config's test binaries.
  Previously `ctest -C Debug` could run the Release binaries

### Repository
- A `.gitignore` is now committed (build trees, IDE files, objects),
  so fresh clones start clean
- `.cache/` (clangd's index) is ignored

## [1.0.0] - 2026-10-19

First stable release. NoisePQC++ 1.0.0 completes the toolchain
modernization: Clang 21, GCC 15.2, CMake 4.3, and Botan 3.13.0
across every supported platform, with all documentation brought in
line.

### Cryptographic Library
- Upgraded Botan from 3.11.1 to 3.13.0; refreshed minimized build
  sources for all six platform targets (macOS x86_64/ARM64,
  Linux x86_64/ARM64 Clang and GCC, Windows x86_64)

### Toolchain & Build System
- Migrated from Clang 18 to Clang 21 (21.1.x) on macOS and Linux
- CMake requirement raised from 4.0 to 4.3; `import std;` experimental
  gate updated for the CMake 4.3.x series
- Consolidated toolchain files:
  - `clang21-macOS-toolchain.cmake` — one file for Apple Silicon and
    Intel; selects the Homebrew LLVM 21 prefix by architecture
  - `clang21-linux-toolchain.cmake` — one file for Linux x86_64,
    ARM64, and Raspberry Pi 5 (Ubuntu 26.04 / Debian Trixie packages)
  - `gcc15-linux-toolchain.cmake` — simplified to target Ubuntu 26.04's
    native `gcc-15`/`g++-15` distro packages
  - Removed the separate Raspberry Pi and MSVC toolchain files
    (Windows needs no toolchain file)
- `import std;` discovery now handled directly via
  `CMAKE_CXX_STDLIB_MODULES_JSON` — the previous macOS Homebrew Clang
  workarounds (resource-dir hints, CMake module patching) are no
  longer needed
- macOS SDK pinned to the Command Line Tools `MacOSX26.sdk`, the SDK
  Homebrew LLVM 21's own config uses: `clang-scan-deps` 21 needs an
  explicit sysroot, and SDK 27 (Xcode 27.1) is incompatible with
  LLVM 21's libc++ headers
- Benchmark automation script updated to the Clang 21 toolchain

### Platform Support
- Linux (x86_64, ARM64) with Clang 21.1.x and GCC 15.2 — verified on
  Ubuntu 26.04
- Raspberry Pi 5 (ARM64, Debian Trixie) with Clang 21.1.x from
  trixie-backports — full test suite verified
- macOS (ARM64) with Homebrew LLVM 21 and the macOS 26 SDK — verified
  on Apple Silicon
- macOS (x86_64, Intel) — **untested**: the build should work, pinned
  to the macOS 26 SDK, but it was not verified for this release. The
  Intel Botan sources (`third_party/botan/plat_mac_x86/`) will be
  removed in a future release
- Windows (x86_64) with MSVC 19.44+ and CMake 4.3+

### Container Images
- New Ubuntu 26.04 Docker images with CMake 4.3.5 added alongside the
  existing ones: `docker/clang21-ubuntu26/` (Clang 21; amd64 + arm64)
  and `docker/gcc15-ubuntu26/` (GCC 15.2 distro packages; amd64 only).
  The 0.9.0 Debian Trixie images (`docker/clang18-linux/`,
  `docker/gcc15-linux/`) are retained unchanged as the paper-pinned
  artifact

### Documentation
- Full documentation sweep for the new toolchain: main README,
  BuildGuide, BenchmarkingGuide, LoggingAndDebugging, Architecture,
  DockerGuide, and the examples/tests/benchmarks READMEs
- Removed obsolete Clang 18 `import std;` workaround instructions
- Rewrote the GCC build path for Ubuntu 26.04 (`build-essential`)

## [0.9.0] - 2026-04-25

First public release of NoisePQC++.

### Cryptographic Primitives
- **Cipher**: ChaCha20-Poly1305 and AES-256-GCM AEAD via Botan 3.11.1
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
- Botan 3.11.1 minimized build source included for all supported platforms
- Multi-config build support (Debug/Release)

### Container Images
- Multi-arch (amd64, arm64) Docker images published to GHCR for Clang 18 and GCC 15
- Debian Trixie base; CMake 4.0.4, Ninja 1.12.1, Python analysis stack pre-installed
- Reproducible pulls by SHA256 digest documented in `docs/DockerGuide.md`
