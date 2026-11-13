//
// Copyright 2024-2026 Nadeem Ahmed
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// For research citation guidance, see RESEARCH-CITATION.md.
//

//
// Wiping Tests using Catch2 v3
//
// Secret material (shared secrets, the chaining key, transport keys, local private keys)
// must be scrubbed before the memory that held it is freed. This translation unit replaces
// the global allocation functions with a hook that, while armed, scans every block being
// freed for a set of registered needles. Replacing the global allocator has no form other
// than raw pointers and malloc/free, so those C constructs are unavoidable here and are
// confined to the hook and to the hook's own self-test.
//
// Test hygiene: needles live in std::arrays on the stack; every test-owned heap buffer that
// holds a needle value stays alive until after the hook is disarmed; no Catch2 macro runs
// while the hook is armed (results are computed into plain values and asserted afterwards).
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>

#if defined(__APPLE__)
#include <malloc/malloc.h>
#elif defined(__linux__)
#include <malloc.h>
#elif defined(_WIN32)
#include <malloc.h>  // _msize, _aligned_malloc, _aligned_msize, _aligned_free (UCRT)
#endif

import noise;

using namespace Noise;

// ================================
// Freed-memory needle hook
// ================================

namespace hook {

constexpr std::size_t kMaxNeedles = 16;
constexpr std::size_t kMaxHits = 64;

/** One needle found in a block that was being freed. */
struct Hit {
    std::size_t needle{0};  ///< Index of the needle in the registered set.
    std::size_t block{0};   ///< Size of the freed block (requested size, or the allocator's usable size).
};

/** What the hook saw between Arm() and Disarm(). */
struct Result {
    std::array<Hit, kMaxHits> hits{};
    std::size_t hitCount{0};  ///< Total hits, including any beyond the kMaxHits recorded.
    std::uint64_t frees{0};   ///< Frees seen while armed.
};

constinit bool g_armed{false};
constinit std::array<std::span<const std::uint8_t>, kMaxNeedles> g_needles{};
constinit std::size_t g_needleCount{0};
constinit Result g_result{};

/** The allocator's usable size of a block whose requested size is unknown (unsized delete). */
std::size_t UsableSize(void* p) {
#if defined(__APPLE__)
    return ::malloc_size(p);
#elif defined(__linux__)
    return ::malloc_usable_size(p);
#elif defined(_WIN32)
    return ::_msize(p);
#else
    (void)p;
    return 0;
#endif
}

/** Scans a block that is about to be freed. Never allocates. */
void Scan(void* p, const std::size_t n) {
    if (!g_armed || p == nullptr) return;
    ++g_result.frees;
    const std::span<const std::uint8_t> block{static_cast<const std::uint8_t*>(p), n};
    for (std::size_t i = 0; i < g_needleCount; ++i) {
        const auto needle = g_needles[i];
        if (needle.empty() || needle.size() > block.size()) continue;
        if (!std::ranges::search(block, needle).empty()) {
            if (g_result.hitCount < kMaxHits) {
                g_result.hits[g_result.hitCount] = Hit{i, n};
            }
            ++g_result.hitCount;
        }
    }
}

/** Registers the needles (at most kMaxNeedles; the spans must outlive the window) and arms the hook. */
void Arm(const std::span<const std::span<const std::uint8_t>> needles) {
    g_needleCount = std::min(needles.size(), kMaxNeedles);
    for (std::size_t i = 0; i < g_needleCount; ++i) {
        g_needles[i] = needles[i];
    }
    g_result = Result{};
    g_armed = true;
}

/** Disarms the hook and returns what it saw. */
Result Disarm() {
    g_armed = false;
    return g_result;
}

void* RawAlloc(const std::size_t n) {
    return std::malloc(n == 0 ? 1 : n);
}

void* AlignedAlloc(const std::size_t n, const std::align_val_t al) {
    const auto a = static_cast<std::size_t>(al);
#if defined(_WIN32)
    return ::_aligned_malloc(n == 0 ? 1 : n, a);  // the UCRT has no std::aligned_alloc
#else
    return std::aligned_alloc(a, ((n == 0 ? 1 : n) + a - 1) / a * a);
#endif
}

void FreeSized(void* p, const std::size_t n) {
    Scan(p, n);
    std::free(p);
}

void FreeUnsized(void* p) {
    if (p != nullptr) Scan(p, UsableSize(p));
    std::free(p);
}

/** Frees a block from AlignedAlloc (sized). On Windows it must go back through _aligned_free. */
void AlignedFreeSized(void* p, const std::size_t n) {
#if defined(_WIN32)
    Scan(p, n);
    ::_aligned_free(p);
#else
    FreeSized(p, n);
#endif
}

/** Frees a block from AlignedAlloc (unsized). On Windows it must go back through _aligned_free. */
void AlignedFreeUnsized(void* p, const std::align_val_t al) {
#if defined(_WIN32)
    if (p != nullptr) Scan(p, ::_aligned_msize(p, static_cast<std::size_t>(al), 0));
    ::_aligned_free(p);
#else
    (void)al;
    FreeUnsized(p);
#endif
}

} // namespace hook

// All 20 replaceable global allocation functions, backed by malloc/free (aligned_alloc, or
// _aligned_malloc/_aligned_free on Windows), with no header added. Each operator delete
// receives a block from its matching operator new form, as the standard requires, so an
// aligned block always reaches the aligned free.

void* operator new(std::size_t n) {
    void* p = hook::RawAlloc(n);
    if (p == nullptr) throw std::bad_alloc{};
    return p;
}
void* operator new[](std::size_t n) { return ::operator new(n); }
void* operator new(std::size_t n, const std::nothrow_t&) noexcept { return hook::RawAlloc(n); }
void* operator new[](std::size_t n, const std::nothrow_t& t) noexcept { return ::operator new(n, t); }
void* operator new(std::size_t n, std::align_val_t al) {
    void* p = hook::AlignedAlloc(n, al);
    if (p == nullptr) throw std::bad_alloc{};
    return p;
}
void* operator new[](std::size_t n, std::align_val_t al) { return ::operator new(n, al); }
void* operator new(std::size_t n, std::align_val_t al, const std::nothrow_t&) noexcept {
    return hook::AlignedAlloc(n, al);
}
void* operator new[](std::size_t n, std::align_val_t al, const std::nothrow_t& t) noexcept {
    return ::operator new(n, al, t);
}

void operator delete(void* p) noexcept { hook::FreeUnsized(p); }
void operator delete[](void* p) noexcept { hook::FreeUnsized(p); }
void operator delete(void* p, std::size_t n) noexcept { hook::FreeSized(p, n); }
void operator delete[](void* p, std::size_t n) noexcept { hook::FreeSized(p, n); }
void operator delete(void* p, const std::nothrow_t&) noexcept { hook::FreeUnsized(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { hook::FreeUnsized(p); }
void operator delete(void* p, std::align_val_t al) noexcept { hook::AlignedFreeUnsized(p, al); }
void operator delete[](void* p, std::align_val_t al) noexcept { hook::AlignedFreeUnsized(p, al); }
void operator delete(void* p, std::size_t n, std::align_val_t) noexcept { hook::AlignedFreeSized(p, n); }
void operator delete[](void* p, std::size_t n, std::align_val_t) noexcept { hook::AlignedFreeSized(p, n); }
void operator delete(void* p, std::align_val_t al, const std::nothrow_t&) noexcept { hook::AlignedFreeUnsized(p, al); }
void operator delete[](void* p, std::align_val_t al, const std::nothrow_t&) noexcept { hook::AlignedFreeUnsized(p, al); }

// ================================
// Helpers
// ================================

namespace {

/** A pointer stored here has escaped, so the compiler cannot elide the allocation that produced it. */
volatile const void* g_escape = nullptr;

/**
 * Writes the needle through volatile stores. A plain copy into a block that is about to be
 * deleted is a dead store (GCC's allocation DSE removes it at -O2 and above, Release and LTO),
 * and the hook would then scan a block that never held the needle.
 */
void WriteVolatile(std::uint8_t* block, const std::span<const std::uint8_t> needle) {
    volatile std::uint8_t* dst = block;
    for (const auto byte : needle) {
        *dst++ = byte;
    }
}

using Needle = std::array<std::uint8_t, SYMMETRIC_KEY_SIZE>;

/** A non-zero 32-byte pattern that differs per seed. */
Needle MakePattern(const std::uint8_t seed) {
    Needle out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(seed + 0x1D * i + 1);
    }
    return out;
}

/** Copies a 32-byte secret into a stack array (the needle form). */
Needle ToNeedle(const std::span<const std::uint8_t> bytes) {
    Needle out{};
    if (bytes.size() == out.size()) {
        std::ranges::copy(bytes, out.begin());
    }
    return out;
}

/** "name@block, ..." for the report; built after the hook is disarmed. */
std::string Describe(const hook::Result& result, const std::span<const std::string_view> names) {
    std::string text;
    const auto recorded = std::min(result.hitCount, hook::kMaxHits);
    for (std::size_t i = 0; i < recorded; ++i) {
        const auto& hit = result.hits[i];
        if (!text.empty()) text += ", ";
        text += hit.needle < names.size() ? std::string{names[hit.needle]} : std::to_string(hit.needle);
        text += '@';
        text += std::to_string(hit.block);
    }
    return text.empty() ? std::string{"none"} : text;
}

} // namespace

// ================================
// Tests
// ================================

TEST_CASE("Wiping - the needle hook sees freed buffers", "[wiping][hook]") {
    // Harness self-test. Without it, a broken hook would make the other wiping tests pass
    // vacuously.
    const Needle needle = MakePattern(0x5A);
    const std::array<std::span<const std::uint8_t>, 1> needles{needle};

    hook::Arm(needles);
    {
        // (a) an explicit operator new block, freed with the sized operator delete
        void* a = ::operator new(64);
        WriteVolatile(static_cast<std::uint8_t*>(a), needle);
        ::operator delete(a, 64);

        // (b) the same, freed with the unsized operator delete (size from the allocator)
        void* b = ::operator new(64);
        WriteVolatile(static_cast<std::uint8_t*>(b), needle);
        ::operator delete(b);

        // (c) a new-expression whose pointer escapes, so it cannot be elided; the fill is
        //     volatile so that it survives dead-store elimination before the delete-expression
        auto c = std::make_unique<std::array<std::uint8_t, 64>>();
        WriteVolatile(c->data(), needle);
        g_escape = c.get();
        c.reset();
    }
    const auto result = hook::Disarm();

    constexpr std::array<std::string_view, 1> names{"needle"};
    INFO("hits: " << Describe(result, names) << "; frees: " << result.frees);
    REQUIRE(result.hitCount == 3);
    REQUIRE(result.frees >= 3);
    for (std::size_t i = 0; i < 3; ++i) {
        CHECK(result.hits[i].needle == 0);
        CHECK(result.hits[i].block >= 64);
    }
}

TEST_CASE("Wiping - SymmetricState destructor scrubs the chaining key", "[wiping][symmetricstate]") {
    const Cipher cipher{ChaChaPoly};
    const Hash hash{SHA256};
    const std::string protocolName{"Noise_XX_25519_ChaChaPoly_SHA256"};
    const Needle ikm = MakePattern(0x33);

    auto ss = std::make_unique<SymmetricState>(cipher, hash);
    ss->InitializeSymmetric(protocolName);
    ss->MixKey(ikm);
    const Needle ck = ToNeedle(ss->ck);
    const std::array<std::span<const std::uint8_t>, 1> needles{ck};

    hook::Arm(needles);
    ss.reset();
    const auto result = hook::Disarm();

    constexpr std::array<std::string_view, 1> names{"ck"};
    INFO("hits: " << Describe(result, names) << "; frees: " << result.frees);
    REQUIRE(result.hitCount == 0);
    REQUIRE(result.frees > 0);
}

TEST_CASE("Wiping - XX handshake leaves no secret in freed memory", "[wiping][handshake]") {
    const Protocol protocol{"Noise_XX_25519_ChaChaPoly_SHA256"};

    // Both sides use config-provided ephemeral and static keypairs, so every secret of the
    // handshake is known in advance. The keypairs stay alive until after the window.
    const KeyPair eI = protocol.dh.GenerateKeypair();
    const KeyPair sI = protocol.dh.GenerateKeypair();
    const KeyPair eR = protocol.dh.GenerateKeypair();
    const KeyPair sR = protocol.dh.GenerateKeypair();

    // XX: -> e; <- e, ee, s, es; -> s, se. Reference derivation through the public API; the
    // reference objects and vectors stay alive until after the window (a block freed before the
    // window could be reused and its stale bytes scanned as slack).
    const auto ee = protocol.dh.DH(eI.private_key, eR.public_key);
    const auto es = protocol.dh.DH(eI.private_key, sR.public_key);
    const auto se = protocol.dh.DH(sI.private_key, eR.public_key);
    const std::string protocolName = protocol.String();
    SymmetricState reference{protocol.cipher, protocol.hash};
    reference.InitializeSymmetric(protocolName);
    reference.MixKey(ee);
    reference.MixKey(es);
    reference.MixKey(se);
    const auto [c1, c2] = reference.Split();

    const Needle eeN = ToNeedle(ee), esN = ToNeedle(es), seN = ToNeedle(se);
    const Needle ckN = ToNeedle(reference.ck);
    const Needle k1N = c1.key, k2N = c2.key;
    const Needle eIN = ToNeedle(eI.private_key), sIN = ToNeedle(sI.private_key);
    const Needle eRN = ToNeedle(eR.private_key), sRN = ToNeedle(sR.private_key);
    const std::array<std::span<const std::uint8_t>, 10> needles{eeN, esN, seN, ckN, k1N, k2N, eIN, sIN, eRN, sRN};
    constexpr std::array<std::string_view, 10> names{"ee", "es", "se", "ck", "k1", "k2",
                                                     "e_i", "s_i", "e_r", "s_r"};

    const HandshakeConfig initiatorCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = sI,
        .localEphemeral = eI
    };
    const HandshakeConfig responderCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = sR,
        .localEphemeral = eR
    };

    bool referenceOk = false;
    hook::Arm(needles);
    {
        auto initiator = std::make_unique<HandshakeState>(initiatorCfg);
        auto responder = std::make_unique<HandshakeState>(responderCfg);
        std::vector<std::uint8_t> message;
        try {
            message = initiator->WriteMessage({});
            (void)responder->ReadMessage(message);
            message = responder->WriteMessage({});
            (void)initiator->ReadMessage(message);
            message = initiator->WriteMessage({});
            (void)responder->ReadMessage(message);
        } catch (const HandshakeComplete&) {
            // completion sentinel
        }

        // The application's copy of the transport states, as GetStatus().cipherStates hands them out.
        auto transport = std::make_unique<std::pair<CipherState, CipherState>>(*initiator->GetStatus().cipherStates);
        referenceOk = std::ranges::equal(transport->first.key, k1N) && std::ranges::equal(transport->second.key, k2N);

        transport.reset();
        initiator.reset();
        responder.reset();
    }
    const auto result = hook::Disarm();

    INFO("hits: " << Describe(result, names) << "; frees: " << result.frees);
    REQUIRE(referenceOk);
    REQUIRE(result.hitCount == 0);
    REQUIRE(result.frees > 0);
}

// Main function for Catch2
int main(int argc, char* argv[]) {
    // Disable all logging during tests for clean output
    Noise::DisableAllLogging();
    return Catch::Session().run(argc, argv);
}
