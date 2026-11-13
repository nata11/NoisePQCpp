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


// Pattern zoo: runs a complete handshake for any of 84 Noise patterns (not the 23 deferred
// HFS patterns), by name or by category, with comprehensive logging in debug builds

import noise;

// Platform-specific symbols for cross-platform compatibility
#ifdef _WIN32
    constexpr std::string_view CHECK_MARK = "[OK]";
    constexpr std::string_view CROSS_MARK = "[!!]";
#else
    constexpr std::string_view CHECK_MARK = "✓";
    constexpr std::string_view CROSS_MARK = "✗";
#endif

// Helper function to compare byte vectors
bool bytes_equal(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
    if (a.size() != b.size()) return false;
    return std::memcmp(a.data(), b.data(), a.size()) == 0;
}

// Helper function to print separator
void print_separator(const std::string& title) {
    std::println("\n{}", std::string(80, '='));
    std::println("{}  {}", std::string(5, ' '), title);
    std::println("{}", std::string(80, '='));
}

void print_subsection(const std::string& title) {
    std::println("\n{}", std::string(80, '-'));
    std::println("  {}", title);
    std::println("{}", std::string(80, '-'));
}

// Structure to hold pattern test configuration
struct PatternTestConfig {
    std::string patternName;
    std::string description;
    bool needsInitiatorStatic;
    bool needsResponderStatic;
    bool initiatorKnowsResponderStatic;
    bool responderKnowsInitiatorStatic;
    int expectedMessages;
    bool isPQ = false;   // Post-Quantum pattern (uses KEM instead of DH)
    bool isHFS = false;  // Hybrid Forward Secrecy pattern (uses DH + KEM)
};

// Get configuration for each pattern
PatternTestConfig get_pattern_config(const std::string& patternName) {
    // One-Way Patterns
    if (patternName == "N") return {"N", "One-way pattern, no initiator authentication", false, true, true, false, 1};
    if (patternName == "K") return {"K", "One-way pattern, mutual knowledge of static keys", true, true, true, true, 1};
    if (patternName == "X") return {"X", "One-way pattern, initiator sends static key", true, true, true, false, 1};

    // Fundamental Interactive Patterns
    if (patternName == "NN") return {"NN", "Ephemeral-only, no authentication", false, false, false, false, 2};
    if (patternName == "NK") return {"NK", "Initiator knows responder's static key", false, true, true, false, 2};
    if (patternName == "NX") return {"NX", "Responder sends static key", false, true, false, false, 2};
    if (patternName == "KN") return {"KN", "Responder knows initiator's static key", true, false, false, true, 2};
    if (patternName == "KK") return {"KK", "Mutual knowledge of static keys", true, true, true, true, 2};
    if (patternName == "KX") return {"KX", "Initiator static known, responder sends static", true, true, false, true, 2};
    if (patternName == "XN") return {"XN", "Initiator sends static key in message 3", true, false, false, false, 3};
    if (patternName == "XK") return {"XK", "Responder static known, initiator sends static", true, true, true, false, 3};
    if (patternName == "XX") return {"XX", "Mutual authentication, no prior knowledge", true, true, false, false, 3};
    if (patternName == "IN") return {"IN", "Initiator sends static in first message", true, false, false, false, 2};
    if (patternName == "IK") return {"IK", "Initiator knows responder's static key", true, true, true, false, 2};
    if (patternName == "IX") return {"IX", "Initiator sends static first, responder responds", true, true, false, false, 2};

    // Deferred Patterns
    if (patternName == "NK1") return {"NK1", "Deferred: Responder static key in message 2", false, true, true, false, 2};
    if (patternName == "NX1") return {"NX1", "Deferred: Responder sends static in msg 2, es in msg 3", false, true, false, false, 3};
    if (patternName == "X1N") return {"X1N", "Deferred: Init sends static in msg 3", true, false, false, false, 4};
    if (patternName == "X1K") return {"X1K", "Deferred: Init sends static in msg 3, resp known", true, true, true, false, 4};
    if (patternName == "XK1") return {"XK1", "Deferred: Resp static known, init in msg 3", true, true, true, false, 3};
    if (patternName == "X1K1") return {"X1K1", "Deferred: Both send static deferred", true, true, true, false, 4};
    if (patternName == "X1X") return {"X1X", "Deferred: Both send static deferred, no prior", true, true, false, false, 4};
    if (patternName == "XX1") return {"XX1", "Deferred: Resp static deferred to msg 3", true, true, false, false, 3};
    if (patternName == "X1X1") return {"X1X1", "Deferred: Both static deferred (X variant)", true, true, false, false, 4};
    if (patternName == "K1N") return {"K1N", "Deferred: Init static pre-message, deferred se", true, false, false, true, 3};
    if (patternName == "K1K") return {"K1K", "Deferred: Both static pre-message, deferred se", true, true, true, true, 3};
    if (patternName == "KK1") return {"KK1", "Deferred: Both static pre-message, KK variant", true, true, true, true, 2};
    if (patternName == "K1K1") return {"K1K1", "Deferred: Both static pre-message, both deferred", true, true, true, true, 3};
    if (patternName == "K1X") return {"K1X", "Deferred: Init pre-message, resp sends static", true, true, false, true, 3};
    if (patternName == "KX1") return {"KX1", "Deferred: Init pre-message, deferred KX", true, true, false, true, 3};
    if (patternName == "K1X1") return {"K1X1", "Deferred: Init pre-message, resp static deferred", true, true, false, true, 3};
    if (patternName == "I1N") return {"I1N", "Deferred: Init sends static in msg 2", true, false, false, false, 3};
    if (patternName == "I1K") return {"I1K", "Deferred: Init static in msg 2, resp known", true, true, true, false, 3};
    if (patternName == "IK1") return {"IK1", "Deferred: IK with deferred es", true, true, true, false, 2};
    if (patternName == "I1K1") return {"I1K1", "Deferred: Init static msg 2, resp deferred", true, true, true, false, 3};
    if (patternName == "I1X") return {"I1X", "Deferred: Init static msg 2, resp sends static", true, true, false, false, 3};
    if (patternName == "IX1") return {"IX1", "Deferred: IX with deferred operations", true, true, false, false, 3};
    if (patternName == "I1X1") return {"I1X1", "Deferred: Both deferred (I variant)", true, true, false, false, 3};

    // PSK Patterns (One-way)
    if (patternName == "Npsk0") return {"Npsk0", "PSK: N with pre-shared key at start", false, true, true, false, 1};
    if (patternName == "Kpsk0") return {"Kpsk0", "PSK: K with pre-shared key at start", true, true, true, true, 1};
    if (patternName == "Xpsk1") return {"Xpsk1", "PSK: X with pre-shared key after msg 1", true, true, true, false, 1};

    // PSK Patterns (Interactive)
    if (patternName == "NNpsk0") return {"NNpsk0", "PSK: NN with PSK at start", false, false, false, false, 2};
    if (patternName == "NNpsk2") return {"NNpsk2", "PSK: NN with PSK after msg 2", false, false, false, false, 2};
    if (patternName == "NKpsk0") return {"NKpsk0", "PSK: NK with PSK at start", false, true, true, false, 2};
    if (patternName == "NKpsk2") return {"NKpsk2", "PSK: NK with PSK after msg 2", false, true, true, false, 2};
    if (patternName == "NXpsk2") return {"NXpsk2", "PSK: NX with PSK after msg 2", false, true, false, false, 2};
    if (patternName == "XNpsk3") return {"XNpsk3", "PSK: XN with PSK after msg 3", true, false, false, false, 3};
    if (patternName == "XKpsk3") return {"XKpsk3", "PSK: XK with PSK after msg 3", true, true, true, false, 3};
    if (patternName == "XXpsk3") return {"XXpsk3", "PSK: XX with PSK after msg 3", true, true, false, false, 3};
    if (patternName == "KNpsk0") return {"KNpsk0", "PSK: KN with PSK at start", true, false, false, true, 2};
    if (patternName == "KNpsk2") return {"KNpsk2", "PSK: KN with PSK after msg 2", true, false, false, true, 2};
    if (patternName == "KKpsk0") return {"KKpsk0", "PSK: KK with PSK at start", true, true, true, true, 2};
    if (patternName == "KKpsk2") return {"KKpsk2", "PSK: KK with PSK after msg 2", true, true, true, true, 2};
    if (patternName == "KXpsk2") return {"KXpsk2", "PSK: KX with PSK after msg 2", true, true, false, true, 2};
    if (patternName == "INpsk1") return {"INpsk1", "PSK: IN with PSK after msg 1", true, false, false, false, 2};
    if (patternName == "INpsk2") return {"INpsk2", "PSK: IN with PSK after msg 2", true, false, false, false, 2};
    if (patternName == "IKpsk1") return {"IKpsk1", "PSK: IK with PSK after msg 1", true, true, true, false, 2};
    if (patternName == "IKpsk2") return {"IKpsk2", "PSK: IK with PSK after msg 2", true, true, true, false, 2};
    if (patternName == "IXpsk2") return {"IXpsk2", "PSK: IX with PSK after msg 2", true, true, false, false, 2};

    // Post-Quantum (PQNoise) Patterns - One-way
    if (patternName == "pqN") return {"pqN", "PQ: One-way, responder auth", false, true, true, false, 1, true};

    // Post-Quantum (PQNoise) Patterns - Interactive
    if (patternName == "pqNN") return {"pqNN", "PQ: Ephemeral only, no auth", false, false, false, false, 2, true};
    if (patternName == "pqNK") return {"pqNK", "PQ: Initiator knows resp static", false, true, true, false, 2, true};
    if (patternName == "pqNX") return {"pqNX", "PQ: Responder sends static", false, true, false, false, 3, true};
    if (patternName == "pqXN") return {"pqXN", "PQ: Init sends static deferred", true, false, false, false, 4, true};
    if (patternName == "pqXK") return {"pqXK", "PQ: Resp known, init deferred", true, true, true, false, 4, true};
    if (patternName == "pqXX") return {"pqXX", "PQ: Mutual auth, no prior", true, true, false, false, 4, true};
    if (patternName == "pqKN") return {"pqKN", "PQ: Resp knows init static", true, false, false, true, 2, true};
    if (patternName == "pqKK") return {"pqKK", "PQ: Mutual known statics", true, true, true, true, 2, true};
    if (patternName == "pqKX") return {"pqKX", "PQ: Init known, resp sends", true, true, false, true, 3, true};
    if (patternName == "pqIN") return {"pqIN", "PQ: Init sends static immed", true, false, false, false, 2, true};
    if (patternName == "pqIK") return {"pqIK", "PQ: Init immed, knows resp", true, true, true, false, 2, true};
    if (patternName == "pqIX") return {"pqIX", "PQ: Init immed, resp sends", true, true, false, false, 3, true};

    // Hybrid Forward Secrecy (HFS) Patterns - Fundamental Interactive
    // HFS combines classical DH (25519/448) with KEM (ML-KEM) for defense-in-depth
    if (patternName == "NNhfs") return {"NNhfs", "HFS: Ephemeral only, hybrid forward secrecy", false, false, false, false, 2, false, true};
    if (patternName == "NKhfs") return {"NKhfs", "HFS: Initiator knows resp static", false, true, true, false, 2, false, true};
    if (patternName == "NXhfs") return {"NXhfs", "HFS: Responder sends static", false, true, false, false, 2, false, true};
    if (patternName == "KNhfs") return {"KNhfs", "HFS: Responder knows init static", true, false, false, true, 2, false, true};
    if (patternName == "KKhfs") return {"KKhfs", "HFS: Mutual known statics", true, true, true, true, 2, false, true};
    if (patternName == "KXhfs") return {"KXhfs", "HFS: Init known, resp sends static", true, true, false, true, 2, false, true};
    if (patternName == "XNhfs") return {"XNhfs", "HFS: Init sends static in msg 3", true, false, false, false, 3, false, true};
    if (patternName == "XKhfs") return {"XKhfs", "HFS: Resp known, init sends static", true, true, true, false, 3, false, true};
    if (patternName == "XXhfs") return {"XXhfs", "HFS: Mutual auth, no prior knowledge", true, true, false, false, 3, false, true};
    if (patternName == "INhfs") return {"INhfs", "HFS: Init sends static immediately", true, false, false, false, 2, false, true};
    if (patternName == "IKhfs") return {"IKhfs", "HFS: Init immediate, knows resp", true, true, true, false, 2, false, true};
    if (patternName == "IXhfs") return {"IXhfs", "HFS: Init immediate, resp sends", true, true, false, false, 2, false, true};

    throw std::runtime_error("Unknown pattern: " + patternName);
}

// Generic test function for any pattern
void test_pattern(const std::string& patternName) {
    auto config = get_pattern_config(patternName);

    print_separator(std::format("NOISE {} PATTERN TEST", config.patternName));
    std::println("Description: {}", config.description);
    std::println("Expected messages: {}", config.expectedMessages);

    // Create protocol first to access pattern details
    // - PQ patterns: Use M768 (ML-KEM-768) as sole key exchange
    // - HFS patterns: Use 25519+M768 (X25519 DH + ML-KEM-768 KEM) for hybrid security
    // - Classical patterns: Use 25519 (X25519 DH)
    std::string protocolString;
    if (config.isPQ) {
        protocolString = std::format("Noise_{}_M768_ChaChaPoly_BLAKE2s", config.patternName);
    } else if (config.isHFS) {
        protocolString = std::format("Noise_{}_25519+M768_ChaChaPoly_BLAKE2s", config.patternName);
    } else {
        protocolString = std::format("Noise_{}_25519_ChaChaPoly_BLAKE2s", config.patternName);
    }
    Noise::Protocol protocol{protocolString};

    std::println("");
    std::println("Pattern structure:");
    protocol.pattern.describe(std::cout);

    print_subsection("Setup: Generating keypairs");

    // Generate static keypairs if needed
    Noise::KeyPair aliceStatic, bobStatic;
    if (config.needsInitiatorStatic) {
        aliceStatic = protocol.dh.GenerateKeypair();
        std::println("Alice static key generated");
    }
    if (config.needsResponderStatic) {
        bobStatic = protocol.dh.GenerateKeypair();
        std::println("Bob static key generated");
    }

    // Generate PSK if pattern requires it
    std::vector<std::array<std::uint8_t, Noise::SYMMETRIC_KEY_SIZE>> preSharedKeys;
    if (patternName.find("psk") != std::string::npos) {
        std::array<std::uint8_t, Noise::SYMMETRIC_KEY_SIZE> psk{};
        std::ranges::fill(psk, 0x42);  // Fill with 0x42 for demo
        preSharedKeys.push_back(psk);
        std::println("Pre-shared key generated (32 bytes)");
    }

    // Create handshake configs
    Noise::HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic,
        .remoteStatic = config.initiatorKnowsResponderStatic ? bobStatic.public_key : Noise::PublicKey{},
        .preSharedKeys = preSharedKeys
    };

    Noise::HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic,
        .remoteStatic = config.responderKnowsInitiatorStatic ? aliceStatic.public_key : Noise::PublicKey{},
        .preSharedKeys = preSharedKeys
    };

    // Create handshake states
    Noise::HandshakeState aliceHs{aliceCfg};
    Noise::HandshakeState bobHs{bobCfg};
    std::println("Handshake states created");

    // Perform handshake
    std::vector<std::uint8_t> msg;
    bool aliceTurn = true;
    int messageCount = 0;

    while (!aliceHs.GetStatus().IsComplete() || !bobHs.GetStatus().IsComplete()) {
        messageCount++;
        print_subsection(std::format("Message {}: {} -> {}",
            messageCount,
            aliceTurn ? "Alice (Initiator)" : "Bob (Responder)",
            aliceTurn ? "Bob (Responder)" : "Alice (Initiator)"));

        try {
            if (aliceTurn) {
                // Alice sends
                std::vector<std::uint8_t> payload{'m', 's', 'g', static_cast<std::uint8_t>('0' + messageCount)};
                msg = aliceHs.WriteMessage(payload);

                // Bob receives
                auto recv = bobHs.ReadMessage(msg);
                if (bytes_equal(recv, payload)) {
                    std::println("{} Payload verified", CHECK_MARK);
                }
            } else {
                // Bob sends
                std::vector<std::uint8_t> payload{'m', 's', 'g', static_cast<std::uint8_t>('0' + messageCount)};
                msg = bobHs.WriteMessage(payload);

                // Alice receives
                auto recv = aliceHs.ReadMessage(msg);
                if (bytes_equal(recv, payload)) {
                    std::println("{} Payload verified", CHECK_MARK);
                }
            }
        } catch (const std::exception& e) {
            std::println(std::cerr, "ERROR during message {}: {}", messageCount, e.what());
            return;
        }

        aliceTurn = !aliceTurn;

        // Safety check to prevent infinite loops
        if (messageCount > 10) {
            std::println(std::cerr, "ERROR: Too many messages, possible infinite loop");
            return;
        }
    }

    // Verification
    print_subsection("Verification");
    const auto& aliceStatus = aliceHs.GetStatus();
    const auto& bobStatus = bobHs.GetStatus();

    if (aliceStatus.IsComplete() && bobStatus.IsComplete()) {
        std::println("{} Both sides report handshake complete", CHECK_MARK);
    } else {
        std::println(std::cerr, "{} Handshake not complete on both sides", CROSS_MARK);
        return;
    }

    if (bytes_equal(aliceStatus.handshakeHash, bobStatus.handshakeHash)) {
        std::println("{} Handshake hashes match", CHECK_MARK);
    } else {
        std::println(std::cerr, "{} Handshake hash mismatch", CROSS_MARK);
        return;
    }

    // Verify static key exchange if applicable
    if (config.needsInitiatorStatic && !config.responderKnowsInitiatorStatic) {
        if (!aliceStatic.public_key.empty() && bytes_equal(bobStatus.remoteStatic, aliceStatic.public_key)) {
            std::println("{} Bob learned Alice's static key", CHECK_MARK);
        }
    }
    if (config.needsResponderStatic && !config.initiatorKnowsResponderStatic) {
        if (!bobStatic.public_key.empty() && bytes_equal(aliceStatus.remoteStatic, bobStatic.public_key)) {
            std::println("{} Alice learned Bob's static key", CHECK_MARK);
        }
    }

    // Test post-handshake transport (not for one-way patterns)
    if (config.expectedMessages >= 2) {
        print_subsection("Post-Handshake Transport: Alice -> Bob");
        auto aliceCs = aliceHs.TakeCipherStates();
        auto bobCs = bobHs.TakeCipherStates();
        if (!aliceCs || !bobCs) {
            std::println(std::cerr, "{} Cipher states not available", CROSS_MARK);
            return;
        }
        auto& [aliceTx, aliceRx] = *aliceCs;
        auto& [bobRx, bobTx] = *bobCs;

        std::vector<std::uint8_t> transportMsg1{'t', 'r', 'a', 'n', 's', 'p', 'o', 'r', 't', '1'};
        auto encrypted1 = aliceTx.EncryptWithAd({}, transportMsg1);
        auto decrypted1 = bobRx.DecryptWithAd({}, encrypted1);

        if (bytes_equal(transportMsg1, decrypted1)) {
            std::println("{} Alice -> Bob transport message successful", CHECK_MARK);
        }

        print_subsection("Post-Handshake Transport: Bob -> Alice");
        std::vector<std::uint8_t> transportMsg2{'t', 'r', 'a', 'n', 's', 'p', 'o', 'r', 't', '2'};
        auto encrypted2 = bobTx.EncryptWithAd({}, transportMsg2);
        auto decrypted2 = aliceRx.DecryptWithAd({}, encrypted2);

        if (bytes_equal(transportMsg2, decrypted2)) {
            std::println("{} Bob -> Alice transport message successful", CHECK_MARK);
        }

        aliceTx.Reset();
        aliceRx.Reset();
        bobTx.Reset();
        bobRx.Reset();
    }

    std::println("\n{}{}{} {} PATTERN TEST PASSED {}{}{}", CHECK_MARK, CHECK_MARK, CHECK_MARK, config.patternName, CHECK_MARK, CHECK_MARK, CHECK_MARK);
}

// The patterns this program runs, by category: exactly the names get_pattern_config knows.
// Each size is deduced from its list, so the counts printed below can't drift from what runs.
constexpr auto ONE_WAY_PATTERNS = std::to_array<std::string_view>({"N", "K", "X"});
constexpr auto INTERACTIVE_PATTERNS = std::to_array<std::string_view>({
    "NN", "NK", "NX", "KN", "KK", "KX", "XN", "XK", "XX", "IN", "IK", "IX"
});
constexpr auto DEFERRED_PATTERNS = std::to_array<std::string_view>({
    "NK1", "NX1", "X1N", "X1K", "XK1", "X1K1", "X1X", "XX1", "X1X1",
    "K1N", "K1K", "KK1", "K1K1", "K1X", "KX1", "K1X1",
    "I1N", "I1K", "IK1", "I1K1", "I1X", "IX1", "I1X1"
});
constexpr auto PSK_PATTERNS = std::to_array<std::string_view>({
    "Npsk0", "Kpsk0", "Xpsk1",
    "NNpsk0", "NNpsk2", "NKpsk0", "NKpsk2", "NXpsk2",
    "XNpsk3", "XKpsk3", "XXpsk3",
    "KNpsk0", "KNpsk2", "KKpsk0", "KKpsk2", "KXpsk2",
    "INpsk1", "INpsk2", "IKpsk1", "IKpsk2", "IXpsk2"
});
constexpr auto PQ_PATTERNS = std::to_array<std::string_view>({
    "pqN",  // One-way
    "pqNN", "pqNK", "pqNX", "pqXN", "pqXK", "pqXX",
    "pqKN", "pqKK", "pqKX", "pqIN", "pqIK", "pqIX"
});
constexpr auto HFS_PATTERNS = std::to_array<std::string_view>({
    "NNhfs", "NKhfs", "NXhfs", "KNhfs", "KKhfs", "KXhfs",
    "XNhfs", "XKhfs", "XXhfs", "INhfs", "IKhfs", "IXhfs"
});
constexpr std::size_t PATTERN_COUNT = ONE_WAY_PATTERNS.size() + INTERACTIVE_PATTERNS.size() +
                                      DEFERRED_PATTERNS.size() + PSK_PATTERNS.size() +
                                      PQ_PATTERNS.size() + HFS_PATTERNS.size();

static_assert(ONE_WAY_PATTERNS.size() == 3);
static_assert(INTERACTIVE_PATTERNS.size() == 12);
static_assert(DEFERRED_PATTERNS.size() == 23);
static_assert(PSK_PATTERNS.size() == 21);
static_assert(PQ_PATTERNS.size() == 13);
static_assert(HFS_PATTERNS.size() == 12);
static_assert(PATTERN_COUNT == 84);

void print_usage(const char* programName) {
    std::println("Usage: {} <PATTERN|CATEGORY>", programName);
    std::println("");
    std::println("PATTERN must be one of {} available patterns (case-sensitive):", PATTERN_COUNT);
    std::println("");
    std::println("Category Options:");
    std::println("  ONEWAY           - Run all One-Way patterns ({} tests)", ONE_WAY_PATTERNS.size());
    std::println("  BASIC            - Run all Fundamental Interactive patterns ({} tests)", INTERACTIVE_PATTERNS.size());
    std::println("  DEFER            - Run all Deferred patterns ({} tests)", DEFERRED_PATTERNS.size());
    std::println("  PSK              - Run all PSK patterns ({} tests)", PSK_PATTERNS.size());
    std::println("  PQC              - Run all Post-Quantum patterns ({} tests)", PQ_PATTERNS.size());
    std::println("  HFS              - Run all Hybrid Forward Secrecy patterns ({} tests)", HFS_PATTERNS.size());
    std::println("");
    std::println("  One-Way Patterns ({}):", ONE_WAY_PATTERNS.size());
    std::println("    N, K, X");
    std::println("");
    std::println("  Fundamental Interactive Patterns ({}):", INTERACTIVE_PATTERNS.size());
    std::println("    NN, NK, NX, KN, KK, KX, XN, XK, XX, IN, IK, IX");
    std::println("");
    std::println("  Deferred Patterns ({}):", DEFERRED_PATTERNS.size());
    std::println("    NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1,");
    std::println("    K1N, K1K, KK1, K1K1, K1X, KX1, K1X1,");
    std::println("    I1N, I1K, IK1, I1K1, I1X, IX1, I1X1");
    std::println("");
    std::println("  PSK Patterns ({}):", PSK_PATTERNS.size());
    std::println("    Npsk0, Kpsk0, Xpsk1,");
    std::println("    NNpsk0, NNpsk2, NKpsk0, NKpsk2, NXpsk2,");
    std::println("    XNpsk3, XKpsk3, XXpsk3,");
    std::println("    KNpsk0, KNpsk2, KKpsk0, KKpsk2, KXpsk2,");
    std::println("    INpsk1, INpsk2, IKpsk1, IKpsk2, IXpsk2");
    std::println("");
    std::println("  Post-Quantum (PQNoise) Patterns ({}):", PQ_PATTERNS.size());
    std::println("    pqN (one-way)");
    std::println("    pqNN, pqNK, pqNX, pqXN, pqXK, pqXX,");
    std::println("    pqKN, pqKK, pqKX, pqIN, pqIK, pqIX");
    std::println("");
    std::println("  Hybrid Forward Secrecy (HFS) Patterns ({}):", HFS_PATTERNS.size());
    std::println("    NNhfs, NKhfs, NXhfs, KNhfs, KKhfs, KXhfs,");
    std::println("    XNhfs, XKhfs, XXhfs, INhfs, IKhfs, IXhfs");
    std::println("");
    std::println("Examples:");
    std::println("  {} XX           - Run only the XX pattern test", programName);
    std::println("  {} XXpsk3       - Run the XX pattern with PSK modifier", programName);
    std::println("  {} X1X1         - Run the X1X1 deferred pattern", programName);
    std::println("  {} BASIC        - Run all {} fundamental interactive patterns", programName, INTERACTIVE_PATTERNS.size());
    std::println("  {} PSK          - Run all {} PSK patterns", programName, PSK_PATTERNS.size());
    std::println("  {} PQC          - Run all {} post-quantum patterns", programName, PQ_PATTERNS.size());
    std::println("  {} HFS          - Run all {} hybrid forward secrecy patterns", programName, HFS_PATTERNS.size());
}

bool is_valid_pattern(const std::string& pattern) {
    // Check if it's a category option
    if (pattern == "ONEWAY" || pattern == "BASIC" || pattern == "DEFER" ||
        pattern == "PSK" || pattern == "PQC" || pattern == "HFS") {
        return true;
    }

    // Check if it's one of the patterns this program runs. Not every registry name: the
    // registry also holds the 23 deferred HFS patterns, which get_pattern_config doesn't know.
    const std::string_view name{pattern};
    return std::ranges::contains(ONE_WAY_PATTERNS, name) || std::ranges::contains(INTERACTIVE_PATTERNS, name) ||
           std::ranges::contains(DEFERRED_PATTERNS, name) || std::ranges::contains(PSK_PATTERNS, name) ||
           std::ranges::contains(PQ_PATTERNS, name) || std::ranges::contains(HFS_PATTERNS, name);
}

int main(int argc, char* argv[]) {
    try {
        // Check for command-line argument
        if (argc != 2) {
            print_usage(argv[0]);
            return 1;
        }

        std::string requestedPattern = argv[1];

        // Validate pattern
        if (!is_valid_pattern(requestedPattern)) {
            std::println(std::cerr, "Error: Invalid pattern '{}'\n", requestedPattern);
            print_usage(argv[0]);
            return 1;
        }

        // Enable comprehensive logging (a no-op unless built with NOISE_DEBUG_BUILD=ON, the default)
        Noise::EnableAllLogging();

        print_separator("NOISE PROTOCOL HANDSHAKE PATTERNS DEMONSTRATION");
        std::println("Requested Pattern: {}", requestedPattern);
        std::println("");
        std::println("Logging Color Guide:");
        std::println("  {}Cyan{}          = Initiator messages", Noise::Color::BrightCyan, Noise::Color::Reset);
        std::println("  {}Magenta{}       = Responder messages", Noise::Color::BrightMagenta, Noise::Color::Reset);
        std::println("  {}Green{}         = Write operations", Noise::Color::BrightGreen, Noise::Color::Reset);
        std::println("  {}Blue{}          = Read operations", Noise::Color::BrightBlue, Noise::Color::Reset);
        std::println("  {}Yellow{}        = Token processing", Noise::Color::BrightYellow, Noise::Color::Reset);
        std::println("  {}[CIPHER]{}      = Cipher state operations", Noise::Color::Cyan, Noise::Color::Reset);
        std::println("  {}[SYMMETRIC]{}   = Symmetric state operations", Noise::Color::Cyan, Noise::Color::Reset);

        // Get all patterns from registry (used for category tests)
        const auto& registry = Noise::GetPatternRegistry();

        // Run requested test(s)
        if (requestedPattern == "ONEWAY") {
            std::println("\n\nRunning One-Way Patterns ({})...", ONE_WAY_PATTERNS.size());
            for (const std::string_view name : ONE_WAY_PATTERNS) {
                const std::string pattern{name};
                if (registry.contains(pattern)) {
                    test_pattern(pattern);
                }
            }
            print_separator(std::format("ONEWAY: ALL {} TESTS COMPLETED SUCCESSFULLY!", ONE_WAY_PATTERNS.size()));
        } else if (requestedPattern == "BASIC") {
            std::println("\n\nRunning Fundamental Interactive Patterns ({})...", INTERACTIVE_PATTERNS.size());
            for (const std::string_view name : INTERACTIVE_PATTERNS) {
                const std::string pattern{name};
                if (registry.contains(pattern)) {
                    test_pattern(pattern);
                }
            }
            print_separator(std::format("BASIC: ALL {} TESTS COMPLETED SUCCESSFULLY!", INTERACTIVE_PATTERNS.size()));
        } else if (requestedPattern == "DEFER") {
            std::println("\n\nRunning Deferred Patterns ({})...", DEFERRED_PATTERNS.size());
            for (const std::string_view name : DEFERRED_PATTERNS) {
                const std::string pattern{name};
                if (registry.contains(pattern)) {
                    test_pattern(pattern);
                }
            }
            print_separator(std::format("DEFER: ALL {} TESTS COMPLETED SUCCESSFULLY!", DEFERRED_PATTERNS.size()));
        } else if (requestedPattern == "PSK") {
            std::println("\n\nRunning PSK Patterns ({})...", PSK_PATTERNS.size());
            for (const std::string_view name : PSK_PATTERNS) {
                const std::string pattern{name};
                if (registry.contains(pattern)) {
                    test_pattern(pattern);
                }
            }
            print_separator(std::format("PSK: ALL {} TESTS COMPLETED SUCCESSFULLY!", PSK_PATTERNS.size()));
        } else if (requestedPattern == "PQC") {
            std::println("\n\nRunning Post-Quantum (PQ) Patterns ({})...", PQ_PATTERNS.size());
            std::println("Using ML-KEM-768 (M768) for all PQ patterns\n");
            for (const std::string_view name : PQ_PATTERNS) {
                const std::string pattern{name};
                if (registry.contains(pattern)) {
                    test_pattern(pattern);
                }
            }
            print_separator(std::format("PQC: ALL {} TESTS COMPLETED SUCCESSFULLY!", PQ_PATTERNS.size()));
        } else if (requestedPattern == "HFS") {
            std::println("\n\nRunning Hybrid Forward Secrecy (HFS) Patterns ({})...", HFS_PATTERNS.size());
            std::println("Using X25519 + ML-KEM-768 (25519+M768) for hybrid security\n");
            for (const std::string_view name : HFS_PATTERNS) {
                const std::string pattern{name};
                if (registry.contains(pattern)) {
                    test_pattern(pattern);
                }
            }
            print_separator(std::format("HFS: ALL {} TESTS COMPLETED SUCCESSFULLY!", HFS_PATTERNS.size()));
        } else {
            // Run single pattern test
            test_pattern(requestedPattern);
        }

        std::println("");
        return 0;
    } catch (const std::exception& e) {
        std::println(std::cerr, "\n!!! FATAL ERROR: {}", e.what());
        return 1;
    }
}
