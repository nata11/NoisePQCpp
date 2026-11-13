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
// NoisePQC++ Post-Quantum Pattern Tests using Catch2 v3
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>

import noise;

using namespace Noise;

// Helper function to compare byte vectors
static bool bytes_equal(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
    if (a.size() != b.size()) return false;
    return std::memcmp(a.data(), b.data(), a.size()) == 0;
}

// ================================
// PQ Pattern Tests
// ================================

// Helper struct for PQ pattern test configuration
struct PQPatternTestConfig {
    std::string_view name;
    const HandshakePattern& pattern;
    std::string_view kemAlgo;  // M512, M768, or M1024
    bool initiatorNeedsStatic;
    bool responderNeedsStatic;
    bool initiatorNeedsRemoteStatic;
    bool responderNeedsRemoteStatic;
    std::size_t expectedMessages;
};

// Helper function to execute a complete PQ handshake
void test_pq_pattern_handshake(const PQPatternTestConfig& config) {
    Protocol protocol(config.pattern, config.kemAlgo, ChaChaPoly, SHA256);

    // Generate keys as needed
    KeyPair aliceStatic = config.initiatorNeedsStatic
        ? protocol.dh.GenerateKeypair()
        : KeyPair{};

    KeyPair bobStatic = config.responderNeedsStatic
        ? protocol.dh.GenerateKeypair()
        : KeyPair{};

    // Build Alice's (initiator) config
    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic,
        .remoteStatic = (config.initiatorNeedsRemoteStatic && !bobStatic.public_key.empty())
            ? bobStatic.public_key
            : PublicKey{}
    };

    // Build Bob's (responder) config
    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic,
        .remoteStatic = (config.responderNeedsRemoteStatic && !aliceStatic.public_key.empty())
            ? aliceStatic.public_key
            : PublicKey{}
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    // Execute handshake
    std::vector<std::uint8_t> payload{'p', 'q', 't', 'e', 's', 't'};

    for (std::size_t i = 0; i < config.expectedMessages; ++i) {
        if (i % 2 == 0) {
            // Alice (initiator) sends
            auto msg = aliceHs.WriteMessage(i == 0 ? payload : std::vector<std::uint8_t>{});
            REQUIRE_FALSE(msg.empty());

            auto recv = bobHs.ReadMessage(msg);
            if (i == 0) {
                REQUIRE(bytes_equal(recv, payload));
            }
        } else {
            // Bob (responder) sends
            auto msg = bobHs.WriteMessage({});
            REQUIRE_FALSE(msg.empty());

            aliceHs.ReadMessage(msg);
        }
    }

    // Verify completion
    REQUIRE(aliceHs.GetStatus().IsComplete());
    REQUIRE(bobHs.GetStatus().IsComplete());

    // Verify handshake hashes match
    REQUIRE(bytes_equal(aliceHs.GetStatus().handshakeHash, bobHs.GetStatus().handshakeHash));

    // Verify cipher states are available
    REQUIRE(aliceHs.GetStatus().cipherStates.has_value());
    REQUIRE(bobHs.GetStatus().cipherStates.has_value());

    // Verify post-handshake encryption works
    // Copy cipher states since encryption modifies them (nonce increment)
    auto [aliceCS1, aliceCS2] = *aliceHs.GetStatus().cipherStates;
    auto [bobCS1, bobCS2] = *bobHs.GetStatus().cipherStates;

    // Alice encrypts with CS1, Bob decrypts with CS1
    std::vector<std::uint8_t> testMessage{'H', 'e', 'l', 'l', 'o', ' ', 'P', 'Q'};
    auto encrypted = aliceCS1.EncryptWithAd({}, testMessage);
    auto decrypted = bobCS1.DecryptWithAd({}, encrypted);
    REQUIRE(bytes_equal(decrypted, testMessage));
}

// ================================
// pqNN Pattern Tests (No authentication)
// ================================

TEST_CASE("PQ - pqNN pattern with M512", "[pqnoise][pattern][pqnn][m512]") {
    PQPatternTestConfig config{
        .name = "pqNN",
        .pattern = pqNN,
        .kemAlgo = "M512",
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_pq_pattern_handshake(config);
}

TEST_CASE("PQ - pqNN pattern with M768", "[pqnoise][pattern][pqnn][m768]") {
    PQPatternTestConfig config{
        .name = "pqNN",
        .pattern = pqNN,
        .kemAlgo = "M768",
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_pq_pattern_handshake(config);
}

TEST_CASE("PQ - pqNN pattern with M1024", "[pqnoise][pattern][pqnn][m1024]") {
    PQPatternTestConfig config{
        .name = "pqNN",
        .pattern = pqNN,
        .kemAlgo = "M1024",
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_pq_pattern_handshake(config);
}

// ================================
// pqNK Pattern Tests (Responder authentication)
// ================================

TEST_CASE("PQ - pqNK pattern with M512", "[pqnoise][pattern][pqnk][m512]") {
    PQPatternTestConfig config{
        .name = "pqNK",
        .pattern = pqNK,
        .kemAlgo = "M512",
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,   // Initiator knows responder's static
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_pq_pattern_handshake(config);
}

TEST_CASE("PQ - pqNK pattern with M768", "[pqnoise][pattern][pqnk][m768]") {
    PQPatternTestConfig config{
        .name = "pqNK",
        .pattern = pqNK,
        .kemAlgo = "M768",
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_pq_pattern_handshake(config);
}

// ================================
// pqKK Pattern Tests (Mutual authentication, pre-known static keys)
// ================================

TEST_CASE("PQ - pqKK pattern with M512", "[pqnoise][pattern][pqkk][m512]") {
    PQPatternTestConfig config{
        .name = "pqKK",
        .pattern = pqKK,
        .kemAlgo = "M512",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,   // Both know each other's static
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 2
    };

    test_pq_pattern_handshake(config);
}

TEST_CASE("PQ - pqKK pattern with M768", "[pqnoise][pattern][pqkk][m768]") {
    PQPatternTestConfig config{
        .name = "pqKK",
        .pattern = pqKK,
        .kemAlgo = "M768",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 2
    };

    test_pq_pattern_handshake(config);
}

// ================================
// pqXX Pattern Tests (Full mutual authentication, progressive)
// ================================

TEST_CASE("PQ - pqXX pattern with M512", "[pqnoise][pattern][pqxx][m512]") {
    PQPatternTestConfig config{
        .name = "pqXX",
        .pattern = pqXX,
        .kemAlgo = "M512",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,  // Keys exchanged during handshake
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 4
    };

    test_pq_pattern_handshake(config);
}

TEST_CASE("PQ - pqXX pattern with M768", "[pqnoise][pattern][pqxx][m768]") {
    PQPatternTestConfig config{
        .name = "pqXX",
        .pattern = pqXX,
        .kemAlgo = "M768",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 4
    };

    test_pq_pattern_handshake(config);
}

TEST_CASE("PQ - pqXX pattern with M1024", "[pqnoise][pattern][pqxx][m1024]") {
    PQPatternTestConfig config{
        .name = "pqXX",
        .pattern = pqXX,
        .kemAlgo = "M1024",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 4
    };

    test_pq_pattern_handshake(config);
}

// ================================
// pqXK Pattern Tests (Responder auth, deferred initiator auth)
// ================================

TEST_CASE("PQ - pqXK pattern with M768", "[pqnoise][pattern][pqxk][m768]") {
    PQPatternTestConfig config{
        .name = "pqXK",
        .pattern = pqXK,
        .kemAlgo = "M768",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,   // Initiator knows responder's static
        .responderNeedsRemoteStatic = false,  // Responder learns initiator's static during handshake
        .expectedMessages = 4
    };

    test_pq_pattern_handshake(config);
}

// ================================
// pqIK Pattern Tests (Immediate mutual authentication)
// ================================

TEST_CASE("PQ - pqIK pattern with M768", "[pqnoise][pattern][pqik][m768]") {
    PQPatternTestConfig config{
        .name = "pqIK",
        .pattern = pqIK,
        .kemAlgo = "M768",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,   // Initiator knows responder's static
        .responderNeedsRemoteStatic = false,  // Responder learns initiator's static in first message
        .expectedMessages = 2
    };

    test_pq_pattern_handshake(config);
}

// ================================
// pqN Pattern Tests (One-way, responder auth)
// ================================

TEST_CASE("PQ - pqN pattern with M768", "[pqnoise][pattern][pqn][m768]") {
    PQPatternTestConfig config{
        .name = "pqN",
        .pattern = pqN,
        .kemAlgo = "M768",
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,   // Initiator knows responder's static
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 1
    };

    test_pq_pattern_handshake(config);
}

// ================================
// pqNX Pattern Tests (No auth initiator, responder sends static)
// ================================

TEST_CASE("PQ - pqNX pattern with M768", "[pqnoise][pattern][pqnx][m768]") {
    PQPatternTestConfig config{
        .name = "pqNX",
        .pattern = pqNX,
        .kemAlgo = "M768",
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,  // Learns responder's static during handshake
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_pq_pattern_handshake(config);
}

// ================================
// pqXN Pattern Tests (Initiator sends static deferred)
// ================================

TEST_CASE("PQ - pqXN pattern with M768", "[pqnoise][pattern][pqxn][m768]") {
    PQPatternTestConfig config{
        .name = "pqXN",
        .pattern = pqXN,
        .kemAlgo = "M768",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,  // Learns initiator's static during handshake
        .expectedMessages = 4
    };

    test_pq_pattern_handshake(config);
}

// ================================
// pqKN Pattern Tests (Responder knows initiator's static)
// ================================

TEST_CASE("PQ - pqKN pattern with M768", "[pqnoise][pattern][pqkn][m768]") {
    PQPatternTestConfig config{
        .name = "pqKN",
        .pattern = pqKN,
        .kemAlgo = "M768",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = true,   // Responder knows initiator's static
        .expectedMessages = 2
    };

    test_pq_pattern_handshake(config);
}

// ================================
// pqKX Pattern Tests (Initiator static known, responder sends)
// ================================

TEST_CASE("PQ - pqKX pattern with M768", "[pqnoise][pattern][pqkx][m768]") {
    PQPatternTestConfig config{
        .name = "pqKX",
        .pattern = pqKX,
        .kemAlgo = "M768",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,  // Learns responder's static during handshake
        .responderNeedsRemoteStatic = true,   // Responder knows initiator's static
        .expectedMessages = 3
    };

    test_pq_pattern_handshake(config);
}

// ================================
// pqIN Pattern Tests (Initiator sends static immediately)
// ================================

TEST_CASE("PQ - pqIN pattern with M768", "[pqnoise][pattern][pqin][m768]") {
    PQPatternTestConfig config{
        .name = "pqIN",
        .pattern = pqIN,
        .kemAlgo = "M768",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,  // Learns initiator's static in first message
        .expectedMessages = 2
    };

    test_pq_pattern_handshake(config);
}

// ================================
// pqIX Pattern Tests (Initiator sends static first, responder responds)
// ================================

TEST_CASE("PQ - pqIX pattern with M768", "[pqnoise][pattern][pqix][m768]") {
    PQPatternTestConfig config{
        .name = "pqIX",
        .pattern = pqIX,
        .kemAlgo = "M768",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,  // Learns responder's static during handshake
        .responderNeedsRemoteStatic = false,  // Learns initiator's static in first message
        .expectedMessages = 3
    };

    test_pq_pattern_handshake(config);
}

// ================================
// Protocol String Tests
// ================================

TEST_CASE("PQ - Protocol string parsing for PQ patterns", "[pqnoise][protocol][string]") {
    SECTION("pqNN with M768") {
        Protocol proto("Noise_pqNN_M768_ChaChaPoly_SHA256");
        REQUIRE(proto.pattern.String() == "pqNN");
        REQUIRE(proto.dh.String() == "M768");
        REQUIRE(proto.dh.IsKEM());
        REQUIRE(proto.String() == "Noise_pqNN_M768_ChaChaPoly_SHA256");
    }

    SECTION("pqXX with M512") {
        Protocol proto("Noise_pqXX_M512_ChaChaPoly_SHA256");
        REQUIRE(proto.pattern.String() == "pqXX");
        REQUIRE(proto.dh.String() == "M512");
        REQUIRE(proto.dh.IsKEM());
    }

    SECTION("pqKK with M1024") {
        Protocol proto("Noise_pqKK_M1024_AESGCM_BLAKE2b");
        REQUIRE(proto.pattern.String() == "pqKK");
        REQUIRE(proto.dh.String() == "M1024");
        REQUIRE(proto.dh.IsKEM());
    }
}

// ================================
// Pattern Validation Tests
// ================================

TEST_CASE("PQ - All 13 PQ patterns pass validation", "[pqnoise][pattern][validation]") {
    // One-way pattern
    SECTION("pqN is valid") {
        auto result = HandshakePattern::IsValid(pqN);
        if (!result.has_value()) {
            FAIL("pqN validation error: " << result.error());
        }
        REQUIRE(result.has_value());
    }

    // Interactive patterns
    SECTION("pqNN is valid") {
        auto result = HandshakePattern::IsValid(pqNN);
        if (!result.has_value()) {
            FAIL("pqNN validation error: " << result.error());
        }
        REQUIRE(result.has_value());
    }

    SECTION("pqNK is valid") {
        auto result = HandshakePattern::IsValid(pqNK);
        if (!result.has_value()) {
            FAIL("pqNK validation error: " << result.error());
        }
        REQUIRE(result.has_value());
    }

    SECTION("pqNX is valid") {
        auto result = HandshakePattern::IsValid(pqNX);
        if (!result.has_value()) {
            FAIL("pqNX validation error: " << result.error());
        }
        REQUIRE(result.has_value());
    }

    SECTION("pqXN is valid") {
        auto result = HandshakePattern::IsValid(pqXN);
        if (!result.has_value()) {
            FAIL("pqXN validation error: " << result.error());
        }
        REQUIRE(result.has_value());
    }

    SECTION("pqXK is valid") {
        auto result = HandshakePattern::IsValid(pqXK);
        if (!result.has_value()) {
            FAIL("pqXK validation error: " << result.error());
        }
        REQUIRE(result.has_value());
    }

    SECTION("pqXX is valid") {
        auto result = HandshakePattern::IsValid(pqXX);
        if (!result.has_value()) {
            FAIL("pqXX validation error: " << result.error());
        }
        REQUIRE(result.has_value());
    }

    SECTION("pqKN is valid") {
        auto result = HandshakePattern::IsValid(pqKN);
        if (!result.has_value()) {
            FAIL("pqKN validation error: " << result.error());
        }
        REQUIRE(result.has_value());
    }

    SECTION("pqKK is valid") {
        auto result = HandshakePattern::IsValid(pqKK);
        if (!result.has_value()) {
            FAIL("pqKK validation error: " << result.error());
        }
        REQUIRE(result.has_value());
    }

    SECTION("pqKX is valid") {
        auto result = HandshakePattern::IsValid(pqKX);
        if (!result.has_value()) {
            FAIL("pqKX validation error: " << result.error());
        }
        REQUIRE(result.has_value());
    }

    SECTION("pqIN is valid") {
        auto result = HandshakePattern::IsValid(pqIN);
        if (!result.has_value()) {
            FAIL("pqIN validation error: " << result.error());
        }
        REQUIRE(result.has_value());
    }

    SECTION("pqIK is valid") {
        auto result = HandshakePattern::IsValid(pqIK);
        if (!result.has_value()) {
            FAIL("pqIK validation error: " << result.error());
        }
        REQUIRE(result.has_value());
    }

    SECTION("pqIX is valid") {
        auto result = HandshakePattern::IsValid(pqIX);
        if (!result.has_value()) {
            FAIL("pqIX validation error: " << result.error());
        }
        REQUIRE(result.has_value());
    }
}

// ================================
// Early ML-KEM key validation
// ================================

namespace {
    // Counts observer calls; never rejects.
    class CountingObserver final : public HandshakeObserver {
    public:
        int calls = 0;

        std::optional<std::string> OnPeerPublicKey(Token /*token*/, const PublicKey& /*pubKey*/) override {
            ++calls;
            return std::nullopt;
        }
    };
}

TEST_CASE("pqNN - Out-of-range ML-KEM ephemeral rejected by ReadMessage", "[pqnoise][error][invalidkey][m768]") {
    Protocol protocol(pqNN, M768, ChaChaPoly, SHA256);
    CountingObserver observer;

    HandshakeConfig aliceCfg{.protocol = protocol, .isInitiator = true};
    HandshakeConfig bobCfg{.protocol = protocol, .isInitiator = false, .observer = &observer};
    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    // -> e : the ML-KEM-768 encapsulation key is in the clear at offset 0. Set coefficient 0
    // (ByteEncode12, FIPS 203 Algorithm 5) to 0xFFF = 4095 >= q = 3329, which the FIPS 203
    // Section 7.2 modulus check must reject.
    auto bad = aliceHs.WriteMessage({});
    REQUIRE(bad.size() >= protocol.dh.PublicKeySize());
    bad[0] = 0xFF;
    bad[1] |= 0x0F;

    // Rejected by the ReadMessage that carries it, before the observer sees the key
    REQUIRE_THROWS_AS(bobHs.ReadMessage(bad), InvalidPublicKeyError);
    REQUIRE(observer.calls == 0);
    REQUIRE(bobHs.GetStatus().HasError());
}

// Main function for Catch2
int main(int argc, char* argv[]) {
    // Disable all logging during tests for clean output
    Noise::DisableAllLogging();
    return Catch::Session().run(argc, argv);
}

// ================================
// pqN is one-way (Noise spec Section 7.4): only the initiator-to-responder CipherState is keyed
// ================================

TEST_CASE("PQ - pqN is one-way: the second CipherState is unkeyed", "[pqnoise][pattern][pqn][oneway]") {
    REQUIRE(pqN.isOneWay);

    const Protocol protocol{"Noise_pqN_M768_ChaChaPoly_SHA256"};
    const KeyPair bobStatic = protocol.dh.GenerateKeypair();

    const HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .remoteStatic = bobStatic.public_key
    };
    const HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic
    };
    HandshakeState alice{aliceCfg};
    HandshakeState bob{bobCfg};

    const std::vector<std::uint8_t> payload{'o', 'n', 'e', '-', 'w', 'a', 'y'};
    const auto message = alice.WriteMessage(payload);
    REQUIRE(bob.ReadMessage(message) == payload);
    REQUIRE(alice.GetStatus().IsComplete());
    REQUIRE(bob.GetStatus().IsComplete());

    REQUIRE(alice.GetStatus().cipherStates.has_value());
    REQUIRE(bob.GetStatus().cipherStates.has_value());

    // The responder-to-initiator direction is reset on both sides
    REQUIRE_FALSE(alice.GetStatus().cipherStates->second.HasKey());
    REQUIRE_FALSE(bob.GetStatus().cipherStates->second.HasKey());

    // The initiator-to-responder direction still carries one transport message
    auto [aliceCs1, aliceCs2] = *alice.GetStatus().cipherStates;
    auto [bobCs1, bobCs2] = *bob.GetStatus().cipherStates;
    REQUIRE(aliceCs1.HasKey());
    REQUIRE(bobCs1.HasKey());
    const std::vector<std::uint8_t> text{'H', 'e', 'l', 'l', 'o'};
    const auto ciphertext = aliceCs1.EncryptWithAd({}, text);
    REQUIRE(bobCs1.DecryptWithAd({}, ciphertext) == text);
}

// ================================
// A pre-message ML-KEM remote static from the config is loaded (and so validated) at
// the first skem token, not at construction, as the rule for config keys says
// ================================

namespace {
    // Sets coefficient 0 of an ML-KEM encapsulation key (ByteEncode12, FIPS 203 Algorithm 5) to
    // 0xFFF = 4095 >= q = 3329, which the FIPS 203 Section 7.2 modulus check must reject
    // (test_dh.cpp has the same helper).
    std::vector<std::uint8_t> WithCoefficient0OutOfRange(std::vector<std::uint8_t> key) {
        key[0] = 0xFF;
        key[1] |= 0x0F;
        return key;
    }
}

TEST_CASE("pqIK: an invalid configured remote static fails the skem write with InvalidPublicKeyError", "[pq][kem][validate]") {
    const Protocol protocol(pqIK, M768, ChaChaPoly, SHA256);
    const KeyPair aliceStatic = protocol.dh.GenerateKeypair();
    const KeyPair bobStatic = protocol.dh.GenerateKeypair();

    // pqIK's pre-message hands the initiator the responder's static. A config key is not checked
    // at construction; the malformed one fails the first WriteMessage at its skem token.
    const HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic,
        .remoteStatic = WithCoefficient0OutOfRange(bobStatic.public_key)
    };
    HandshakeState alice{aliceCfg};
    REQUIRE_FALSE(alice.GetStatus().HasError());

    REQUIRE_THROWS_AS(alice.WriteMessage({}), InvalidPublicKeyError);
    REQUIRE(alice.GetStatus().HasError());
    REQUIRE(alice.GetStatus().state == HandshakeStatus::State::Failed);
}

// ================================
// The observer is called for exactly the e, s and e1 keys a side receives
// ================================

namespace {
    std::string_view TokenName(const Token token) {
        switch (token) {
        case Token::Token_e:     return "e";
        case Token::Token_s:     return "s";
        case Token::Token_e1:    return "e1";
        case Token::Token_ekem:  return "ekem";
        case Token::Token_skem:  return "skem";
        case Token::Token_ekem1: return "ekem1";
        default:                 return "other";
        }
    }

    // Records every observer call in order; never rejects.
    class RecordingObserver final : public HandshakeObserver {
    public:
        std::vector<std::string_view> tokens;
        std::vector<PublicKey> keys;

        std::optional<std::string> OnPeerPublicKey(const Token token, const PublicKey& pubKey) override {
            tokens.push_back(TokenName(token));
            keys.push_back(pubKey);
            return std::nullopt;
        }
    };

    struct ObservedHandshake {
        RecordingObserver initiator;
        RecordingObserver responder;
        KeyPair initiatorStatic;
        KeyPair responderStatic;
        PublicKey initiatorEphemeral;
        PublicKey responderEphemeral;
    };

    // Runs a complete handshake with a static key and an observer on each side.
    void RunObserved(const Protocol& protocol, ObservedHandshake& run) {
        run.initiatorStatic = protocol.dh.GenerateKeypair();
        run.responderStatic = protocol.dh.GenerateKeypair();
        const HandshakeConfig initiatorCfg{
            .protocol = protocol,
            .isInitiator = true,
            .localStatic = run.initiatorStatic,
            .observer = &run.initiator
        };
        const HandshakeConfig responderCfg{
            .protocol = protocol,
            .isInitiator = false,
            .localStatic = run.responderStatic,
            .observer = &run.responder
        };
        HandshakeState initiator{initiatorCfg};
        HandshakeState responder{responderCfg};

        bool initiatorWrites = true;
        for (int message = 0; message < 8 && !(initiator.GetStatus().IsComplete() && responder.GetStatus().IsComplete()); ++message) {
            HandshakeState& writer = initiatorWrites ? initiator : responder;
            HandshakeState& reader = initiatorWrites ? responder : initiator;
            (void)reader.ReadMessage(writer.WriteMessage({}));
            initiatorWrites = !initiatorWrites;
        }
        REQUIRE(initiator.GetStatus().IsComplete());
        REQUIRE(responder.GetStatus().IsComplete());

        run.initiatorEphemeral = initiator.GetStatus().localEphemeral;
        run.responderEphemeral = responder.GetStatus().localEphemeral;
    }
}

TEST_CASE("PQ - the observer is called only for the e, s and e1 keys each side receives", "[pqnoise][hfs][observer]") {
    SECTION("pqXX (ML-KEM-768): -> e / <- ekem, s / -> skem, s / <- skem") {
        const Protocol protocol(pqXX, M768, ChaChaPoly, SHA256);
        ObservedHandshake run;
        RunObserved(protocol, run);

        // The initiator receives s (message 2); the responder receives e (message 1) and s (message 3).
        CHECK(run.initiator.tokens == std::vector<std::string_view>{"s"});
        CHECK(run.initiator.keys == std::vector<PublicKey>{run.responderStatic.public_key});
        CHECK(run.responder.tokens == std::vector<std::string_view>{"e", "s"});
        CHECK(run.responder.keys == std::vector<PublicKey>{run.initiatorEphemeral, run.initiatorStatic.public_key});
    }

    SECTION("XXhfs (X25519 + ML-KEM-768): -> e, e1 / <- e, ee, ekem1, s, es / -> s, se") {
        const Protocol protocol{"Noise_XXhfs_25519+M768_ChaChaPoly_SHA256"};
        ObservedHandshake run;
        RunObserved(protocol, run);

        // The initiator receives e and s (message 2); the responder receives e and e1 (message 1)
        // and s (message 3).
        CHECK(run.initiator.tokens == std::vector<std::string_view>{"e", "s"});
        CHECK(run.initiator.keys == std::vector<PublicKey>{run.responderEphemeral, run.responderStatic.public_key});
        CHECK(run.responder.tokens == std::vector<std::string_view>{"e", "e1", "s"});
        REQUIRE(run.responder.keys.size() == 3);
        CHECK(run.responder.keys[0] == run.initiatorEphemeral);
        CHECK(run.responder.keys[1].size() == protocol.kem->PublicKeySize());
        CHECK(run.responder.keys[2] == run.initiatorStatic.public_key);
    }
}
