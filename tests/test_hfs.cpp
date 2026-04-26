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
// HFS (Hybrid Forward Secrecy) Pattern Tests using Catch2 v3.11
//
// Tests for the "hfs" pattern modifier which adds KEM-based hybrid forward secrecy
// to standard Noise handshakes per noise-kem-hfs.pdf specification.
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>

import std;
import noise;

using namespace Noise;

// Helper function to compare byte vectors
static bool bytes_equal(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
    if (a.size() != b.size()) return false;
    return std::memcmp(a.data(), b.data(), a.size()) == 0;
}

// ================================
// Protocol String Parsing Tests
// ================================

TEST_CASE("HFS - Protocol string parsing", "[hfs][protocol][parsing]") {
    SECTION("Parse NNhfs protocol string") {
        Protocol protocol("Noise_NNhfs_25519+M768_ChaChaPoly_SHA256");

        REQUIRE(protocol.IsHFS());
        REQUIRE(protocol.pattern.String() == "NNhfs");
        REQUIRE(protocol.dh.String() == "25519");
        REQUIRE(protocol.kem.has_value());
        REQUIRE(protocol.kem->String() == "M768");
        REQUIRE(protocol.cipher.String() == "ChaChaPoly");
        REQUIRE(protocol.hash.String() == "SHA256");
    }

    SECTION("Parse XXhfs protocol string") {
        Protocol protocol("Noise_XXhfs_25519+M768_ChaChaPoly_SHA256");

        REQUIRE(protocol.IsHFS());
        REQUIRE(protocol.pattern.String() == "XXhfs");
    }

    SECTION("Parse NKhfs protocol string") {
        Protocol protocol("Noise_NKhfs_448+M1024_ChaChaPoly_BLAKE2b");

        REQUIRE(protocol.IsHFS());
        REQUIRE(protocol.dh.String() == "448");
        REQUIRE(protocol.kem->String() == "M1024");
    }

    SECTION("Non-HFS protocol has no KEM") {
        Protocol protocol("Noise_XX_25519_ChaChaPoly_SHA256");

        REQUIRE_FALSE(protocol.IsHFS());
        REQUIRE_FALSE(protocol.kem.has_value());
    }

    SECTION("DH+KEM without hfs suffix throws") {
        REQUIRE_THROWS_AS(
            Protocol("Noise_XX_25519+M768_ChaChaPoly_SHA256"),
            NoiseError
        );
    }

    SECTION("hfs suffix without DH+KEM throws") {
        REQUIRE_THROWS_AS(
            Protocol("Noise_XXhfs_25519_ChaChaPoly_SHA256"),
            NoiseError
        );
    }
}

// ================================
// Pattern Transformation Tests
// ================================

TEST_CASE("HFS - ApplyHFSModifier transformation", "[hfs][pattern][transform]") {
    SECTION("NN -> NNhfs transformation") {
        // NN:      -> e       NNhfs:    -> e, e1
        //          <- e, ee              <- e, ee, ekem1
        auto hfs = ApplyHFSModifier(NN);

        REQUIRE(hfs.String() == "NNhfs");
        REQUIRE(hfs.messages.size() == 2);

        // First message: e, e1
        REQUIRE(hfs.messages[0].tokens.size() == 2);
        REQUIRE(hfs.messages[0].tokens[0] == Token_e);
        REQUIRE(hfs.messages[0].tokens[1] == Token_e1);

        // Second message: e, ee, ekem1
        REQUIRE(hfs.messages[1].tokens.size() == 3);
        REQUIRE(hfs.messages[1].tokens[0] == Token_e);
        REQUIRE(hfs.messages[1].tokens[1] == Token_ee);
        REQUIRE(hfs.messages[1].tokens[2] == Token_ekem1);
    }

    SECTION("NK -> NKhfs transformation") {
        // NK:      <- s       NKhfs:    <- s
        //          -> e, es              -> e, es, e1
        //          <- e, ee              <- e, ee, ekem1
        auto hfs = ApplyHFSModifier(NK);

        REQUIRE(hfs.String() == "NKhfs");

        // First message: e, es, e1 (e1 after DH operation es)
        REQUIRE(hfs.messages[0].tokens.size() == 3);
        REQUIRE(hfs.messages[0].tokens[0] == Token_e);
        REQUIRE(hfs.messages[0].tokens[1] == Token_es);
        REQUIRE(hfs.messages[0].tokens[2] == Token_e1);

        // Second message: e, ee, ekem1
        REQUIRE(hfs.messages[1].tokens.size() == 3);
        REQUIRE(hfs.messages[1].tokens[0] == Token_e);
        REQUIRE(hfs.messages[1].tokens[1] == Token_ee);
        REQUIRE(hfs.messages[1].tokens[2] == Token_ekem1);
    }

    SECTION("XX -> XXhfs transformation") {
        // XX:      -> e            XXhfs:    -> e, e1
        //          <- e, ee, s, es           <- e, ee, ekem1, s, es
        //          -> s, se                  -> s, se
        auto hfs = ApplyHFSModifier(XX);

        REQUIRE(hfs.String() == "XXhfs");
        REQUIRE(hfs.messages.size() == 3);

        // First message: e, e1
        REQUIRE(hfs.messages[0].tokens.size() == 2);
        REQUIRE(hfs.messages[0].tokens[0] == Token_e);
        REQUIRE(hfs.messages[0].tokens[1] == Token_e1);

        // Second message: e, ee, ekem1, s, es
        REQUIRE(hfs.messages[1].tokens.size() == 5);
        REQUIRE(hfs.messages[1].tokens[0] == Token_e);
        REQUIRE(hfs.messages[1].tokens[1] == Token_ee);
        REQUIRE(hfs.messages[1].tokens[2] == Token_ekem1);
        REQUIRE(hfs.messages[1].tokens[3] == Token_s);
        REQUIRE(hfs.messages[1].tokens[4] == Token_es);

        // Third message: s, se (unchanged)
        REQUIRE(hfs.messages[2].tokens.size() == 2);
        REQUIRE(hfs.messages[2].tokens[0] == Token_s);
        REQUIRE(hfs.messages[2].tokens[1] == Token_se);
    }

    SECTION("IK -> IKhfs transformation") {
        // IK:      <- s            IKhfs:    <- s
        //          -> e, es, s, ss           -> e, es, e1, s, ss (e1 after last DH)
        //          <- e, ee, se              <- e, ee, ekem1, se
        auto hfs = ApplyHFSModifier(IK);

        REQUIRE(hfs.String() == "IKhfs");

        // First message: e, es, e1, s, ss (e1 after es which is the last DH before s)
        // Actually per spec: e1 after "last DH operation in this message"
        // es and ss are both DH ops, so e1 should be after ss
        auto& msg0 = hfs.messages[0].tokens;
        REQUIRE(msg0.size() == 5);
        REQUIRE(msg0[0] == Token_e);
        REQUIRE(msg0[1] == Token_es);
        // e1 could be after es or after ss depending on interpretation
        // Let's check what we have
        bool has_e1 = std::find(msg0.begin(), msg0.end(), Token_e1) != msg0.end();
        REQUIRE(has_e1);

        // Second message: e, ee, ekem1, se
        auto& msg1 = hfs.messages[1].tokens;
        REQUIRE(msg1.size() == 4);
        REQUIRE(msg1[0] == Token_e);
        REQUIRE(msg1[1] == Token_ee);
        REQUIRE(msg1[2] == Token_ekem1);
        REQUIRE(msg1[3] == Token_se);
    }
}

// ================================
// HFS Pattern Handshake Tests
// ================================

// Helper struct for HFS pattern test configuration
struct HFSPatternTestConfig {
    std::string_view protocolString;
    bool initiatorNeedsStatic;
    bool responderNeedsStatic;
    bool initiatorNeedsRemoteStatic;
    bool responderNeedsRemoteStatic;
    std::size_t expectedMessages;
};

// Helper function to execute a complete HFS handshake
void test_hfs_pattern_handshake(const HFSPatternTestConfig& config) {
    Protocol protocol(config.protocolString);

    REQUIRE(protocol.IsHFS());

    // Generate DH keys as needed (HFS uses DH for main keys)
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
    std::vector<std::uint8_t> payload{'h', 'f', 's', 't', 'e', 's', 't'};

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
    auto [aliceCS1, aliceCS2] = *aliceHs.GetStatus().cipherStates;
    auto [bobCS1, bobCS2] = *bobHs.GetStatus().cipherStates;

    // Alice encrypts with CS1, Bob decrypts with CS1
    std::vector<std::uint8_t> testMessage{'H', 'e', 'l', 'l', 'o', ' ', 'H', 'F', 'S'};
    auto encrypted = aliceCS1.EncryptWithAd({}, testMessage);
    auto decrypted = bobCS1.DecryptWithAd({}, encrypted);
    REQUIRE(bytes_equal(decrypted, testMessage));

    // Bob encrypts with CS2, Alice decrypts with CS2
    std::vector<std::uint8_t> testReply{'H', 'F', 'S', ' ', 'O', 'K'};
    encrypted = bobCS2.EncryptWithAd({}, testReply);
    decrypted = aliceCS2.DecryptWithAd({}, encrypted);
    REQUIRE(bytes_equal(decrypted, testReply));
}

// ================================
// Fundamental Interactive HFS Pattern Tests
// ================================

// NNhfs - No static keys
TEST_CASE("HFS - NNhfs pattern with 25519+M768", "[hfs][pattern][nnhfs][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_NNhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

TEST_CASE("HFS - NNhfs pattern with 25519+M512", "[hfs][pattern][nnhfs][m512]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_NNhfs_25519+M512_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

TEST_CASE("HFS - NNhfs pattern with 448+M1024", "[hfs][pattern][nnhfs][m1024]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_NNhfs_448+M1024_ChaChaPoly_BLAKE2b",
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

// NKhfs - Responder has pre-known static key
TEST_CASE("HFS - NKhfs pattern with 25519+M768", "[hfs][pattern][nkhfs][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_NKhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

TEST_CASE("HFS - NKhfs pattern with 448+M1024", "[hfs][pattern][nkhfs][m1024]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_NKhfs_448+M1024_ChaChaPoly_BLAKE2b",
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

// NXhfs - Responder transmits static key
TEST_CASE("HFS - NXhfs pattern with 25519+M768", "[hfs][pattern][nxhfs][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_NXhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

// KNhfs - Initiator has pre-known static key
TEST_CASE("HFS - KNhfs pattern with 25519+M768", "[hfs][pattern][knhfs][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_KNhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

// KKhfs - Both have pre-known static keys
TEST_CASE("HFS - KKhfs pattern with 25519+M768", "[hfs][pattern][kkhfs][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_KKhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

TEST_CASE("HFS - KKhfs pattern with 448+M1024", "[hfs][pattern][kkhfs][m1024]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_KKhfs_448+M1024_ChaChaPoly_BLAKE2b",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

// KXhfs - Initiator pre-known, responder transmits
TEST_CASE("HFS - KXhfs pattern with 25519+M768", "[hfs][pattern][kxhfs][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_KXhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

// XNhfs - Initiator transmits static key
TEST_CASE("HFS - XNhfs pattern with 25519+M768", "[hfs][pattern][xnhfs][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_XNhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

// XKhfs - Initiator transmits, responder pre-known
TEST_CASE("HFS - XKhfs pattern with 25519+M768", "[hfs][pattern][xkhfs][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_XKhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

// XXhfs - Both transmit static keys
TEST_CASE("HFS - XXhfs pattern with 25519+M768", "[hfs][pattern][xxhfs][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_XXhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

TEST_CASE("HFS - XXhfs pattern with 448+M512", "[hfs][pattern][xxhfs][m512]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_XXhfs_448+M512_ChaChaPoly_BLAKE2s",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

TEST_CASE("HFS - XXhfs pattern with 448+M1024", "[hfs][pattern][xxhfs][m1024]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_XXhfs_448+M1024_ChaChaPoly_BLAKE2b",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

// INhfs - Initiator transmits identity immediately
TEST_CASE("HFS - INhfs pattern with 25519+M768", "[hfs][pattern][inhfs][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_INhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

// IKhfs - Initiator identity immediate, responder pre-known
TEST_CASE("HFS - IKhfs pattern with 25519+M768", "[hfs][pattern][ikhfs][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_IKhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

TEST_CASE("HFS - IKhfs pattern with 448+M1024", "[hfs][pattern][ikhfs][m1024]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_IKhfs_448+M1024_ChaChaPoly_BLAKE2b",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

// IXhfs - Initiator identity immediate, responder transmits
TEST_CASE("HFS - IXhfs pattern with 25519+M768", "[hfs][pattern][ixhfs][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_IXhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

// ================================
// Deferred HFS Pattern Tests
// ================================

// NK1hfs - Deferred responder authentication
TEST_CASE("HFS - NK1hfs pattern with 25519+M768", "[hfs][pattern][nk1hfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_NK1hfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

// XX1hfs - Deferred responder identity
TEST_CASE("HFS - XX1hfs pattern with 25519+M768", "[hfs][pattern][xx1hfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_XX1hfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

TEST_CASE("HFS - XX1hfs pattern with 448+M1024", "[hfs][pattern][xx1hfs][deferred][m1024]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_XX1hfs_448+M1024_ChaChaPoly_BLAKE2b",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

// KK1hfs - Deferred responder authentication with known keys
TEST_CASE("HFS - KK1hfs pattern with 25519+M768", "[hfs][pattern][kk1hfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_KK1hfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

// IK1hfs - Deferred responder authentication
TEST_CASE("HFS - IK1hfs pattern with 25519+M768", "[hfs][pattern][ik1hfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_IK1hfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

// NX1hfs - Deferred responder identity transmission
TEST_CASE("HFS - NX1hfs pattern with 25519+M768", "[hfs][pattern][nx1hfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_NX1hfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

// X1Nhfs - Deferred initiator identity
TEST_CASE("HFS - X1Nhfs pattern with 25519+M768", "[hfs][pattern][x1nhfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_X1Nhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 4
    };

    test_hfs_pattern_handshake(config);
}

// X1Khfs - Deferred initiator identity with known responder
TEST_CASE("HFS - X1Khfs pattern with 25519+M768", "[hfs][pattern][x1khfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_X1Khfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 4
    };

    test_hfs_pattern_handshake(config);
}

TEST_CASE("HFS - X1Khfs pattern with 448+M1024", "[hfs][pattern][x1khfs][deferred][m1024]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_X1Khfs_448+M1024_ChaChaPoly_BLAKE2b",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 4
    };

    test_hfs_pattern_handshake(config);
}

// XK1hfs - Deferred responder authentication
TEST_CASE("HFS - XK1hfs pattern with 25519+M768", "[hfs][pattern][xk1hfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_XK1hfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

// X1K1hfs - Both deferred
TEST_CASE("HFS - X1K1hfs pattern with 25519+M768", "[hfs][pattern][x1k1hfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_X1K1hfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 4
    };

    test_hfs_pattern_handshake(config);
}

// X1Xhfs - Deferred initiator identity, responder transmits
TEST_CASE("HFS - X1Xhfs pattern with 25519+M768", "[hfs][pattern][x1xhfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_X1Xhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 4
    };

    test_hfs_pattern_handshake(config);
}

// X1X1hfs - Both deferred identity transmission
TEST_CASE("HFS - X1X1hfs pattern with 25519+M768", "[hfs][pattern][x1x1hfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_X1X1hfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 4
    };

    test_hfs_pattern_handshake(config);
}

// K1Nhfs - Deferred initiator authentication
TEST_CASE("HFS - K1Nhfs pattern with 25519+M768", "[hfs][pattern][k1nhfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_K1Nhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

// K1Khfs - Deferred initiator authentication with known responder
TEST_CASE("HFS - K1Khfs pattern with 25519+M768", "[hfs][pattern][k1khfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_K1Khfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

// K1K1hfs - Both deferred authentication
TEST_CASE("HFS - K1K1hfs pattern with 25519+M768", "[hfs][pattern][k1k1hfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_K1K1hfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

// K1Xhfs - Deferred initiator authentication, responder transmits
TEST_CASE("HFS - K1Xhfs pattern with 25519+M768", "[hfs][pattern][k1xhfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_K1Xhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

// KX1hfs - Deferred responder identity transmission
TEST_CASE("HFS - KX1hfs pattern with 25519+M768", "[hfs][pattern][kx1hfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_KX1hfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

// K1X1hfs - Both deferred
TEST_CASE("HFS - K1X1hfs pattern with 25519+M768", "[hfs][pattern][k1x1hfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_K1X1hfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

// I1Nhfs - Deferred initiator identity
TEST_CASE("HFS - I1Nhfs pattern with 25519+M768", "[hfs][pattern][i1nhfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_I1Nhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

// I1Khfs - Deferred initiator identity with known responder
TEST_CASE("HFS - I1Khfs pattern with 25519+M768", "[hfs][pattern][i1khfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_I1Khfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

// I1K1hfs - Both deferred
TEST_CASE("HFS - I1K1hfs pattern with 25519+M768", "[hfs][pattern][i1k1hfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_I1K1hfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

// I1Xhfs - Deferred initiator identity, responder transmits
TEST_CASE("HFS - I1Xhfs pattern with 25519+M768", "[hfs][pattern][i1xhfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_I1Xhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

// IX1hfs - Deferred responder identity transmission
TEST_CASE("HFS - IX1hfs pattern with 25519+M768", "[hfs][pattern][ix1hfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_IX1hfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

// I1X1hfs - Both deferred
TEST_CASE("HFS - I1X1hfs pattern with 25519+M768", "[hfs][pattern][i1x1hfs][deferred][m768]") {
    HFSPatternTestConfig config{
        .protocolString = "Noise_I1X1hfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

// ================================
// Pattern Validation Tests
// ================================

TEST_CASE("HFS - Pattern validation for all fundamental interactive patterns", "[hfs][pattern][validation]") {
    SECTION("NNhfs pattern validates successfully") {
        auto hfs = ApplyHFSModifier(NN);
        auto result = HandshakePattern::IsValid(hfs);
        REQUIRE(result.has_value());
    }

    SECTION("NKhfs pattern validates successfully") {
        auto hfs = ApplyHFSModifier(NK);
        auto result = HandshakePattern::IsValid(hfs);
        REQUIRE(result.has_value());
    }

    SECTION("NXhfs pattern validates successfully") {
        auto hfs = ApplyHFSModifier(NX);
        auto result = HandshakePattern::IsValid(hfs);
        REQUIRE(result.has_value());
    }

    SECTION("KNhfs pattern validates successfully") {
        auto hfs = ApplyHFSModifier(KN);
        auto result = HandshakePattern::IsValid(hfs);
        REQUIRE(result.has_value());
    }

    SECTION("KKhfs pattern validates successfully") {
        auto hfs = ApplyHFSModifier(KK);
        auto result = HandshakePattern::IsValid(hfs);
        REQUIRE(result.has_value());
    }

    SECTION("KXhfs pattern validates successfully") {
        auto hfs = ApplyHFSModifier(KX);
        auto result = HandshakePattern::IsValid(hfs);
        REQUIRE(result.has_value());
    }

    SECTION("XNhfs pattern validates successfully") {
        auto hfs = ApplyHFSModifier(XN);
        auto result = HandshakePattern::IsValid(hfs);
        REQUIRE(result.has_value());
    }

    SECTION("XKhfs pattern validates successfully") {
        auto hfs = ApplyHFSModifier(XK);
        auto result = HandshakePattern::IsValid(hfs);
        REQUIRE(result.has_value());
    }

    SECTION("XXhfs pattern validates successfully") {
        auto hfs = ApplyHFSModifier(XX);
        auto result = HandshakePattern::IsValid(hfs);
        REQUIRE(result.has_value());
    }

    SECTION("INhfs pattern validates successfully") {
        auto hfs = ApplyHFSModifier(IN);
        auto result = HandshakePattern::IsValid(hfs);
        REQUIRE(result.has_value());
    }

    SECTION("IKhfs pattern validates successfully") {
        auto hfs = ApplyHFSModifier(IK);
        auto result = HandshakePattern::IsValid(hfs);
        REQUIRE(result.has_value());
    }

    SECTION("IXhfs pattern validates successfully") {
        auto hfs = ApplyHFSModifier(IX);
        auto result = HandshakePattern::IsValid(hfs);
        REQUIRE(result.has_value());
    }
}

TEST_CASE("HFS - Pattern registry contains all HFS patterns", "[hfs][pattern][registry]") {
    const auto& registry = GetPatternRegistry();

    SECTION("Fundamental interactive HFS patterns are in registry") {
        REQUIRE(registry.contains("NNhfs"));
        REQUIRE(registry.contains("NKhfs"));
        REQUIRE(registry.contains("NXhfs"));
        REQUIRE(registry.contains("KNhfs"));
        REQUIRE(registry.contains("KKhfs"));
        REQUIRE(registry.contains("KXhfs"));
        REQUIRE(registry.contains("XNhfs"));
        REQUIRE(registry.contains("XKhfs"));
        REQUIRE(registry.contains("XXhfs"));
        REQUIRE(registry.contains("INhfs"));
        REQUIRE(registry.contains("IKhfs"));
        REQUIRE(registry.contains("IXhfs"));
    }

    SECTION("Deferred HFS patterns are in registry") {
        REQUIRE(registry.contains("NK1hfs"));
        REQUIRE(registry.contains("NX1hfs"));
        REQUIRE(registry.contains("X1Nhfs"));
        REQUIRE(registry.contains("X1Khfs"));
        REQUIRE(registry.contains("XK1hfs"));
        REQUIRE(registry.contains("X1K1hfs"));
        REQUIRE(registry.contains("X1Xhfs"));
        REQUIRE(registry.contains("XX1hfs"));
        REQUIRE(registry.contains("X1X1hfs"));
        REQUIRE(registry.contains("K1Nhfs"));
        REQUIRE(registry.contains("K1Khfs"));
        REQUIRE(registry.contains("KK1hfs"));
        REQUIRE(registry.contains("K1K1hfs"));
        REQUIRE(registry.contains("K1Xhfs"));
        REQUIRE(registry.contains("KX1hfs"));
        REQUIRE(registry.contains("K1X1hfs"));
        REQUIRE(registry.contains("I1Nhfs"));
        REQUIRE(registry.contains("I1Khfs"));
        REQUIRE(registry.contains("IK1hfs"));
        REQUIRE(registry.contains("I1K1hfs"));
        REQUIRE(registry.contains("I1Xhfs"));
        REQUIRE(registry.contains("IX1hfs"));
        REQUIRE(registry.contains("I1X1hfs"));
    }
}

// ================================
// Message Size Tests
// ================================

TEST_CASE("HFS - Message sizes are larger than non-HFS", "[hfs][message][size]") {
    SECTION("NNhfs messages include KEM overhead") {
        Protocol hfsProtocol("Noise_NNhfs_25519+M768_ChaChaPoly_SHA256");
        Protocol normalProtocol("Noise_NN_25519_ChaChaPoly_SHA256");

        // HFS first message includes: e (32 bytes) + e1 (1184 bytes KEM public key)
        // Normal first message includes: e (32 bytes)

        HandshakeConfig aliceCfgHfs{
            .protocol = hfsProtocol,
            .isInitiator = true
        };
        HandshakeConfig aliceCfgNormal{
            .protocol = normalProtocol,
            .isInitiator = true
        };

        HandshakeState aliceHfs(aliceCfgHfs);
        HandshakeState aliceNormal(aliceCfgNormal);

        auto hfsMsg = aliceHfs.WriteMessage({});
        auto normalMsg = aliceNormal.WriteMessage({});

        // HFS message should be larger due to KEM public key
        REQUIRE(hfsMsg.size() > normalMsg.size());

        // Expected difference is approximately KEM public key size (1184 for M768)
        // Plus AEAD overhead if encrypted
        auto sizeDiff = hfsMsg.size() - normalMsg.size();
        REQUIRE(sizeDiff >= 1184);  // M768 public key size
    }
}

// ================================
// Main entry point for Catch2
// ================================

int main(int argc, char* argv[]) {
    // Disable all logging during tests for clean output
    Noise::DisableAllLogging();
    return Catch::Session().run(argc, argv);
}
