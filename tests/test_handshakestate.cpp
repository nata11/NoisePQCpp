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
// HandshakeState Module Tests using Catch2 v3
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>

import noise;

using namespace Noise;

// Helper function to compare byte vectors
bool bytes_equal(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
    if (a.size() != b.size()) return false;
    return std::memcmp(a.data(), b.data(), a.size()) == 0;
}

// Simple observer for testing
class TestObserver : public HandshakeObserver {
public:
    int callCount = 0;
    Token lastToken = Token::Token_e;
    PublicKey lastKey{};
    bool shouldReject = false;

    std::optional<std::string> OnPeerPublicKey(Token token, const PublicKey& pubKey) override {
        callCount++;
        lastToken = token;
        lastKey = pubKey;

        if (shouldReject) {
            return "rejected by observer";
        }
        return std::nullopt;
    }
};

// ================================
// Construction Tests
// ================================

TEST_CASE("HandshakeState - XX pattern construction as initiator", "[handshakestate][constructor][xx]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);
    auto static_key = protocol.dh.GenerateKeypair();

    HandshakeConfig cfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = static_key
    };

    REQUIRE_NOTHROW([&]() {
        HandshakeState hs(cfg);
        const auto& status = hs.GetStatus();
        REQUIRE_FALSE(status.IsComplete());
        REQUIRE_FALSE(status.HasError());
    }());
}

TEST_CASE("HandshakeState - XX pattern construction as responder", "[handshakestate][constructor][xx]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);
    auto static_key = protocol.dh.GenerateKeypair();

    HandshakeConfig cfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = static_key
    };

    REQUIRE_NOTHROW([&]() {
        HandshakeState hs(cfg);
        const auto& status = hs.GetStatus();
        REQUIRE_FALSE(status.IsComplete());
        REQUIRE_FALSE(status.HasError());
    }());
}

TEST_CASE("HandshakeState - NN pattern construction", "[handshakestate][constructor][nn]") {
    Protocol protocol(NN, X25519, ChaChaPoly, SHA256);

    HandshakeConfig cfg{
        .protocol = protocol,
        .isInitiator = true
    };

    REQUIRE_NOTHROW([&]() {
        HandshakeState hs(cfg);
        REQUIRE_FALSE(hs.GetStatus().IsComplete());
    }());
}

TEST_CASE("HandshakeState - KK pattern with pre-shared static keys", "[handshakestate][constructor][kk]") {
    Protocol protocol(KK, X25519, ChaChaPoly, SHA256);

    auto aliceStatic = protocol.dh.GenerateKeypair();
    auto bobStatic = protocol.dh.GenerateKeypair();

    SECTION("Initiator knows responder's static key") {
        HandshakeConfig cfg{
            .protocol = protocol,
            .isInitiator = true,
            .localStatic = aliceStatic,
            .remoteStatic = bobStatic.public_key
        };

        REQUIRE_NOTHROW([&]() {
            HandshakeState hs(cfg);
            REQUIRE_FALSE(hs.GetStatus().IsComplete());
        }());
    }

    SECTION("Responder knows initiator's static key") {
        HandshakeConfig cfg{
            .protocol = protocol,
            .isInitiator = false,
            .localStatic = bobStatic,
            .remoteStatic = aliceStatic.public_key
        };

        REQUIRE_NOTHROW([&]() {
            HandshakeState hs(cfg);
            REQUIRE_FALSE(hs.GetStatus().IsComplete());
        }());
    }
}

TEST_CASE("HandshakeState - NK pattern with responder static key", "[handshakestate][constructor][nk]") {
    Protocol protocol(NK, X25519, ChaChaPoly, SHA256);
    auto bobStatic = protocol.dh.GenerateKeypair();

    SECTION("Initiator knows responder's static key") {
        HandshakeConfig cfg{
            .protocol = protocol,
            .isInitiator = true,
            .remoteStatic = bobStatic.public_key
        };

        REQUIRE_NOTHROW([&]() {
            HandshakeState hs(cfg);
            REQUIRE_FALSE(hs.GetStatus().IsComplete());
        }());
    }

    SECTION("Responder has static key") {
        HandshakeConfig cfg{
            .protocol = protocol,
            .isInitiator = false,
            .localStatic = bobStatic
        };

        REQUIRE_NOTHROW([&]() {
            HandshakeState hs(cfg);
            REQUIRE_FALSE(hs.GetStatus().IsComplete());
        }());
    }
}

TEST_CASE("HandshakeState - Construction with prologue", "[handshakestate][constructor][prologue]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);
    auto static_key = protocol.dh.GenerateKeypair();

    std::vector<std::uint8_t> prologue{'p', 'r', 'o', 'l', 'o', 'g', 'u', 'e'};

    HandshakeConfig cfg{
        .protocol = protocol,
        .isInitiator = true,
        .prologue = prologue,
        .localStatic = static_key
    };

    REQUIRE_NOTHROW([&]() {
        HandshakeState hs(cfg);
        REQUIRE_FALSE(hs.GetStatus().IsComplete());
    }());
}

TEST_CASE("HandshakeState - Construction with pre-generated ephemeral key", "[handshakestate][constructor][ephemeral]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);
    auto static_key = protocol.dh.GenerateKeypair();
    auto ephemeral_key = protocol.dh.GenerateKeypair();

    HandshakeConfig cfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = static_key,
        .localEphemeral = ephemeral_key
    };

    REQUIRE_NOTHROW([&]() {
        HandshakeState hs(cfg);
        const auto& status = hs.GetStatus();
        REQUIRE(bytes_equal(status.localEphemeral, ephemeral_key.public_key));
    }());
}

TEST_CASE("HandshakeState - Construction with custom max message size", "[handshakestate][constructor][messagesize]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);
    auto static_key = protocol.dh.GenerateKeypair();

    SECTION("Default max message size") {
        HandshakeConfig cfg{
            .protocol = protocol,
            .isInitiator = true,
            .localStatic = static_key,
            .maxMessageSize = 0  // Uses DefaultMaxMessageSize
        };

        REQUIRE_NOTHROW([&]() {
            HandshakeState hs(cfg);
        }());
    }

    SECTION("Custom max message size") {
        HandshakeConfig cfg{
            .protocol = protocol,
            .isInitiator = true,
            .localStatic = static_key,
            .maxMessageSize = 1024
        };

        REQUIRE_NOTHROW([&]() {
            HandshakeState hs(cfg);
        }());
    }

    SECTION("Unlimited message size") {
        HandshakeConfig cfg{
            .protocol = protocol,
            .isInitiator = true,
            .localStatic = static_key,
            .maxMessageSize = -1  // Disables check
        };

        REQUIRE_NOTHROW([&]() {
            HandshakeState hs(cfg);
        }());
    }
}

// ================================
// XX Handshake Tests
// ================================

TEST_CASE("HandshakeState - Complete XX handshake", "[handshakestate][xx][handshake]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);

    auto aliceStatic = protocol.dh.GenerateKeypair();
    auto bobStatic = protocol.dh.GenerateKeypair();

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    // Message 1: Alice -> Bob (e)
    std::vector<std::uint8_t> payload1{'h', 'e', 'l', 'l', 'o'};
    auto msg1 = aliceHs.WriteMessage(payload1);
    REQUIRE_FALSE(msg1.empty());
    REQUIRE_FALSE(aliceHs.GetStatus().IsComplete());

    auto recv1 = bobHs.ReadMessage(msg1);
    REQUIRE(bytes_equal(recv1, payload1));
    REQUIRE_FALSE(bobHs.GetStatus().IsComplete());

    // Message 2: Bob -> Alice (e, ee, s, es)
    std::vector<std::uint8_t> payload2{};
    auto msg2 = bobHs.WriteMessage(payload2);
    REQUIRE_FALSE(msg2.empty());
    REQUIRE_FALSE(bobHs.GetStatus().IsComplete());

    auto recv2 = aliceHs.ReadMessage(msg2);
    REQUIRE(recv2.empty());
    REQUIRE_FALSE(aliceHs.GetStatus().IsComplete());

    // Message 3: Alice -> Bob (s, se)
    std::vector<std::uint8_t> payload3{};
    auto msg3 = aliceHs.WriteMessage(payload3);
    REQUIRE_FALSE(msg3.empty());
    REQUIRE(aliceHs.GetStatus().IsComplete());

    auto recv3 = bobHs.ReadMessage(msg3);
    REQUIRE(recv3.empty());
    REQUIRE(bobHs.GetStatus().IsComplete());

    // Verify both sides learned each other's static keys
    REQUIRE(bytes_equal(aliceHs.GetStatus().remoteStatic, bobStatic.public_key));
    REQUIRE(bytes_equal(bobHs.GetStatus().remoteStatic, aliceStatic.public_key));

    // Verify handshake hashes match
    REQUIRE(bytes_equal(aliceHs.GetStatus().handshakeHash, bobHs.GetStatus().handshakeHash));

    // Verify cipher states are available
    REQUIRE(aliceHs.GetStatus().cipherStates.has_value());
    REQUIRE(bobHs.GetStatus().cipherStates.has_value());
}

TEST_CASE("HandshakeState - XX handshake with payload in all messages", "[handshakestate][xx][payload]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);

    auto aliceStatic = protocol.dh.GenerateKeypair();
    auto bobStatic = protocol.dh.GenerateKeypair();

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    // Message 1 with payload
    std::vector<std::uint8_t> payload1{'m', 's', 'g', '1'};
    auto msg1 = aliceHs.WriteMessage(payload1);
    auto recv1 = bobHs.ReadMessage(msg1);
    REQUIRE(bytes_equal(recv1, payload1));

    // Message 2 with payload
    std::vector<std::uint8_t> payload2{'m', 's', 'g', '2'};
    auto msg2 = bobHs.WriteMessage(payload2);
    auto recv2 = aliceHs.ReadMessage(msg2);
    REQUIRE(bytes_equal(recv2, payload2));

    // Message 3 with payload
    std::vector<std::uint8_t> payload3{'m', 's', 'g', '3'};
    auto msg3 = aliceHs.WriteMessage(payload3);
    auto recv3 = bobHs.ReadMessage(msg3);
    REQUIRE(bytes_equal(recv3, payload3));

    REQUIRE(aliceHs.GetStatus().IsComplete());
    REQUIRE(bobHs.GetStatus().IsComplete());
}

// ================================
// NN Handshake Tests
// ================================

TEST_CASE("HandshakeState - Complete NN handshake", "[handshakestate][nn][handshake]") {
    Protocol protocol(NN, X25519, ChaChaPoly, SHA256);

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    // Message 1: Alice -> Bob (e)
    auto msg1 = aliceHs.WriteMessage({});
    REQUIRE_FALSE(aliceHs.GetStatus().IsComplete());

    bobHs.ReadMessage(msg1);
    REQUIRE_FALSE(bobHs.GetStatus().IsComplete());

    // Message 2: Bob -> Alice (e, ee)
    auto msg2 = bobHs.WriteMessage({});
    REQUIRE(bobHs.GetStatus().IsComplete());

    aliceHs.ReadMessage(msg2);
    REQUIRE(aliceHs.GetStatus().IsComplete());

    // Verify no static keys were exchanged
    REQUIRE(aliceHs.GetStatus().remoteStatic.empty());
    REQUIRE(bobHs.GetStatus().remoteStatic.empty());

    // Verify ephemeral keys were exchanged
    REQUIRE_FALSE(aliceHs.GetStatus().remoteEphemeral.empty());
    REQUIRE_FALSE(bobHs.GetStatus().remoteEphemeral.empty());

    // Verify handshake hashes match
    REQUIRE(bytes_equal(aliceHs.GetStatus().handshakeHash, bobHs.GetStatus().handshakeHash));
}

// ================================
// KK Handshake Tests
// ================================

TEST_CASE("HandshakeState - Complete KK handshake with known static keys", "[handshakestate][kk][handshake]") {
    Protocol protocol(KK, X25519, ChaChaPoly, SHA256);

    auto aliceStatic = protocol.dh.GenerateKeypair();
    auto bobStatic = protocol.dh.GenerateKeypair();

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic,
        .remoteStatic = bobStatic.public_key
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic,
        .remoteStatic = aliceStatic.public_key
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    // Message 1: Alice -> Bob (e, es, ss)
    auto msg1 = aliceHs.WriteMessage({});
    REQUIRE_FALSE(aliceHs.GetStatus().IsComplete());

    bobHs.ReadMessage(msg1);
    REQUIRE_FALSE(bobHs.GetStatus().IsComplete());

    // Message 2: Bob -> Alice (e, ee, se)
    auto msg2 = bobHs.WriteMessage({});
    REQUIRE(bobHs.GetStatus().IsComplete());

    aliceHs.ReadMessage(msg2);
    REQUIRE(aliceHs.GetStatus().IsComplete());

    // Verify both sides have the correct remote static keys
    REQUIRE(bytes_equal(aliceHs.GetStatus().remoteStatic, bobStatic.public_key));
    REQUIRE(bytes_equal(bobHs.GetStatus().remoteStatic, aliceStatic.public_key));
}

// ================================
// NK Handshake Tests
// ================================

TEST_CASE("HandshakeState - Complete NK handshake", "[handshakestate][nk][handshake]") {
    Protocol protocol(NK, X25519, ChaChaPoly, SHA256);

    auto bobStatic = protocol.dh.GenerateKeypair();

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .remoteStatic = bobStatic.public_key
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    // Message 1: Alice -> Bob (e, es)
    auto msg1 = aliceHs.WriteMessage({});
    REQUIRE_FALSE(aliceHs.GetStatus().IsComplete());

    bobHs.ReadMessage(msg1);
    REQUIRE_FALSE(bobHs.GetStatus().IsComplete());

    // Message 2: Bob -> Alice (e, ee)
    auto msg2 = bobHs.WriteMessage({});
    REQUIRE(bobHs.GetStatus().IsComplete());

    aliceHs.ReadMessage(msg2);
    REQUIRE(aliceHs.GetStatus().IsComplete());

    // Verify Alice knows Bob's static key
    REQUIRE(bytes_equal(aliceHs.GetStatus().remoteStatic, bobStatic.public_key));

    // Verify Bob doesn't know Alice's static key (she didn't send one)
    REQUIRE(bobHs.GetStatus().remoteStatic.empty());
}

// ================================
// Error Handling Tests
// ================================

TEST_CASE("HandshakeState - Out of order write throws error", "[handshakestate][error][outoforder]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);

    auto aliceStatic = protocol.dh.GenerateKeypair();
    auto bobStatic = protocol.dh.GenerateKeypair();

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    // Bob tries to write before Alice (out of order)
    REQUIRE_THROWS_AS(bobHs.WriteMessage({}), OutOfOrderError);
    REQUIRE(bobHs.GetStatus().HasError());
}

TEST_CASE("HandshakeState - Out of order read throws error", "[handshakestate][error][outoforder]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);

    auto aliceStatic = protocol.dh.GenerateKeypair();

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic
    };

    HandshakeState aliceHs(aliceCfg);

    // Alice tries to read before writing (out of order)
    std::vector<std::uint8_t> dummy_msg(32, 0);
    REQUIRE_THROWS_AS(aliceHs.ReadMessage(dummy_msg), OutOfOrderError);
    REQUIRE(aliceHs.GetStatus().HasError());
}

TEST_CASE("HandshakeState - Reading after error throws same error", "[handshakestate][error][persistence]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);

    auto bobStatic = protocol.dh.GenerateKeypair();

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic
    };

    HandshakeState bobHs(bobCfg);

    // Cause an error
    REQUIRE_THROWS_AS(bobHs.WriteMessage({}), OutOfOrderError);
    REQUIRE(bobHs.GetStatus().HasError());

    // Try to write again - should throw the same error
    REQUIRE_THROWS_AS(bobHs.WriteMessage({}), OutOfOrderError);
}

TEST_CASE("HandshakeState - Truncated message throws error", "[handshakestate][error][truncated]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);

    auto aliceStatic = protocol.dh.GenerateKeypair();
    auto bobStatic = protocol.dh.GenerateKeypair();

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    // Alice sends first message
    auto msg1 = aliceHs.WriteMessage({});

    // Truncate the message
    std::vector<std::uint8_t> truncated(msg1.begin(), msg1.begin() + 10);

    // Bob tries to read truncated message
    REQUIRE_THROWS_AS(bobHs.ReadMessage(truncated), TruncatedMessageError);
    REQUIRE(bobHs.GetStatus().HasError());
}

TEST_CASE("HandshakeState - Message exceeding max size throws error", "[handshakestate][error][messagesize]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);

    auto aliceStatic = protocol.dh.GenerateKeypair();

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic,
        .maxMessageSize = 100  // Very small limit
    };

    HandshakeState aliceHs(aliceCfg);

    // Try to send a large payload
    std::vector<std::uint8_t> large_payload(200, 0x42);

    REQUIRE_THROWS_AS(aliceHs.WriteMessage(large_payload), MessageSizeError);
    REQUIRE(aliceHs.GetStatus().HasError());
}

TEST_CASE("HandshakeState - Reading message exceeding max size throws error", "[handshakestate][error][messagesize][read]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);

    auto bobStatic = protocol.dh.GenerateKeypair();

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic,
        .maxMessageSize = 100  // Very small limit
    };

    HandshakeState bobHs(bobCfg);

    // Create a large fake message
    std::vector<std::uint8_t> large_message(200, 0x42);

    REQUIRE_THROWS_AS(bobHs.ReadMessage(large_message), MessageSizeError);
    REQUIRE(bobHs.GetStatus().HasError());
}

// ================================
// HandshakeStatus Tests
// ================================

TEST_CASE("HandshakeState - Tampered message throws DecryptionError and stays failed", "[handshakestate][error][decryption]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);

    auto aliceStatic = protocol.dh.GenerateKeypair();
    auto bobStatic = protocol.dh.GenerateKeypair();

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic
    };
    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    // -> e            (plaintext)
    auto msg1 = aliceHs.WriteMessage({});
    bobHs.ReadMessage(msg1);

    // <- e, ee, s, es (first encrypted message)
    auto msg2 = bobHs.WriteMessage({});
    aliceHs.ReadMessage(msg2);

    // -> s, se        (the initiator's second message; bob reads it)
    auto msg3 = aliceHs.WriteMessage({});
    auto tampered = msg3;
    tampered.back() ^= 0x01;

    REQUIRE_THROWS_AS(bobHs.ReadMessage(tampered), DecryptionError);
    REQUIRE(bobHs.GetStatus().HasError());
    REQUIRE_FALSE(bobHs.GetStatus().IsComplete());

    // The error is sticky: the genuine message is refused with the same type
    REQUIRE_THROWS_AS(bobHs.ReadMessage(msg3), DecryptionError);
    REQUIRE(bobHs.GetStatus().HasError());
}

TEST_CASE("HandshakeState - Low-order DH key throws InvalidPublicKeyError", "[handshakestate][error][invalidkey]") {
    // NN: -> e / <- e, ee. The initiator reads a message 2 whose e is the all-zero point, a
    // low-order point (RFC 7748 Section 6.1/6.2: the shared secret is all zeros and the key
    // agreement rejects it), followed by 16 junk bytes where the payload tag would be.
    auto run = [](const std::string_view dhAlgo) {
        Protocol protocol(NN, dhAlgo, ChaChaPoly, SHA256);

        HandshakeConfig aliceCfg{.protocol = protocol, .isInitiator = true};
        HandshakeConfig bobCfg{.protocol = protocol, .isInitiator = false};
        HandshakeState aliceHs(aliceCfg);
        HandshakeState bobHs(bobCfg);

        // -> e
        auto msg1 = aliceHs.WriteMessage({});
        bobHs.ReadMessage(msg1);

        // <- e, ee   with e = zeros, then 16 junk bytes
        std::vector<std::uint8_t> badMsg2(protocol.dh.PublicKeySize(), 0x00);
        badMsg2.insert(badMsg2.end(), 16, 0xA5);

        REQUIRE_THROWS_AS(aliceHs.ReadMessage(badMsg2), InvalidPublicKeyError);
        REQUIRE(aliceHs.GetStatus().HasError());
        REQUIRE_FALSE(aliceHs.GetStatus().IsComplete());

        // The error is sticky: the genuine message 2 is refused with the same type
        auto msg2 = bobHs.WriteMessage({});
        REQUIRE_THROWS_AS(aliceHs.ReadMessage(msg2), InvalidPublicKeyError);
        REQUIRE(aliceHs.GetStatus().HasError());
    };

    SECTION("X25519 (32-byte key)") { run(X25519); }
    SECTION("X448 (56-byte key)") { run(X448); }
}

TEST_CASE("HandshakeStatus - IsComplete returns false during handshake", "[handshakestate][status]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);

    auto aliceStatic = protocol.dh.GenerateKeypair();

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic
    };

    HandshakeState aliceHs(aliceCfg);

    REQUIRE_FALSE(aliceHs.GetStatus().IsComplete());
    REQUIRE_FALSE(aliceHs.GetStatus().HasError());

    // After first message
    aliceHs.WriteMessage({});
    REQUIRE_FALSE(aliceHs.GetStatus().IsComplete());
    REQUIRE_FALSE(aliceHs.GetStatus().HasError());
}

TEST_CASE("HandshakeStatus - IsComplete returns true after handshake", "[handshakestate][status]") {
    Protocol protocol(NN, X25519, ChaChaPoly, SHA256);

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    auto msg1 = aliceHs.WriteMessage({});
    bobHs.ReadMessage(msg1);

    auto msg2 = bobHs.WriteMessage({});
    REQUIRE(bobHs.GetStatus().IsComplete());

    aliceHs.ReadMessage(msg2);
    REQUIRE(aliceHs.GetStatus().IsComplete());
}

TEST_CASE("HandshakeStatus - HasError returns true on error", "[handshakestate][status][error]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);

    auto bobStatic = protocol.dh.GenerateKeypair();

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic
    };

    HandshakeState bobHs(bobCfg);

    REQUIRE_FALSE(bobHs.GetStatus().HasError());

    // Cause an error
    REQUIRE_THROWS(bobHs.WriteMessage({}));

    REQUIRE(bobHs.GetStatus().HasError());
    REQUIRE_FALSE(bobHs.GetStatus().IsComplete());
}

TEST_CASE("HandshakeStatus - CipherStates available after completion", "[handshakestate][status][cipherstates]") {
    Protocol protocol(NN, X25519, ChaChaPoly, SHA256);

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    REQUIRE_FALSE(aliceHs.GetStatus().cipherStates.has_value());

    auto msg1 = aliceHs.WriteMessage({});
    bobHs.ReadMessage(msg1);

    auto msg2 = bobHs.WriteMessage({});
    aliceHs.ReadMessage(msg2);

    REQUIRE(aliceHs.GetStatus().cipherStates.has_value());
    REQUIRE(bobHs.GetStatus().cipherStates.has_value());
}

TEST_CASE("HandshakeStatus - Handshake hash available after completion", "[handshakestate][status][hash]") {
    Protocol protocol(NN, X25519, ChaChaPoly, SHA256);

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    REQUIRE(aliceHs.GetStatus().handshakeHash.empty());

    auto msg1 = aliceHs.WriteMessage({});
    bobHs.ReadMessage(msg1);

    auto msg2 = bobHs.WriteMessage({});
    aliceHs.ReadMessage(msg2);

    REQUIRE_FALSE(aliceHs.GetStatus().handshakeHash.empty());
    REQUIRE_FALSE(bobHs.GetStatus().handshakeHash.empty());
    REQUIRE(bytes_equal(aliceHs.GetStatus().handshakeHash, bobHs.GetStatus().handshakeHash));
}

// ================================
// Observer Tests
// ================================

TEST_CASE("HandshakeState - Observer called on ephemeral key reception", "[handshakestate][observer]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);

    auto aliceStatic = protocol.dh.GenerateKeypair();
    auto bobStatic = protocol.dh.GenerateKeypair();

    TestObserver bobObserver;

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic,
        .observer = &bobObserver
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    auto msg1 = aliceHs.WriteMessage({});

    REQUIRE(bobObserver.callCount == 0);

    bobHs.ReadMessage(msg1);

    REQUIRE(bobObserver.callCount == 1);
    REQUIRE(bobObserver.lastToken == Token::Token_e);
    REQUIRE_FALSE(bobObserver.lastKey.empty());
}

TEST_CASE("HandshakeState - Observer called on static key reception", "[handshakestate][observer]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);

    auto aliceStatic = protocol.dh.GenerateKeypair();
    auto bobStatic = protocol.dh.GenerateKeypair();

    TestObserver aliceObserver;

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic,
        .observer = &aliceObserver
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    auto msg1 = aliceHs.WriteMessage({});
    bobHs.ReadMessage(msg1);

    auto msg2 = bobHs.WriteMessage({});

    int callsBefore = aliceObserver.callCount;
    aliceHs.ReadMessage(msg2);

    // Should be called twice: once for 'e', once for 's'
    REQUIRE(aliceObserver.callCount == callsBefore + 2);
}

TEST_CASE("HandshakeState - Observer rejection aborts handshake", "[handshakestate][observer][reject]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);

    auto aliceStatic = protocol.dh.GenerateKeypair();
    auto bobStatic = protocol.dh.GenerateKeypair();

    TestObserver bobObserver;
    bobObserver.shouldReject = true;

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic,
        .observer = &bobObserver
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    auto msg1 = aliceHs.WriteMessage({});

    // Bob's observer should reject Alice's ephemeral key
    REQUIRE_THROWS_AS(bobHs.ReadMessage(msg1), NoiseError);
    REQUIRE(bobHs.GetStatus().HasError());
}

// ================================
// Prologue Tests
// ================================

TEST_CASE("HandshakeState - Matching prologues succeed", "[handshakestate][prologue]") {
    Protocol protocol(NN, X25519, ChaChaPoly, SHA256);

    std::vector<std::uint8_t> prologue{'t', 'e', 's', 't', ' ', 'p', 'r', 'o', 'l', 'o', 'g', 'u', 'e'};

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .prologue = prologue
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .prologue = prologue
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    auto msg1 = aliceHs.WriteMessage({});
    bobHs.ReadMessage(msg1);

    auto msg2 = bobHs.WriteMessage({});
    aliceHs.ReadMessage(msg2);

    REQUIRE(aliceHs.GetStatus().IsComplete());
    REQUIRE(bobHs.GetStatus().IsComplete());
}

TEST_CASE("HandshakeState - Mismatched prologues cause decryption failure", "[handshakestate][prologue][mismatch]") {
    Protocol protocol(NN, X25519, ChaChaPoly, SHA256);

    std::vector<std::uint8_t> prologue1{'p', 'r', 'o', 'l', 'o', 'g', 'u', 'e', '1'};
    std::vector<std::uint8_t> prologue2{'p', 'r', 'o', 'l', 'o', 'g', 'u', 'e', '2'};

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .prologue = prologue1
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .prologue = prologue2
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    // First message (unencrypted) succeeds
    auto msg1 = aliceHs.WriteMessage({});
    bobHs.ReadMessage(msg1);

    // Second message fails due to authentication error from prologue mismatch
    auto msg2 = bobHs.WriteMessage({});
    REQUIRE_THROWS(aliceHs.ReadMessage(msg2));
    REQUIRE(aliceHs.GetStatus().HasError());
}

// ================================
// Algorithm Combination Tests
// ================================

TEST_CASE("HandshakeState - XX with X448 DH algorithm", "[handshakestate][xx][x448]") {
    Protocol protocol(XX, X448, ChaChaPoly, SHA256);

    auto aliceStatic = protocol.dh.GenerateKeypair();
    auto bobStatic = protocol.dh.GenerateKeypair();

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    // Complete handshake
    auto msg1 = aliceHs.WriteMessage({});
    bobHs.ReadMessage(msg1);

    auto msg2 = bobHs.WriteMessage({});
    aliceHs.ReadMessage(msg2);

    auto msg3 = aliceHs.WriteMessage({});
    bobHs.ReadMessage(msg3);

    REQUIRE(aliceHs.GetStatus().IsComplete());
    REQUIRE(bobHs.GetStatus().IsComplete());

    // Verify X448 keys (56 bytes)
    REQUIRE(aliceStatic.public_key.size() == 56);
    REQUIRE(bobStatic.public_key.size() == 56);
}

TEST_CASE("HandshakeState - XX with AESGCM cipher", "[handshakestate][xx][aesgcm]") {
    Protocol protocol(XX, X25519, AESGCM, SHA256);

    auto aliceStatic = protocol.dh.GenerateKeypair();
    auto bobStatic = protocol.dh.GenerateKeypair();

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    // Complete handshake
    auto msg1 = aliceHs.WriteMessage({});
    bobHs.ReadMessage(msg1);

    auto msg2 = bobHs.WriteMessage({});
    aliceHs.ReadMessage(msg2);

    auto msg3 = aliceHs.WriteMessage({});
    bobHs.ReadMessage(msg3);

    REQUIRE(aliceHs.GetStatus().IsComplete());
    REQUIRE(bobHs.GetStatus().IsComplete());
}

TEST_CASE("HandshakeState - XX with BLAKE2b hash", "[handshakestate][xx][blake2b]") {
    Protocol protocol(XX, X25519, ChaChaPoly, BLAKE2b);

    auto aliceStatic = protocol.dh.GenerateKeypair();
    auto bobStatic = protocol.dh.GenerateKeypair();

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    // Complete handshake
    auto msg1 = aliceHs.WriteMessage({});
    bobHs.ReadMessage(msg1);

    auto msg2 = bobHs.WriteMessage({});
    aliceHs.ReadMessage(msg2);

    auto msg3 = aliceHs.WriteMessage({});
    bobHs.ReadMessage(msg3);

    REQUIRE(aliceHs.GetStatus().IsComplete());
    REQUIRE(bobHs.GetStatus().IsComplete());

    // BLAKE2b produces 64-byte hash
    REQUIRE(aliceHs.GetStatus().handshakeHash.size() == 64);
}

// ================================
// GetSymmetricState Tests
// ================================

TEST_CASE("HandshakeState - GetSymmetricState returns valid state", "[handshakestate][symmetricstate]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);

    auto aliceStatic = protocol.dh.GenerateKeypair();

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic
    };

    HandshakeState aliceHs(aliceCfg);

    const auto& ss = aliceHs.GetSymmetricState();

    REQUIRE_FALSE(ss.h.empty());
    REQUIRE_FALSE(ss.ck.empty());
    REQUIRE(ss.hashLen > 0);
}

// ================================
// Post-Handshake Communication Tests
// ================================

TEST_CASE("HandshakeState - CipherStates usable for post-handshake encryption", "[handshakestate][post-handshake]") {
    Protocol protocol(NN, X25519, ChaChaPoly, SHA256);

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true
    };

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    // Complete handshake
    auto msg1 = aliceHs.WriteMessage({});
    bobHs.ReadMessage(msg1);

    auto msg2 = bobHs.WriteMessage({});
    aliceHs.ReadMessage(msg2);

    // Get cipher states
    auto [aliceTx_temp, aliceRx_temp] = *aliceHs.GetStatus().cipherStates;
    auto [bobRx_temp, bobTx_temp] = *bobHs.GetStatus().cipherStates;

    // Make copies
    CipherState aliceTx = aliceTx_temp;
    CipherState aliceRx = aliceRx_temp;
    CipherState bobRx = bobRx_temp;
    CipherState bobTx = bobTx_temp;

    // Test Alice -> Bob
    std::vector<std::uint8_t> plaintext1{'h', 'e', 'l', 'l', 'o'};
    auto ciphertext1 = aliceTx.EncryptWithAd({}, plaintext1);
    auto decrypted1 = bobRx.DecryptWithAd({}, ciphertext1);
    REQUIRE(bytes_equal(plaintext1, decrypted1));

    // Test Bob -> Alice
    std::vector<std::uint8_t> plaintext2{'w', 'o', 'r', 'l', 'd'};
    auto ciphertext2 = bobTx.EncryptWithAd({}, plaintext2);
    auto decrypted2 = aliceRx.DecryptWithAd({}, ciphertext2);
    REQUIRE(bytes_equal(plaintext2, decrypted2));
}

// ================================
// Comprehensive Pattern Tests
// ================================

// Helper function to execute a complete handshake for any pattern
struct PatternTestConfig {
    std::string_view name;
    const HandshakePattern& pattern;
    bool initiatorNeedsStatic;
    bool responderNeedsStatic;
    bool initiatorNeedsRemoteStatic;
    bool responderNeedsRemoteStatic;
    std::size_t expectedMessages;
};

void test_pattern_handshake(const PatternTestConfig& config) {
    Protocol protocol(config.pattern, X25519, ChaChaPoly, SHA256);

    // Generate keys as needed
    KeyPair aliceStatic = config.initiatorNeedsStatic
        ? protocol.dh.GenerateKeypair()
        : KeyPair{};

    KeyPair bobStatic = config.responderNeedsStatic
        ? protocol.dh.GenerateKeypair()
        : KeyPair{};

    // Build Alice's config
    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic,
        .remoteStatic = (config.initiatorNeedsRemoteStatic && !bobStatic.public_key.empty())
            ? bobStatic.public_key
            : PublicKey{}
    };

    // Build Bob's config
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
    std::vector<std::uint8_t> payload{'t', 'e', 's', 't'};

    for (std::size_t i = 0; i < config.expectedMessages; ++i) {
        if (i % 2 == 0) {
            // Alice sends
            auto msg = aliceHs.WriteMessage(i == 0 ? payload : std::vector<std::uint8_t>{});
            REQUIRE_FALSE(msg.empty());

            auto recv = bobHs.ReadMessage(msg);
            if (i == 0) {
                REQUIRE(bytes_equal(recv, payload));
            }
        } else {
            // Bob sends
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
}

TEST_CASE("HandshakeState - One-Way Pattern N", "[handshakestate][pattern][n][oneway]") {
    PatternTestConfig config{
        .name = "N",
        .pattern = N,
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 1
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - One-Way Pattern K", "[handshakestate][pattern][k][oneway]") {
    PatternTestConfig config{
        .name = "K",
        .pattern = K,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 1
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - One-Way Pattern X", "[handshakestate][pattern][x][oneway]") {
    PatternTestConfig config{
        .name = "X",
        .pattern = X,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 1
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Interactive Pattern NX", "[handshakestate][pattern][nx][interactive]") {
    PatternTestConfig config{
        .name = "NX",
        .pattern = NX,
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Interactive Pattern KN", "[handshakestate][pattern][kn][interactive]") {
    PatternTestConfig config{
        .name = "KN",
        .pattern = KN,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 2
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Interactive Pattern KX", "[handshakestate][pattern][kx][interactive]") {
    PatternTestConfig config{
        .name = "KX",
        .pattern = KX,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 2
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Interactive Pattern XN", "[handshakestate][pattern][xn][interactive]") {
    PatternTestConfig config{
        .name = "XN",
        .pattern = XN,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Interactive Pattern XK", "[handshakestate][pattern][xk][interactive]") {
    PatternTestConfig config{
        .name = "XK",
        .pattern = XK,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Interactive Pattern IN", "[handshakestate][pattern][in][interactive]") {
    PatternTestConfig config{
        .name = "IN",
        .pattern = IN,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Interactive Pattern IK", "[handshakestate][pattern][ik][interactive]") {
    PatternTestConfig config{
        .name = "IK",
        .pattern = IK,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Interactive Pattern IX", "[handshakestate][pattern][ix][interactive]") {
    PatternTestConfig config{
        .name = "IX",
        .pattern = IX,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_pattern_handshake(config);
}

// ================================
// Deferred Pattern Tests
// ================================

TEST_CASE("HandshakeState - Deferred Pattern NK1", "[handshakestate][pattern][nk1][deferred]") {
    PatternTestConfig config{
        .name = "NK1",
        .pattern = NK1,
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern NX1", "[handshakestate][pattern][nx1][deferred]") {
    PatternTestConfig config{
        .name = "NX1",
        .pattern = NX1,
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern X1N", "[handshakestate][pattern][x1n][deferred]") {
    PatternTestConfig config{
        .name = "X1N",
        .pattern = X1N,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 4
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern X1K", "[handshakestate][pattern][x1k][deferred]") {
    PatternTestConfig config{
        .name = "X1K",
        .pattern = X1K,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 4
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern XK1", "[handshakestate][pattern][xk1][deferred]") {
    PatternTestConfig config{
        .name = "XK1",
        .pattern = XK1,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern X1K1", "[handshakestate][pattern][x1k1][deferred]") {
    PatternTestConfig config{
        .name = "X1K1",
        .pattern = X1K1,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 4
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern X1X", "[handshakestate][pattern][x1x][deferred]") {
    PatternTestConfig config{
        .name = "X1X",
        .pattern = X1X,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 4
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern XX1", "[handshakestate][pattern][xx1][deferred]") {
    PatternTestConfig config{
        .name = "XX1",
        .pattern = XX1,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern X1X1", "[handshakestate][pattern][x1x1][deferred]") {
    PatternTestConfig config{
        .name = "X1X1",
        .pattern = X1X1,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 4
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern K1N", "[handshakestate][pattern][k1n][deferred]") {
    PatternTestConfig config{
        .name = "K1N",
        .pattern = K1N,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 3
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern K1K", "[handshakestate][pattern][k1k][deferred]") {
    PatternTestConfig config{
        .name = "K1K",
        .pattern = K1K,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 3
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern KK1", "[handshakestate][pattern][kk1][deferred]") {
    PatternTestConfig config{
        .name = "KK1",
        .pattern = KK1,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 2
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern K1K1", "[handshakestate][pattern][k1k1][deferred]") {
    PatternTestConfig config{
        .name = "K1K1",
        .pattern = K1K1,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 3
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern K1X", "[handshakestate][pattern][k1x][deferred]") {
    PatternTestConfig config{
        .name = "K1X",
        .pattern = K1X,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 3
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern KX1", "[handshakestate][pattern][kx1][deferred]") {
    PatternTestConfig config{
        .name = "KX1",
        .pattern = KX1,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 3
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern K1X1", "[handshakestate][pattern][k1x1][deferred]") {
    PatternTestConfig config{
        .name = "K1X1",
        .pattern = K1X1,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 3
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern I1N", "[handshakestate][pattern][i1n][deferred]") {
    PatternTestConfig config{
        .name = "I1N",
        .pattern = I1N,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern I1K", "[handshakestate][pattern][i1k][deferred]") {
    PatternTestConfig config{
        .name = "I1K",
        .pattern = I1K,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern IK1", "[handshakestate][pattern][ik1][deferred]") {
    PatternTestConfig config{
        .name = "IK1",
        .pattern = IK1,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern I1K1", "[handshakestate][pattern][i1k1][deferred]") {
    PatternTestConfig config{
        .name = "I1K1",
        .pattern = I1K1,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern I1X", "[handshakestate][pattern][i1x][deferred]") {
    PatternTestConfig config{
        .name = "I1X",
        .pattern = I1X,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern IX1", "[handshakestate][pattern][ix1][deferred]") {
    PatternTestConfig config{
        .name = "IX1",
        .pattern = IX1,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_pattern_handshake(config);
}

TEST_CASE("HandshakeState - Deferred Pattern I1X1", "[handshakestate][pattern][i1x1][deferred]") {
    PatternTestConfig config{
        .name = "I1X1",
        .pattern = I1X1,
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_pattern_handshake(config);
}

// ================================
// PSK Pattern Tests
// ================================

// Helper function for PSK pattern tests
void test_psk_pattern_handshake(const PatternTestConfig& config, const std::vector<std::uint8_t>& psk) {
    Protocol protocol(config.pattern, X25519, ChaChaPoly, SHA256);

    // Generate keys as needed
    KeyPair aliceStatic = config.initiatorNeedsStatic
        ? protocol.dh.GenerateKeypair()
        : KeyPair{};

    KeyPair bobStatic = config.responderNeedsStatic
        ? protocol.dh.GenerateKeypair()
        : KeyPair{};

    // Convert PSK to array format
    std::array<std::uint8_t, SYMMETRIC_KEY_SIZE> pskArray{};
    std::copy(psk.begin(), psk.begin() + SYMMETRIC_KEY_SIZE, pskArray.begin());
    std::vector<std::array<std::uint8_t, SYMMETRIC_KEY_SIZE>> preSharedKeys = {pskArray};

    // Build Alice's config with PSK
    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic,
        .remoteStatic = (config.initiatorNeedsRemoteStatic && !bobStatic.public_key.empty())
            ? bobStatic.public_key
            : PublicKey{},
        .preSharedKeys = preSharedKeys
    };

    // Build Bob's config with PSK
    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic,
        .remoteStatic = (config.responderNeedsRemoteStatic && !aliceStatic.public_key.empty())
            ? aliceStatic.public_key
            : PublicKey{},
        .preSharedKeys = preSharedKeys
    };

    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    // Execute handshake
    std::vector<std::uint8_t> payload{'t', 'e', 's', 't'};

    for (std::size_t i = 0; i < config.expectedMessages; ++i) {
        if (i % 2 == 0) {
            // Alice sends
            auto msg = aliceHs.WriteMessage(i == 0 ? payload : std::vector<std::uint8_t>{});
            REQUIRE_FALSE(msg.empty());

            auto recv = bobHs.ReadMessage(msg);
            if (i == 0) {
                REQUIRE(bytes_equal(recv, payload));
            }
        } else {
            // Bob sends
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
}

// Helper function to get a pattern from the registry by name
const HandshakePattern& get_pattern_from_registry(std::string_view name) {
    const auto& registry = GetPatternRegistry();
    std::string pattern_name{name};
    auto it = registry.find(pattern_name);
    if (it == registry.end()) {
        throw std::runtime_error(std::string("Pattern not found in registry: ") + std::string(name));
    }
    return it->second;
}

TEST_CASE("HandshakeState - PSK Pattern Npsk0", "[handshakestate][pattern][npsk0][psk][oneway]") {
    std::vector<std::uint8_t> psk(32, 0x42);  // 32-byte PSK

    PatternTestConfig config{
        .name = "Npsk0",
        .pattern = get_pattern_from_registry("Npsk0"),
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 1
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern Kpsk0", "[handshakestate][pattern][kpsk0][psk][oneway]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "Kpsk0",
        .pattern = get_pattern_from_registry("Kpsk0"),
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 1
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern Xpsk1", "[handshakestate][pattern][xpsk1][psk][oneway]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "Xpsk1",
        .pattern = get_pattern_from_registry("Xpsk1"),
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 1
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern NNpsk0", "[handshakestate][pattern][nnpsk0][psk]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "NNpsk0",
        .pattern = get_pattern_from_registry("NNpsk0"),
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern NNpsk2", "[handshakestate][pattern][nnpsk2][psk]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "NNpsk2",
        .pattern = get_pattern_from_registry("NNpsk2"),
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern NKpsk0", "[handshakestate][pattern][nkpsk0][psk]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "NKpsk0",
        .pattern = get_pattern_from_registry("NKpsk0"),
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern NKpsk2", "[handshakestate][pattern][nkpsk2][psk]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "NKpsk2",
        .pattern = get_pattern_from_registry("NKpsk2"),
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern NXpsk2", "[handshakestate][pattern][nxpsk2][psk]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "NXpsk2",
        .pattern = get_pattern_from_registry("NXpsk2"),
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern XNpsk3", "[handshakestate][pattern][xnpsk3][psk]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "XNpsk3",
        .pattern = get_pattern_from_registry("XNpsk3"),
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern XKpsk3", "[handshakestate][pattern][xkpsk3][psk]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "XKpsk3",
        .pattern = get_pattern_from_registry("XKpsk3"),
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern XXpsk3", "[handshakestate][pattern][xxpsk3][psk]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "XXpsk3",
        .pattern = get_pattern_from_registry("XXpsk3"),
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern KNpsk0", "[handshakestate][pattern][knpsk0][psk]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "KNpsk0",
        .pattern = get_pattern_from_registry("KNpsk0"),
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 2
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern KNpsk2", "[handshakestate][pattern][knpsk2][psk]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "KNpsk2",
        .pattern = get_pattern_from_registry("KNpsk2"),
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 2
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern KKpsk0", "[handshakestate][pattern][kkpsk0][psk]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "KKpsk0",
        .pattern = get_pattern_from_registry("KKpsk0"),
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 2
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern KKpsk2", "[handshakestate][pattern][kkpsk2][psk]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "KKpsk2",
        .pattern = get_pattern_from_registry("KKpsk2"),
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 2
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern KXpsk2", "[handshakestate][pattern][kxpsk2][psk]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "KXpsk2",
        .pattern = get_pattern_from_registry("KXpsk2"),
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 2
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern INpsk1", "[handshakestate][pattern][inpsk1][psk]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "INpsk1",
        .pattern = get_pattern_from_registry("INpsk1"),
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern INpsk2", "[handshakestate][pattern][inpsk2][psk]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "INpsk2",
        .pattern = get_pattern_from_registry("INpsk2"),
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern IKpsk1", "[handshakestate][pattern][ikpsk1][psk]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "IKpsk1",
        .pattern = get_pattern_from_registry("IKpsk1"),
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern IKpsk2", "[handshakestate][pattern][ikpsk2][psk]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "IKpsk2",
        .pattern = get_pattern_from_registry("IKpsk2"),
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_psk_pattern_handshake(config, psk);
}

TEST_CASE("HandshakeState - PSK Pattern IXpsk2", "[handshakestate][pattern][ixpsk2][psk]") {
    std::vector<std::uint8_t> psk(32, 0x42);

    PatternTestConfig config{
        .name = "IXpsk2",
        .pattern = get_pattern_from_registry("IXpsk2"),
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_psk_pattern_handshake(config, psk);
}

// ================================
// HFS (Hybrid Forward Secrecy) Pattern Tests
// ================================

// Helper struct for HFS pattern test configuration
struct HFSPatternTestConfig {
    std::string_view name;
    std::string_view protocolString;
    bool initiatorNeedsStatic;
    bool responderNeedsStatic;
    bool initiatorNeedsRemoteStatic;
    bool responderNeedsRemoteStatic;
    std::size_t expectedMessages;
};

void test_hfs_pattern_handshake(const HFSPatternTestConfig& config) {
    Protocol protocol(config.protocolString);

    REQUIRE(protocol.IsHFS());

    // Generate DH keys as needed
    KeyPair aliceStatic = config.initiatorNeedsStatic
        ? protocol.dh.GenerateKeypair()
        : KeyPair{};

    KeyPair bobStatic = config.responderNeedsStatic
        ? protocol.dh.GenerateKeypair()
        : KeyPair{};

    // Build Alice's config
    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic,
        .remoteStatic = (config.initiatorNeedsRemoteStatic && !bobStatic.public_key.empty())
            ? bobStatic.public_key
            : PublicKey{}
    };

    // Build Bob's config
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
            auto msg = aliceHs.WriteMessage(i == 0 ? payload : std::vector<std::uint8_t>{});
            REQUIRE_FALSE(msg.empty());

            auto recv = bobHs.ReadMessage(msg);
            if (i == 0) {
                REQUIRE(bytes_equal(recv, payload));
            }
        } else {
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

    std::vector<std::uint8_t> testMessage{'H', 'F', 'S', ' ', 'O', 'K'};
    auto encrypted = aliceCS1.EncryptWithAd({}, testMessage);
    auto decrypted = bobCS1.DecryptWithAd({}, encrypted);
    REQUIRE(bytes_equal(decrypted, testMessage));
}

TEST_CASE("HandshakeState - HFS NNhfs with 25519+M768", "[handshakestate][hfs][nnhfs][m768]") {
    HFSPatternTestConfig config{
        .name = "NNhfs",
        .protocolString = "Noise_NNhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = false,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

TEST_CASE("HandshakeState - HFS XXhfs with 25519+M768", "[handshakestate][hfs][xxhfs][m768]") {
    HFSPatternTestConfig config{
        .name = "XXhfs",
        .protocolString = "Noise_XXhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

TEST_CASE("HandshakeState - HFS XXhfs with 448+M1024", "[handshakestate][hfs][xxhfs][m1024]") {
    HFSPatternTestConfig config{
        .name = "XXhfs",
        .protocolString = "Noise_XXhfs_448+M1024_ChaChaPoly_BLAKE2b",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = false,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 3
    };

    test_hfs_pattern_handshake(config);
}

TEST_CASE("HandshakeState - HFS IKhfs with 25519+M768", "[handshakestate][hfs][ikhfs][m768]") {
    HFSPatternTestConfig config{
        .name = "IKhfs",
        .protocolString = "Noise_IKhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

TEST_CASE("HandshakeState - HFS IKhfs with 448+M1024", "[handshakestate][hfs][ikhfs][m1024]") {
    HFSPatternTestConfig config{
        .name = "IKhfs",
        .protocolString = "Noise_IKhfs_448+M1024_AESGCM_SHA512",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

TEST_CASE("HandshakeState - HFS KKhfs with 25519+M768", "[handshakestate][hfs][kkhfs][m768]") {
    HFSPatternTestConfig config{
        .name = "KKhfs",
        .protocolString = "Noise_KKhfs_25519+M768_ChaChaPoly_SHA256",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

TEST_CASE("HandshakeState - HFS KKhfs with 448+M1024", "[handshakestate][hfs][kkhfs][m1024]") {
    HFSPatternTestConfig config{
        .name = "KKhfs",
        .protocolString = "Noise_KKhfs_448+M1024_AESGCM_BLAKE2b",
        .initiatorNeedsStatic = true,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = true,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

TEST_CASE("HandshakeState - HFS NKhfs with 448+M1024", "[handshakestate][hfs][nkhfs][m1024]") {
    HFSPatternTestConfig config{
        .name = "NKhfs",
        .protocolString = "Noise_NKhfs_448+M1024_ChaChaPoly_BLAKE2b",
        .initiatorNeedsStatic = false,
        .responderNeedsStatic = true,
        .initiatorNeedsRemoteStatic = true,
        .responderNeedsRemoteStatic = false,
        .expectedMessages = 2
    };

    test_hfs_pattern_handshake(config);
}

// ================================
// Concurrency Tests
// ================================

TEST_CASE("HandshakeState - handshakes from one Protocol on two threads", "[handshakestate][thread]") {
    // One Protocol shared by two threads, each running complete NN handshakes built from it.
    // The library must not mutate the Protocol (its Hash in particular) during a handshake.
    // In the ordinary suite this is a smoke test; it is also meant to be run under
    // ThreadSanitizer. No Catch2 macro runs inside a thread: each thread counts its own
    // failures and completed handshakes, and the assertions follow the joins.
    const Protocol protocol{"Noise_NN_25519_ChaChaPoly_SHA256"};
    constexpr int kHandshakesPerThread = 1000;

    std::array<int, 2> failures{0, 0};
    std::array<int, 2> completed{0, 0};

    const auto worker = [&protocol](int& failureCount, int& completedCount) {
        const std::vector<std::uint8_t> payload{'p', 'i', 'n', 'g'};
        for (int i = 0; i < kHandshakesPerThread; ++i) {
            try {
                const HandshakeConfig initiatorCfg{.protocol = protocol, .isInitiator = true};
                const HandshakeConfig responderCfg{.protocol = protocol, .isInitiator = false};
                HandshakeState initiator{initiatorCfg};
                HandshakeState responder{responderCfg};

                const auto msg1 = initiator.WriteMessage({});
                (void)responder.ReadMessage(msg1);
                const auto msg2 = responder.WriteMessage({});
                (void)initiator.ReadMessage(msg2);

                const auto& initiatorStatus = initiator.GetStatus();
                const auto& responderStatus = responder.GetStatus();
                bool ok = initiatorStatus.IsComplete() && responderStatus.IsComplete() &&
                          initiatorStatus.handshakeHash == responderStatus.handshakeHash &&
                          initiatorStatus.cipherStates.has_value() && responderStatus.cipherStates.has_value();
                if (ok) {
                    // One transport message: initiator cs1 encrypts, responder cs1 decrypts.
                    auto tx = initiatorStatus.cipherStates->first;
                    auto rx = responderStatus.cipherStates->first;
                    const auto ciphertext = tx.EncryptWithAd({}, payload);
                    ok = rx.DecryptWithAd({}, ciphertext) == payload;
                }
                if (ok) {
                    ++completedCount;
                } else {
                    ++failureCount;
                }
            } catch (...) {
                ++failureCount;
            }
        }
    };

    {
        std::jthread first{worker, std::ref(failures[0]), std::ref(completed[0])};
        std::jthread second{worker, std::ref(failures[1]), std::ref(completed[1])};
    }

    REQUIRE(failures[0] == 0);
    REQUIRE(failures[1] == 0);
    REQUIRE(completed[0] == kHandshakesPerThread);
    REQUIRE(completed[1] == kHandshakesPerThread);
}

// ============================================================================
// Completion path: TakeCipherStates() and HandshakeStatus::state
// ============================================================================

TEST_CASE("HandshakeState - TakeCipherStates moves the transport states out", "[handshakestate][completion][take]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);
    auto aliceStatic = protocol.dh.GenerateKeypair();
    auto bobStatic = protocol.dh.GenerateKeypair();
    HandshakeConfig aliceCfg{.protocol = protocol, .isInitiator = true, .localStatic = aliceStatic};
    HandshakeConfig bobCfg{.protocol = protocol, .isInitiator = false, .localStatic = bobStatic};
    HandshakeState alice(aliceCfg);
    HandshakeState bob(bobCfg);

    (void)bob.ReadMessage(alice.WriteMessage({}));
    (void)alice.ReadMessage(bob.WriteMessage({}));
    (void)bob.ReadMessage(alice.WriteMessage({}));
    REQUIRE(alice.GetStatus().IsComplete());
    REQUIRE(bob.GetStatus().IsComplete());

    auto a = alice.TakeCipherStates();
    auto b = bob.TakeCipherStates();
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());

    // cs1 carries initiator -> responder, cs2 responder -> initiator (Noise spec Section 5.2).
    const std::vector<std::uint8_t> toBob{'t', 'o', ' ', 'b', 'o', 'b'};
    const std::vector<std::uint8_t> toAlice{'t', 'o', ' ', 'a', 'l', 'i', 'c', 'e'};
    CHECK(b->first.DecryptWithAd({}, a->first.EncryptWithAd({}, toBob)) == toBob);
    CHECK(a->second.DecryptWithAd({}, b->second.EncryptWithAd({}, toAlice)) == toAlice);

    // Taken once: the status no longer holds them, but the handshake is still complete.
    CHECK_FALSE(alice.TakeCipherStates().has_value());
    CHECK_FALSE(bob.TakeCipherStates().has_value());
    CHECK_FALSE(alice.GetStatus().cipherStates.has_value());
    CHECK_FALSE(bob.GetStatus().cipherStates.has_value());
    CHECK(alice.GetStatus().IsComplete());
    CHECK(bob.GetStatus().IsComplete());
    CHECK(alice.GetStatus().handshakeHash == bob.GetStatus().handshakeHash);
}

TEST_CASE("HandshakeStatus - state tracks in progress, done and failed", "[handshakestate][completion][state]") {
    Protocol protocol(XX, X25519, ChaChaPoly, SHA256);
    auto aliceStatic = protocol.dh.GenerateKeypair();
    auto bobStatic = protocol.dh.GenerateKeypair();
    HandshakeConfig aliceCfg{.protocol = protocol, .isInitiator = true, .localStatic = aliceStatic};
    HandshakeConfig bobCfg{.protocol = protocol, .isInitiator = false, .localStatic = bobStatic};

    const auto checkInProgress = [](const HandshakeState& hs) {
        CHECK(hs.GetStatus().state == HandshakeStatus::State::InProgress);
        CHECK_FALSE(hs.GetStatus().IsComplete());
        CHECK_FALSE(hs.GetStatus().HasError());
        CHECK(hs.GetStatus().err == nullptr);
    };
    const auto checkDone = [](const HandshakeState& hs) {
        CHECK(hs.GetStatus().state == HandshakeStatus::State::Done);
        CHECK(hs.GetStatus().IsComplete());
        CHECK_FALSE(hs.GetStatus().HasError());
        // The documented tri-state is kept: err holds a HandshakeComplete on completion.
        REQUIRE(hs.GetStatus().err != nullptr);
        CHECK_THROWS_AS(std::rethrow_exception(hs.GetStatus().err), HandshakeComplete);
    };

    // A completing pair.
    {
        HandshakeState alice(aliceCfg);
        HandshakeState bob(bobCfg);
        checkInProgress(alice);
        checkInProgress(bob);

        (void)bob.ReadMessage(alice.WriteMessage({}));
        checkInProgress(alice);
        checkInProgress(bob);
        (void)alice.ReadMessage(bob.WriteMessage({}));
        (void)bob.ReadMessage(alice.WriteMessage({}));

        checkDone(alice);
        checkDone(bob);
        // A further call rethrows the stored sentinel, as before.
        CHECK_THROWS_AS(alice.ReadMessage(std::vector<std::uint8_t>{}), HandshakeComplete);
        CHECK_THROWS_AS(bob.WriteMessage({}), HandshakeComplete);
        checkDone(alice);
        checkDone(bob);
    }

    // A failing pair: one ciphertext byte of message 2 flipped.
    {
        HandshakeState alice(aliceCfg);
        HandshakeState bob(bobCfg);
        (void)bob.ReadMessage(alice.WriteMessage({}));
        auto msg2 = bob.WriteMessage({});
        msg2.back() ^= 0x01;

        REQUIRE_THROWS_AS(alice.ReadMessage(msg2), DecryptionError);
        CHECK(alice.GetStatus().state == HandshakeStatus::State::Failed);
        CHECK(alice.GetStatus().HasError());
        CHECK_FALSE(alice.GetStatus().IsComplete());
        CHECK_FALSE(alice.GetStatus().cipherStates.has_value());
        REQUIRE(alice.GetStatus().err != nullptr);
        CHECK_THROWS_AS(std::rethrow_exception(alice.GetStatus().err), DecryptionError);

        // Sticky: the failure is rethrown on every later call, and the state stays Failed.
        CHECK_THROWS_AS(alice.ReadMessage(msg2), DecryptionError);
        CHECK_THROWS_AS(alice.WriteMessage({}), DecryptionError);
        CHECK(alice.GetStatus().state == HandshakeStatus::State::Failed);

        // Bob never saw the tampering and is still in progress.
        checkInProgress(bob);
    }
}


TEST_CASE("HandshakeState - a temporary HandshakeConfig does not compile", "[handshakestate][config][lifetime]") {
    // A HandshakeState keeps a reference to its HandshakeConfig (and, through it, to
    // the Protocol), so a temporary config would dangle at the end of the full expression. The
    // rvalue overload is deleted; the lvalue overload is the only way to build a state.
    static_assert(!std::is_constructible_v<HandshakeState, HandshakeConfig&&>);
    static_assert(std::is_constructible_v<HandshakeState, const HandshakeConfig&>);
    SUCCEED("HandshakeState(HandshakeConfig&&) is deleted; HandshakeState(const HandshakeConfig&) remains");
}

// Main function for Catch2
int main(int argc, char* argv[]) {
    // Disable all logging during tests for clean output
    Noise::DisableAllLogging();
    return Catch::Session().run(argc, argv);
}
