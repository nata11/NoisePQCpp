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
// Example Test - Comprehensive API demonstration using Catch2 v3.11
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>

import noise;

using namespace Noise;

TEST_CASE("Example - Protocol construction from string", "[example][protocol]") {
    // Protocols can be constructed by parsing a protocol name
    Protocol protocol("Noise_XX_25519_ChaChaPoly_BLAKE2s");

    REQUIRE(protocol.pattern.String() == "XX");
    REQUIRE(protocol.dh.String() == "25519");
    REQUIRE(protocol.cipher.String() == "ChaChaPoly");
    REQUIRE(protocol.hash.String() == "BLAKE2s");
    REQUIRE(protocol.String() == "Noise_XX_25519_ChaChaPoly_BLAKE2s");
}

TEST_CASE("Example - Protocol construction manual vs string", "[example][protocol]") {
    // Protocols can be constructed by parsing a protocol name
    Protocol protocol1("Noise_XX_25519_ChaChaPoly_BLAKE2s");

    // Protocols can also be constructed manually
    Protocol protocol2(XX, X25519, ChaChaPoly, BLAKE2s);

    // Both should be equivalent
    REQUIRE(protocol1.pattern.String() == protocol2.pattern.String());
    REQUIRE(protocol1.dh.String() == protocol2.dh.String());
    REQUIRE(protocol1.cipher.String() == protocol2.cipher.String());
    REQUIRE(protocol1.hash.String() == protocol2.hash.String());
    REQUIRE(protocol1.String() == protocol2.String());
}

TEST_CASE("Example - Full XX handshake and transport", "[example][handshake]") {
    // Create protocol
    Protocol protocol("Noise_XX_25519_ChaChaPoly_BLAKE2s");

    // Each side needs a HandshakeConfig, properly filled out

    // Generate Alice's static keypair
    Dh dhAlice(protocol.dh.String());
    auto aliceStatic = dhAlice.GenerateKeypair();
    REQUIRE_FALSE(aliceStatic.IsEmpty());

    HandshakeConfig aliceCfg{
        .protocol = protocol,
        .isInitiator = true,
        .localStatic = aliceStatic
    };

    // Generate Bob's static keypair
    Dh dhBob(protocol.dh.String());
    auto bobStatic = dhBob.GenerateKeypair();
    REQUIRE_FALSE(bobStatic.IsEmpty());

    HandshakeConfig bobCfg{
        .protocol = protocol,
        .isInitiator = false,
        .localStatic = bobStatic
    };

    // Each side then constructs a HandshakeState
    HandshakeState aliceHs(aliceCfg);
    HandshakeState bobHs(bobCfg);

    // The SymmetricState and CipherState objects embedded in the
    // HandshakeState can be accessed while the handshake is in progress,
    // though most users likely will not need to do this.
    auto& aliceSs = aliceHs.GetSymmetricState();
    REQUIRE_FALSE(aliceSs.cs.HasKey());  // CipherState accessible via public member 'cs'

    // Then, each side calls hs.ReadMessage/hs.WriteMessage as appropriate

    // Message 1: Alice -> Bob (alice) -> e
    std::vector<std::uint8_t> alicePlaintextE = {
        'a', 'l', 'i', 'c', 'e', ' ', 'e', ' ',
        'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't'
    };  // "alice e plaintext"

    auto aliceMsg1 = aliceHs.WriteMessage(alicePlaintextE);
    REQUIRE_FALSE(aliceMsg1.empty());
    REQUIRE_FALSE(aliceHs.GetStatus().IsComplete());

    auto bobRecv1 = bobHs.ReadMessage(aliceMsg1);
    REQUIRE(bobRecv1 == alicePlaintextE);
    REQUIRE_FALSE(bobHs.GetStatus().IsComplete());

    // Message 2: Bob -> Alice (bob) -> e, ee, s, es
    auto bobMsg1 = bobHs.WriteMessage({});  // Empty payload
    REQUIRE_FALSE(bobMsg1.empty());
    REQUIRE_FALSE(bobHs.GetStatus().IsComplete());

    auto aliceRecv1 = aliceHs.ReadMessage(bobMsg1);
    REQUIRE(aliceRecv1.empty());  // We sent empty payload
    REQUIRE_FALSE(aliceHs.GetStatus().IsComplete());

    // Message 3: Alice -> Bob (alice) -> s, se
    auto aliceMsg2 = aliceHs.WriteMessage({});  // Empty payload
    REQUIRE_FALSE(aliceMsg2.empty());
    REQUIRE(aliceHs.GetStatus().IsComplete());  // Alice completes after write

    auto bobRecv2 = bobHs.ReadMessage(aliceMsg2);
    REQUIRE(bobRecv2.empty());  // We sent empty payload
    REQUIRE(bobHs.GetStatus().IsComplete());  // Bob completes after read

    // Once a handshake is completed, the CipherState objects, handshake hash
    // and various public keys can be pulled out of the HandshakeStatus object
    auto aliceStatus = aliceHs.GetStatus();
    auto bobStatus = bobHs.GetStatus();

    // Verify handshake hashes match
    REQUIRE(aliceStatus.handshakeHash == bobStatus.handshakeHash);

    // Verify ephemeral keys (these are PublicKey = std::vector<std::uint8_t>)
    REQUIRE(aliceStatus.localEphemeral == bobStatus.remoteEphemeral);
    REQUIRE(bobStatus.localEphemeral == aliceStatus.remoteEphemeral);

    // Verify static keys
    REQUIRE(aliceStatus.remoteStatic == bobStatic.public_key);
    REQUIRE(bobStatus.remoteStatic == aliceStatic.public_key);

    // Then the CipherState objects can be used to exchange messages
    REQUIRE(aliceStatus.cipherStates.has_value());
    REQUIRE(bobStatus.cipherStates.has_value());

    auto& aliceTx = aliceStatus.cipherStates->first;
    auto& aliceRx = aliceStatus.cipherStates->second;
    auto& bobRx = bobStatus.cipherStates->first;  // Reversed from alice!
    auto& bobTx = bobStatus.cipherStates->second;

    REQUIRE(aliceTx.HasKey());
    REQUIRE(aliceRx.HasKey());
    REQUIRE(bobTx.HasKey());
    REQUIRE(bobRx.HasKey());

    // Alice -> Bob, post-handshake
    std::vector<std::uint8_t> alicePlaintext = {
        'a', 'l', 'i', 'c', 'e', ' ', 't', 'r', 'a', 'n', 's', 'p', 'o', 'r', 't', ' ',
        'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't'
    };  // "alice transport plaintext"

    auto aliceMsg3 = aliceTx.EncryptWithAd({}, alicePlaintext);
    REQUIRE_FALSE(aliceMsg3.empty());
    REQUIRE(aliceMsg3.size() > alicePlaintext.size());  // Should have overhead

    auto bobRecv3 = bobRx.DecryptWithAd({}, aliceMsg3);
    REQUIRE(bobRecv3 == alicePlaintext);

    // Bob -> Alice, post-handshake
    std::vector<std::uint8_t> bobPlaintext = {
        'b', 'o', 'b', ' ', 't', 'r', 'a', 'n', 's', 'p', 'o', 'r', 't', ' ',
        'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't'
    };  // "bob transport plaintext"

    auto bobMsg2 = bobTx.EncryptWithAd({}, bobPlaintext);
    REQUIRE_FALSE(bobMsg2.empty());
    REQUIRE(bobMsg2.size() > bobPlaintext.size());  // Should have overhead

    auto aliceRecv2 = aliceRx.DecryptWithAd({}, bobMsg2);
    REQUIRE(aliceRecv2 == bobPlaintext);
}

// Main function for Catch2
int main(int argc, char* argv[]) {
    // Disable all logging during tests for clean output
    Noise::DisableAllLogging();
    return Catch::Session().run(argc, argv);
}
