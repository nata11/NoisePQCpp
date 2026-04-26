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
// Catch 2 v3 Test Vectors Tests
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>
#include <catch2/matchers/catch_matchers_all.hpp>
#include "botan_all.h"
#include <json.hpp>

import noise;

using json = nlohmann::json;
using namespace Botan;
using namespace Noise;
using ByteVec = std::vector<std::uint8_t>;

// ============================================================================
// Test Vector Structures
// ============================================================================

struct TestMessage {
    ByteVec payload; // hex string
    ByteVec ciphertext; // hex string
};

struct TestVector {
    std::string protocol_name;

    // Prologues
    ByteVec init_prologue; //always present in test vectors
    ByteVec resp_prologue; //always present in test vectors

    // Keys
    ByteVec init_static;
    ByteVec init_ephemeral; //always present in test vectors
    ByteVec init_remote_static; // For one-way patterns

    ByteVec resp_static;
    ByteVec resp_ephemeral;
    ByteVec resp_remote_static; // For one-way patterns

    // Pre-shared keys
    std::vector<ByteVec> init_psks;
    std::vector<ByteVec> resp_psks;

    // Expected handshake hash
    ByteVec handshake_hash; // always present in test vectors

    // Messages
    std::vector<TestMessage> messages; //always present in test vectors
};

KeyPair keypair_from_private(std::size_t key_size, const std::vector<std::uint8_t>& private_key) {
    KeyPair kp;
    kp.private_key = private_key;

    // Derive public key from private key using Botan based on key size
    if (key_size == 32) {
        // X25519
        const Botan::X25519_PrivateKey sk(
            Botan::secure_vector<std::uint8_t>(private_key.begin(), private_key.end()));
        auto pub_bits = sk.raw_public_key_bits();
        kp.public_key = {pub_bits.begin(), pub_bits.end()};
    }
    else if (key_size == 56) {
        // X448
        const Botan::X448_PrivateKey sk(
            Botan::secure_vector<std::uint8_t>(private_key.begin(), private_key.end()));
        auto pub_bits = sk.raw_public_key_bits();
        kp.public_key = {pub_bits.begin(), pub_bits.end()};
    }
    else {
        throw std::runtime_error(std::format("Unsupported key size: {}", key_size));
    }

    return kp;
}

// ============================================================================
// JSON Loading
// ============================================================================

std::vector<TestVector> load_test_vectors(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open test vector file: " + filepath);
    }

    json j;
    file >> j;

    std::vector<TestVector> test_vectors;

    for (const auto& vec_json : j["vectors"]) {
        TestVector vec;
        vec.protocol_name = vec_json.at("protocol_name").get<std::string>();

        // Prologues
        vec.init_prologue = hex_decode(vec_json.at("init_prologue").get<std::string_view>());
        vec.resp_prologue = hex_decode(vec_json.at("resp_prologue").get<std::string_view>());

        // Init keys
        vec.init_ephemeral = hex_decode(vec_json.at("init_ephemeral").get<std::string_view>());
        if (vec_json.contains("init_static")) {
            vec.init_static = hex_decode(vec_json.at("init_static").get<std::string_view>());
        }
        if (vec_json.contains("init_remote_static")) {
            vec.init_remote_static = hex_decode(vec_json.at("init_remote_static").get<std::string_view>());
        }
        // Resp keys
        if (vec_json.contains("resp_static")) {
            vec.resp_static = hex_decode(vec_json.at("resp_static").get<std::string_view>());
        }
        if (vec_json.contains("resp_ephemeral")) {
            vec.resp_ephemeral = hex_decode(vec_json.at("resp_ephemeral").get<std::string_view>());
        }
        if (vec_json.contains("resp_remote_static")) {
            vec.resp_remote_static = hex_decode(vec_json.at("resp_remote_static").get<std::string_view>());
        }

        // Optional PSKs
        if (vec_json.contains("init_psks")) {
            for (const auto& psk : vec_json.at("init_psks")) {
                vec.init_psks.push_back(hex_decode(psk.get<std::string_view>()));
            }
        }
        if (vec_json.contains("resp_psks")) {
            for (const auto& psk : vec_json.at("resp_psks")) {
                vec.resp_psks.push_back(hex_decode(psk.get<std::string_view>()));
            }
        }

        // Handshake hash
        vec.handshake_hash = hex_decode(vec_json.at("handshake_hash").get<std::string_view>());

        // Messages
        for (const auto& msg_json : vec_json.at("messages")) {
            TestMessage msg;
            msg.payload = hex_decode(msg_json.at("payload").get<std::string_view>());
            msg.ciphertext = hex_decode(msg_json.at("ciphertext").get<std::string_view>());
            vec.messages.push_back(std::move(msg));
        }

        test_vectors.push_back(vec);
    }

    return test_vectors;
}

// ============================================================================
// Config Creation Helper
// ============================================================================

std::pair<HandshakeConfig, HandshakeConfig> create_test_vector_configs(
    const TestVector& vec,
    const Protocol& protocol) {
    const std::size_t dh_key_size = protocol.dh.Size();

    HandshakeConfig init_cfg{
        .protocol = protocol,
        .isInitiator = true,
        .prologue = vec.init_prologue,
        .localStatic = vec.init_static.empty() ? KeyPair{} : keypair_from_private(dh_key_size, vec.init_static),
        .localEphemeral = keypair_from_private(dh_key_size, vec.init_ephemeral),
        .remoteStatic = vec.init_remote_static.empty() ? PublicKey{} : vec.init_remote_static,
    };

    if (!vec.init_psks.empty()) {
        for (const auto& psk_bytes : vec.init_psks) {
            std::array<std::uint8_t, SYMMETRIC_KEY_SIZE> psk{};
            if (psk_bytes.size() != SYMMETRIC_KEY_SIZE) {
                throw std::runtime_error("Invalid PSK size in initiator config");
            }
            std::ranges::copy(psk_bytes, psk.begin());
            init_cfg.preSharedKeys.push_back(psk);
        }
    }

    HandshakeConfig resp_cfg{
        .protocol = protocol,
        .isInitiator = false,
        .prologue = vec.resp_prologue,
        .localStatic = vec.resp_static.empty() ? KeyPair{} : keypair_from_private(dh_key_size, vec.resp_static),
        .localEphemeral = vec.resp_ephemeral.empty()
                              ? KeyPair{}
                              : keypair_from_private(dh_key_size, vec.resp_ephemeral),
        .remoteStatic = vec.resp_remote_static.empty() ? PublicKey{} : vec.resp_remote_static,
    };

    if (!vec.resp_psks.empty()) {
        for (const auto& psk_bytes : vec.resp_psks) {
            std::array<std::uint8_t, SYMMETRIC_KEY_SIZE> psk{};
            if (psk_bytes.size() != SYMMETRIC_KEY_SIZE) {
                throw std::runtime_error("Invalid PSK size in responder config");
            }
            std::ranges::copy(psk_bytes, psk.begin());
            resp_cfg.preSharedKeys.push_back(psk);
        }
    }

    return {init_cfg, resp_cfg};
}

// ============================================================================
// Message Testing Logic
// ============================================================================

void test_vector_messages(const TestVector& vec, HandshakeState& hs) {

    const bool is_initiator = hs.IsInitiator();
    const bool writeOnEven = hs.IsInitiator();
    const bool is_one_way = hs.GetConfig().protocol.pattern.isOneWay;

    // Transport phase cipher states - will be populated once handshake completes
    std::unique_ptr<CipherState> txCs;
    std::unique_ptr<CipherState> rxCs;

    for (std::size_t idx = 0; idx < vec.messages.size(); ++idx) {

        ByteVec result, expected;
        const auto& [payload, ciphertext] = vec.messages[idx];
        const bool isEvenMessage = (idx & 1) == 0;

        if (!hs.GetStatus().IsComplete()) {

            // Handshake phase
            if (isEvenMessage == writeOnEven) {
                // Write message
                INFO("Message " << idx << ": " << (is_initiator ? "Initiator" : "Responder") << " writing");
                result = hs.WriteMessage(payload);
                expected = ciphertext;
            }
            else {
                // Read message
                INFO("Message " << idx << ": " << (is_initiator ? "Initiator" : "Responder") << " reading");
                result = hs.ReadMessage(ciphertext);
                expected = payload;
            }

            // Check if handshake just completed
            if (hs.GetStatus().IsComplete()) {
                // Verify handshake hash
                if (!vec.handshake_hash.empty()) {
                    auto actual_hash = hs.GetStatus().handshakeHash;
                    REQUIRE_THAT(actual_hash, Catch::Matchers::Equals(vec.handshake_hash));
                }
                auto cipher_states = hs.GetStatus().cipherStates;
                REQUIRE(cipher_states.has_value());
                REQUIRE(cipher_states->first.HasKey());
                if (is_one_way) {
                    // For one-way patterns, second cipher state should be empty
                    REQUIRE_FALSE(cipher_states->second.HasKey());
                }
                else {
                    REQUIRE(cipher_states->second.HasKey());
                }

                txCs = is_initiator
                           ? std::make_unique<CipherState>(cipher_states->first)
                           : std::make_unique<CipherState>(cipher_states->second);
                rxCs = is_initiator
                           ? std::make_unique<CipherState>(cipher_states->second)
                           : std::make_unique<CipherState>(cipher_states->first);
            }
        }
        else {
            // Transport phase
            // The messages that use the derived cipherstates just follow the
            // handshake message(s), and the flow continues.
            if (is_one_way) {
                // Except one-way patterns which go from initiator to responder.
                if (is_initiator) {
                    result = txCs->EncryptWithAd({}, payload);
                    expected = ciphertext;
                }
                else {
                    result = rxCs->DecryptWithAd({}, ciphertext);
                    expected = payload;
                }
            }
            else {
                if (isEvenMessage == writeOnEven) {
                    result = txCs->EncryptWithAd({}, payload);
                    expected = ciphertext;
                }
                else {
                    result = rxCs->DecryptWithAd({}, ciphertext);
                    expected = payload;
                }
            }
        }
        REQUIRE_THAT(result, Catch::Matchers::Equals(expected));
    }

    if (txCs != nullptr) {
        txCs->Reset();
    }
    if (rxCs != nullptr) {
        rxCs->Reset();
    }
}

// ============================================================================
// Catch2 Test Cases
// ============================================================================

TEST_CASE("Test vectors from cacophony.json", "[vectors][small1]") {

    // Use compile-time definition from CMakeLists.txt for robust path resolution
    const std::string filepath = std::string(TESTDATA_DIR) + "/cacophony.json";

    auto vectors = load_test_vectors(filepath);

    SECTION("Run full protocol tests - All protocols") {
        REQUIRE(!vectors.empty());

        for (const auto& vec : vectors) {
            INFO("Testing protocol: " << vec.protocol_name);
            REQUIRE(!vec.protocol_name.empty());
            REQUIRE(!vec.messages.empty());

            // Parse protocol
            Protocol protocol(vec.protocol_name);
            auto err = HandshakePattern::IsValid(protocol.pattern);
            INFO("Validating pattern for protocol: " << vec.protocol_name);
            REQUIRE(err.has_value());

            // Create configs for initiator and responder
            auto [init_cfg, resp_cfg] = create_test_vector_configs(vec, protocol);

            // Test initiator perspective
            {
                HandshakeState init_hs{init_cfg};
                test_vector_messages(vec, init_hs);
            }

            // Test responder perspective (need fresh state)
            {
                HandshakeState resp_hs{resp_cfg};
                test_vector_messages(vec, resp_hs);
            }
        }
    }
}

// ============================================================================
// Catch2 Main
// ============================================================================

int main(int argc, char* argv[]) {
    // Disable all logging during tests for clean output
    Noise::DisableAllLogging();
    return Catch::Session().run(argc, argv);
}
