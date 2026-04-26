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
// Bob - Quote Exchange Client (Initiator)
// Connects to Alice, performs handshake, then exchanges quotes
// Supports XX, pqXX, and XXhfs modes with X448/M1024 and AESGCM/SHA512
//

#include <json.hpp>
#include "asio_common.hpp"
import noise;

using namespace Noise;
using namespace NoiseAsio;
using json = nlohmann::json;

// ============================================================================
// Quote Management
// ============================================================================

struct Quotes {
    std::vector<std::string> my_quotes;      // Bob's quotes to send
    std::vector<std::string> their_quotes;   // Alice's quotes for verification
};

Quotes load_quotes_for_bob(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open quotes file: " + filepath);
    }

    json j;
    file >> j;

    Quotes quotes;
    for (const auto& q : j.at("bob_quotes")) {
        quotes.my_quotes.push_back(q.get<std::string>());
    }
    for (const auto& q : j.at("alice_quotes")) {
        quotes.their_quotes.push_back(q.get<std::string>());
    }

    return quotes;
}

// ============================================================================
// Mode Configuration
// ============================================================================

struct ModeConfig {
    std::string mode;           // "xx", "pqxx", "xxhfs"
    std::string protocol_str;   // Full protocol string
    std::string description;    // Human-readable description
};

ModeConfig get_mode_config(std::string_view mode) {
    if (mode == "xx") {
        return {
            .mode = "xx",
            .protocol_str = "Noise_XX_448_AESGCM_SHA512",
            .description = "Classical (X448 DH)"
        };
    }
    if (mode == "pqxx") {
        return {
            .mode = "pqxx",
            .protocol_str = "Noise_pqXX_M1024_AESGCM_SHA512",
            .description = "Post-Quantum (ML-KEM-1024)"
        };
    }
    if (mode == "xxhfs") {
        return {
            .mode = "xxhfs",
            .protocol_str = "Noise_XXhfs_448+M1024_AESGCM_SHA512",
            .description = "Hybrid Forward Secrecy (X448 + ML-KEM-1024)"
        };
    }
    throw std::invalid_argument(std::format("Unknown mode: '{}'. Valid modes: xx, pqxx, xxhfs", mode));
}

// Create prologue for mode binding
std::vector<std::uint8_t> create_prologue(std::string_view mode) {
    std::string prologue_str = std::format("ALICE_BOB_MODE:{}", mode);
    return to_bytes(prologue_str);
}

// ============================================================================
// Bob Client
// ============================================================================

class Bob {
public:
    Bob(asio::io_context& io_context, const ModeConfig& config,
        const Quotes& quotes, const std::string& host, std::uint16_t port)
        : socket_(io_context)
        , config_(config)
        , protocol_(config.protocol_str)
        , prologue_(create_prologue(config.mode))
        , quotes_(quotes)
    {
        // Generate Bob's static keypair
        Dh dh(protocol_.dh.String());
        bob_static_ = dh.GenerateKeypair();

        std::println("Bob's static public key generated:");
        print_bytes_hex("Public key", bob_static_.public_key);

        // Connect to Alice
        connect(host, port);
    }

    void run() {
        // Perform handshake (Bob is initiator)
        auto [tx, rx] = perform_handshake();

        std::println("\nHandshake complete! Mode '{}' verified.", config_.mode);
        std::println("Starting quote exchange...");
        std::println("{}", std::string(60, '-'));

        // Exchange quotes
        exchange_quotes(tx, rx);
    }

private:
    void connect(const std::string& host, std::uint16_t port) {
        print_separator("BOB - QUOTE EXCHANGE CLIENT");
        std::println("Mode:     {} ({})", config_.mode, config_.description);
        std::println("Protocol: {}", protocol_.String());
        std::println("Quotes:   {} to send, {} for verification",
                     quotes_.my_quotes.size(), quotes_.their_quotes.size());
        std::println("\nConnecting to Alice at {}:{}...", host, port);

        tcp::resolver resolver(socket_.get_executor());
        auto endpoints = resolver.resolve(host, std::to_string(port));
        asio::connect(socket_, endpoints);

        std::println("Connected to Alice!");
    }

    std::pair<CipherState, CipherState> perform_handshake() {
        std::println("\nPerforming {} handshake (initiator)...", config_.mode);

        HandshakeConfig hs_config{
            .protocol = protocol_,
            .isInitiator = true,
            .prologue = prologue_,
            .localStatic = bob_static_
        };
        HandshakeState hs(hs_config);

        // XX/XXhfs: 3 messages        pqXX: 4 messages
        // -> e                         -> e
        // <- e, ee, s, es              <- ekem, s
        // -> s, se                     -> skem, s
        //                              <- skem

        // Message 1: Send to Alice (e + payload)
        std::println("  -> Sending handshake message 1...");
        auto bob_init = to_bytes("BOB_INIT");
        auto msg1 = hs.WriteMessage(bob_init);
        send_framed(socket_, msg1);
        std::println("     Sent {} bytes with payload \"BOB_INIT\"", msg1.size());

        // Message 2: Receive from Alice (e,ee,s,es or ekem,s + payload)
        std::println("  <- Receiving handshake message 2...");
        auto msg2 = recv_framed(socket_);
        auto payload2 = hs.ReadMessage(msg2);
        std::println("     Received {} bytes, payload: \"{}\"", msg2.size(), to_string(payload2));

        // Message 3: Send to Alice (s,se or skem,s + payload)
        std::println("  -> Sending handshake message 3...");
        auto bob_confirm = to_bytes("BOB_CONFIRM");
        auto msg3 = hs.WriteMessage(bob_confirm);
        send_framed(socket_, msg3);
        std::println("     Sent {} bytes with payload \"BOB_CONFIRM\"", msg3.size());

        // Message 4: pqXX requires a 4th message (receive from responder)
        if (config_.mode == "pqxx") {
            std::println("  <- Receiving handshake message 4...");
            auto msg4 = recv_framed(socket_);
            auto payload4 = hs.ReadMessage(msg4);
            std::println("     Received {} bytes, payload: \"{}\"", msg4.size(), to_string(payload4));
        }

        // Verify handshake completed
        auto status = hs.GetStatus();
        if (!status.IsComplete()) {
            throw std::runtime_error("Handshake did not complete");
        }

        if (!status.cipherStates.has_value()) {
            throw std::runtime_error("No cipher states available after handshake");
        }

        std::println("\n  Alice authenticated:");
        print_bytes_hex("  Remote static key", status.remoteStatic);
        print_bytes_hex("  Handshake hash", status.handshakeHash);

        // For initiator: first = Tx, second = Rx
        return {status.cipherStates->first, status.cipherStates->second};
    }

    void exchange_quotes(CipherState& tx, CipherState& rx) {
        std::size_t total_quotes = quotes_.my_quotes.size();
        std::size_t successful = 0;
        std::size_t failed = 0;

        std::println("\nExchanging {} quotes with Alice...\n", total_quotes);

        for (std::size_t i = 0; i < total_quotes; ++i) {
            std::size_t quote_num = i + 1;

            try {
                // Receive Alice's quote
                auto alice_ciphertext = recv_framed(socket_);
                auto alice_plaintext = rx.DecryptWithAd({}, alice_ciphertext);
                std::string alice_msg = to_string(alice_plaintext);

                // Parse and verify Alice's quote
                // Expected format: "Alice #N: <quote>"
                std::string expected_prefix = std::format("Alice #{}: ", quote_num);
                if (alice_msg.starts_with(expected_prefix)) {
                    std::string received_quote = alice_msg.substr(expected_prefix.size());
                    if (received_quote == quotes_.their_quotes[i]) {
                        std::println("  Recv Alice #{}: \"{}\" [VERIFIED]", quote_num, received_quote);
                        successful++;
                    } else {
                        std::println("{}  Recv Alice #{}: \"{}\" [MISMATCH]{}",
                            Color::BrightRed, quote_num, received_quote, Color::Reset);
                        std::println("{}       Expected: \"{}\"{}",
                            Color::BrightRed, quotes_.their_quotes[i], Color::Reset);
                        failed++;
                    }
                } else {
                    std::println("  Recv Alice: \"{}\" [FORMAT ERROR]", alice_msg);
                    failed++;
                }

                // Send Bob's quote as acknowledgment
                std::string bob_msg = std::format("Bob #{}: {}", quote_num, quotes_.my_quotes[i]);
                auto ciphertext = tx.EncryptWithAd({}, to_bytes(bob_msg));
                send_framed(socket_, ciphertext);
                std::println("  Sent Bob #{}: \"{}\"", quote_num, quotes_.my_quotes[i]);

            } catch (const asio::system_error& e) {
                if (e.code() == asio::error::eof) {
                    std::println("\nAlice disconnected during exchange at quote #{}.", quote_num);
                } else {
                    std::println("\nConnection error at quote #{}: {}", quote_num, e.what());
                }
                break;
            }
        }

        std::println("\n{}", std::string(60, '='));
        std::println("Quote exchange complete!");
        std::println("  Successful: {}/{}", successful, total_quotes);
        std::println("  Failed:     {}/{}", failed, total_quotes);
        std::println("{}", std::string(60, '='));

        std::println("\nDisconnecting from Alice...");
    }

    tcp::socket socket_;
    ModeConfig config_;
    Protocol protocol_;
    std::vector<std::uint8_t> prologue_;
    Quotes quotes_;
    KeyPair bob_static_;
};

// ============================================================================
// Main
// ============================================================================

void print_usage(const char* program) {
    std::println("Usage: {} [mode] [host] [port]", program);
    std::println("");
    std::println("Bob - Quote Exchange Client (Initiator)");
    std::println("");
    std::println("Modes:");
    std::println("  xx      - Classical XX pattern (X448 DH) [default]");
    std::println("  pqxx    - Post-Quantum pqXX pattern (ML-KEM-1024)");
    std::println("  xxhfs   - Hybrid XXhfs pattern (X448 + ML-KEM-1024)");
    std::println("");
    std::println("Host: localhost (default)");
    std::println("Port: {} (default)", DEFAULT_PORT);
    std::println("");
    std::println("Examples:");
    std::println("  {}                          # Classical mode, localhost:{}", program, DEFAULT_PORT);
    std::println("  {} pqxx                     # Post-quantum mode", program);
    std::println("  {} xxhfs 192.168.1.10 12346 # Hybrid mode, custom host:port", program);
    std::println("");
    std::println("Note: Bob's mode must match Alice's mode, or handshake will fail.");
}

int main(int argc, char* argv[]) {
    try {
        std::string mode = "xx";
        std::string host = "localhost";
        std::uint16_t port = DEFAULT_PORT;

        // Parse arguments
        if (argc > 1) {
            std::string arg1 = argv[1];
            if (arg1 == "-h" || arg1 == "--help") {
                print_usage(argv[0]);
                return 0;
            }
            mode = arg1;
        }
        if (argc > 2) {
            host = argv[2];
        }
        if (argc > 3) {
            port = static_cast<std::uint16_t>(std::stoi(argv[3]));
        }

        // Validate mode
        auto config = get_mode_config(mode);

        // Load quotes from testdata directory
        // Bob loads from bob_alice_quotes.json (his copy, allowing mismatch simulation)
        const std::string quotes_path = std::string(TESTDATA_DIR) + "/bob_alice_quotes.json";

        std::println("Loading quotes from: {}", quotes_path);
        auto quotes = load_quotes_for_bob(quotes_path);
        std::println("Loaded {} Bob quotes and {} Alice quotes for verification\n",
                     quotes.my_quotes.size(), quotes.their_quotes.size());

        asio::io_context io_context;
        Bob bob(io_context, config, quotes, host, port);
        bob.run();

    } catch (const NoiseError& e) {
        std::println("\nHandshake failed: {}", e.what());
        std::println("Hint: Alice may be running in a different mode.");
        std::println("      Make sure both Alice and Bob use the same mode (xx, pqxx, or xxhfs).");
        return 1;
    } catch (const asio::system_error& e) {
        std::println("\nConnection error: {}", e.what());
        std::println("Hint: Make sure Alice is running before starting Bob.");
        return 1;
    } catch (const std::exception& e) {
        std::println("Error: {}", e.what());
        return 1;
    }

    return 0;
}
