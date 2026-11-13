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
// Alice - Quote Exchange Server (Responder)
// Waits for Bob to connect, performs handshake, then exchanges quotes
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
    std::vector<std::string> my_quotes;      // Alice's quotes to send
    std::vector<std::string> their_quotes;   // Bob's quotes for verification
};

Quotes load_quotes_for_alice(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open quotes file: " + filepath);
    }

    json j;
    file >> j;

    Quotes quotes;
    for (const auto& q : j.at("alice_quotes")) {
        quotes.my_quotes.push_back(q.get<std::string>());
    }
    for (const auto& q : j.at("bob_quotes")) {
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
// Alice Server
// ============================================================================

class Alice {
public:
    Alice(asio::io_context& io_context, const ModeConfig& config,
          const Quotes& quotes, std::uint16_t port)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
        , config_(config)
        , protocol_(config.protocol_str)
        , prologue_(create_prologue(config.mode))
        , quotes_(quotes)
    {
        // Generate Alice's static keypair
        Dh dh(protocol_.dh.String());
        alice_static_ = dh.GenerateKeypair();

        std::println("Alice's static public key generated:");
        print_bytes_hex("Public key", alice_static_.public_key);
    }

    void run() {
        print_separator("ALICE - QUOTE EXCHANGE SERVER");
        std::println("Mode:     {} ({})", config_.mode, config_.description);
        std::println("Protocol: {}", protocol_.String());
        std::println("Port:     {}", acceptor_.local_endpoint().port());
        std::println("Quotes:   {} to send, {} for verification\n",
                     quotes_.my_quotes.size(), quotes_.their_quotes.size());

        while (true) {
            try {
                handle_bob();
            } catch (const NoiseError& e) {
                std::println("\nHandshake error: {}", e.what());
                std::println("Hint: Bob may be using a different mode (Alice mode: '{}')", config_.mode);
                std::println("\nWaiting for Bob to connect again...\n");
            } catch (const std::exception& e) {
                std::println("\nSession error: {}", e.what());
                std::println("\nWaiting for Bob to connect again...\n");
            }
        }
    }

private:
    void handle_bob() {
        std::println("{}", std::string(60, '-'));
        std::println("Waiting for Bob's connection...");

        // Accept incoming connection
        tcp::socket socket(acceptor_.get_executor());
        acceptor_.accept(socket);

        auto remote = socket.remote_endpoint();
        std::println("Bob connected from {}:{}", remote.address().to_string(), remote.port());

        // Perform handshake (Alice is responder)
        auto [rx, tx] = perform_handshake(socket);

        std::println("\nHandshake complete! Mode '{}' verified.", config_.mode);
        std::println("Starting quote exchange...");
        std::println("{}", std::string(60, '-'));

        // Exchange quotes
        exchange_quotes(socket, rx, tx);
    }

    std::pair<CipherState, CipherState> perform_handshake(tcp::socket& socket) {
        std::println("\nPerforming {} handshake (responder)...", config_.mode);

        HandshakeConfig hs_config{
            .protocol = protocol_,
            .isInitiator = false,
            .prologue = prologue_,
            .localStatic = alice_static_
        };
        HandshakeState hs(hs_config);

        // XX/XXhfs: 3 messages        pqXX: 4 messages
        // -> e                         -> e
        // <- e, ee, s, es              <- ekem, s
        // -> s, se                     -> skem, s
        //                              <- skem

        // Message 1: Receive from Bob (e + payload)
        std::println("  <- Receiving handshake message 1...");
        auto msg1 = recv_framed(socket);
        auto payload1 = hs.ReadMessage(msg1);
        std::println("     Received {} bytes, payload: \"{}\"", msg1.size(), to_string(payload1));

        // Message 2: Send to Bob (e,ee,s,es or ekem,s + payload)
        std::println("  -> Sending handshake message 2...");
        auto alice_hello = to_bytes("ALICE_HELLO");
        auto msg2 = hs.WriteMessage(alice_hello);
        send_framed(socket, msg2);
        std::println("     Sent {} bytes with payload \"ALICE_HELLO\"", msg2.size());

        // Message 3: Receive from Bob (s,se or skem,s + payload)
        std::println("  <- Receiving handshake message 3...");
        auto msg3 = recv_framed(socket);
        auto payload3 = hs.ReadMessage(msg3);
        std::println("     Received {} bytes, payload: \"{}\"", msg3.size(), to_string(payload3));

        // Message 4: pqXX requires a 4th message (responder sends <- skem)
        if (config_.mode == "pqxx") {
            std::println("  -> Sending handshake message 4...");
            auto alice_ready = to_bytes("ALICE_READY");
            auto msg4 = hs.WriteMessage(alice_ready);
            send_framed(socket, msg4);
            std::println("     Sent {} bytes with payload \"ALICE_READY\"", msg4.size());
        }

        // Verify handshake completed
        const auto& status = hs.GetStatus();
        if (!status.IsComplete()) {
            throw std::runtime_error("Handshake did not complete");
        }

        // Take the transport states out of the HandshakeState (moved, not copied)
        auto cs = hs.TakeCipherStates();
        if (!cs) {
            throw std::runtime_error("No cipher states available after handshake");
        }

        std::println("\n  Bob authenticated:");
        print_bytes_hex("  Remote static key", status.remoteStatic);
        print_bytes_hex("  Handshake hash", status.handshakeHash);

        // For responder: first = Rx, second = Tx
        return {std::move(cs->first), std::move(cs->second)};
    }

    void exchange_quotes(tcp::socket& socket, CipherState& rx, CipherState& tx) {
        std::size_t total_quotes = quotes_.my_quotes.size();
        std::size_t successful = 0;
        std::size_t failed = 0;

        std::println("\nExchanging {} quotes with Bob...\n", total_quotes);

        for (std::size_t i = 0; i < total_quotes; ++i) {
            std::size_t quote_num = i + 1;

            try {
                // Send Alice's quote
                std::string alice_msg = std::format("Alice #{}: {}", quote_num, quotes_.my_quotes[i]);
                auto ciphertext = tx.EncryptWithAd({}, to_bytes(alice_msg));
                send_framed(socket, ciphertext);
                std::println("  Sent Alice #{}: \"{}\"", quote_num, quotes_.my_quotes[i]);

                // Receive Bob's quote
                auto bob_ciphertext = recv_framed(socket);
                auto bob_plaintext = rx.DecryptWithAd({}, bob_ciphertext);
                std::string bob_msg = to_string(bob_plaintext);

                // Parse and verify Bob's quote
                // Expected format: "Bob #N: <quote>"
                std::string expected_prefix = std::format("Bob #{}: ", quote_num);
                if (bob_msg.starts_with(expected_prefix)) {
                    std::string received_quote = bob_msg.substr(expected_prefix.size());
                    if (received_quote == quotes_.their_quotes[i]) {
                        std::println("  Recv Bob #{}: \"{}\" [VERIFIED]", quote_num, received_quote);
                        successful++;
                    } else {
                        std::println("{}  Recv Bob #{}: \"{}\" [MISMATCH]{}",
                            Color::BrightRed, quote_num, received_quote, Color::Reset);
                        std::println("{}       Expected: \"{}\"{}",
                            Color::BrightRed, quotes_.their_quotes[i], Color::Reset);
                        failed++;
                    }
                } else {
                    std::println("  Recv Bob: \"{}\" [FORMAT ERROR]", bob_msg);
                    failed++;
                }

            } catch (const asio::system_error& e) {
                if (e.code() == asio::error::eof) {
                    std::println("\nBob disconnected during exchange at quote #{}.", quote_num);
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
    }

    tcp::acceptor acceptor_;
    ModeConfig config_;
    Protocol protocol_;
    std::vector<std::uint8_t> prologue_;
    Quotes quotes_;
    KeyPair alice_static_;
};

// ============================================================================
// Main
// ============================================================================

void print_usage(const char* program) {
    std::println("Usage: {} [mode] [port]", program);
    std::println("");
    std::println("Alice - Quote Exchange Server (Responder)");
    std::println("");
    std::println("Modes:");
    std::println("  xx      - Classical XX pattern (X448 DH) [default]");
    std::println("  pqxx    - Post-Quantum pqXX pattern (ML-KEM-1024)");
    std::println("  xxhfs   - Hybrid XXhfs pattern (X448 + ML-KEM-1024)");
    std::println("");
    std::println("Port: {} (default)", DEFAULT_PORT);
    std::println("");
    std::println("Examples:");
    std::println("  {} xx           # Classical mode on default port", program);
    std::println("  {} pqxx 12346   # Post-quantum mode on port 12346", program);
    std::println("  {} xxhfs        # Hybrid mode on default port", program);
}

int main(int argc, char* argv[]) {
    try {
        std::string mode = "xx";
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
            port = static_cast<std::uint16_t>(std::stoi(argv[2]));
        }

        // Validate mode
        auto config = get_mode_config(mode);

        // Load quotes from testdata directory
        const std::string quotes_path = std::string(TESTDATA_DIR) + "/alice_bob_quotes.json";

        std::println("Loading quotes from: {}", quotes_path);
        auto quotes = load_quotes_for_alice(quotes_path);
        std::println("Loaded {} Alice quotes and {} Bob quotes for verification\n",
                     quotes.my_quotes.size(), quotes.their_quotes.size());

        asio::io_context io_context;
        Alice alice(io_context, config, quotes, port);
        alice.run();

    } catch (const std::exception& e) {
        std::println("Fatal error: {}", e.what());
        return 1;
    }

    return 0;
}
