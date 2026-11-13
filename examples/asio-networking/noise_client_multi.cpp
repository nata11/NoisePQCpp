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
// Noise Protocol Multi-Mode Client Example
// Supports XX (classical), pqXX (post-quantum), and XXhfs (hybrid) modes
// Mode enforcement via Noise prologue matching
//

#include "asio_common.hpp"
import std;
import noise;

using namespace Noise;
using namespace NoiseAsio;

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
            .protocol_str = "Noise_XX_25519_ChaChaPoly_BLAKE2s",
            .description = "Classical (X25519 DH)"
        };
    }
    if (mode == "pqxx") {
        return {
            .mode = "pqxx",
            .protocol_str = "Noise_pqXX_M768_ChaChaPoly_BLAKE2s",
            .description = "Post-Quantum (ML-KEM-768)"
        };
    }
    if (mode == "xxhfs") {
        return {
            .mode = "xxhfs",
            .protocol_str = "Noise_XXhfs_25519+M768_ChaChaPoly_BLAKE2s",
            .description = "Hybrid Forward Secrecy (X25519 + ML-KEM-768)"
        };
    }
    throw std::invalid_argument(std::format("Unknown mode: '{}'. Valid modes: xx, pqxx, xxhfs", mode));
}

// Create prologue for mode binding
std::vector<std::uint8_t> create_prologue(std::string_view mode) {
    std::string prologue_str = std::format("NOISEPQC_MODE:{}", mode);
    return to_bytes(prologue_str);
}

// ============================================================================
// Multi-Mode Client
// ============================================================================

class NoiseClientMulti {
public:
    NoiseClientMulti(asio::io_context& io_context, const ModeConfig& config,
                     const std::string& host, std::uint16_t port)
        : socket_(io_context)
        , config_(config)
        , protocol_(config.protocol_str)
        , prologue_(create_prologue(config.mode))
    {
        // Generate client's static keypair based on mode
        Dh dh(protocol_.dh.String());
        client_static_ = dh.GenerateKeypair();

        std::println("Client static public key generated:");
        print_bytes_hex("Public key", client_static_.public_key);

        // Connect to server
        connect(host, port);
    }

    void run() {
        // Perform handshake with prologue binding
        auto [tx, rx] = perform_handshake();

        std::println("\nHandshake complete! Mode '{}' verified.", config_.mode);
        std::println("Starting secure transport...");
        std::println("{}", std::string(60, '-'));
        std::println("Enter messages to send (or 'quit' to exit):\n");

        // Enter transport phase
        transport_loop(tx, rx);
    }

private:
    void connect(const std::string& host, std::uint16_t port) {
        print_separator("NOISE PROTOCOL MULTI-MODE CLIENT");
        std::println("Mode:     {} ({})", config_.mode, config_.description);
        std::println("Protocol: {}", protocol_.String());
        std::println("Prologue: {}", to_string(prologue_));
        std::println("\nConnecting to {}:{}...", host, port);

        tcp::resolver resolver(socket_.get_executor());
        auto endpoints = resolver.resolve(host, std::to_string(port));
        asio::connect(socket_, endpoints);

        std::println("Connected to server!");
    }

    std::pair<CipherState, CipherState> perform_handshake() {
        std::println("\nPerforming {} handshake (initiator)...", config_.mode);

        // Create handshake state with prologue for mode binding
        HandshakeConfig hs_config{
            .protocol = protocol_,
            .isInitiator = true,
            .prologue = prologue_,  // Mode binding - must match server
            .localStatic = client_static_
        };
        HandshakeState hs(hs_config);

        // XX/XXhfs: 3 messages        pqXX: 4 messages
        // -> e                         -> e
        // <- e, ee, s, es              <- ekem, s
        // -> s, se                     -> skem, s
        //                              <- skem

        // Message 1: Send to server
        std::println("  -> Sending handshake message 1...");
        auto msg1 = hs.WriteMessage({});
        send_framed(socket_, msg1);
        std::println("     Sent {} bytes", msg1.size());

        // Message 2: Receive from server
        std::println("  <- Receiving handshake message 2...");
        auto msg2 = recv_framed(socket_);
        auto payload2 = hs.ReadMessage(msg2);  // May throw if mode mismatch
        std::println("     Received {} bytes", msg2.size());

        // Message 3: Send to server
        std::println("  -> Sending handshake message 3...");
        auto msg3 = hs.WriteMessage({});
        send_framed(socket_, msg3);
        std::println("     Sent {} bytes", msg3.size());

        // Message 4: pqXX requires a 4th message (responder sends <- skem)
        if (config_.mode == "pqxx") {
            std::println("  <- Receiving handshake message 4...");
            auto msg4 = recv_framed(socket_);
            [[maybe_unused]] auto payload4 = hs.ReadMessage(msg4);
            std::println("     Received {} bytes", msg4.size());
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

        // Display server's identity
        std::println("\n  Server authenticated:");
        print_bytes_hex("  Remote static key", status.remoteStatic);
        print_bytes_hex("  Handshake hash", status.handshakeHash);

        // For initiator: first = Tx, second = Rx
        return {std::move(cs->first), std::move(cs->second)};
    }

    void transport_loop(CipherState& tx, CipherState& rx) {
        std::uint32_t message_count = 0;
        std::string input;

        while (true) {
            // Prompt for input
            std::print("> ");
            std::cout.flush();

            if (!std::getline(std::cin, input)) {
                std::println("\nInput closed.");
                break;
            }

            if (input.empty()) {
                continue;
            }

            message_count++;

            // Check for quit command
            bool is_quit = (input == "quit");

            // Encrypt and send message
            auto plaintext = to_bytes(input);
            auto ciphertext = tx.EncryptWithAd({}, plaintext);
            send_framed(socket_, ciphertext);

            std::println("  Client msg #{} [{}]: \"{}\"", message_count, config_.mode, input);

            if (is_quit) {
                std::println("\nDisconnecting...");
                break;
            }

            // Receive and decrypt response
            try {
                auto response_ciphertext = recv_framed(socket_);
                auto response_plaintext = rx.DecryptWithAd({}, response_ciphertext);
                std::string response = to_string(response_plaintext);

                std::println("  {}", response);
                std::println("");

            } catch (const asio::system_error& e) {
                if (e.code() == asio::error::eof) {
                    std::println("\nServer disconnected.");
                } else {
                    std::println("\nConnection error: {}", e.what());
                }
                break;
            }
        }

        std::println("Session ended. {} messages sent.", message_count);
    }

    tcp::socket socket_;
    ModeConfig config_;
    Protocol protocol_;
    std::vector<std::uint8_t> prologue_;
    KeyPair client_static_;
};

// ============================================================================
// Main
// ============================================================================

void print_usage(const char* program) {
    std::println("Usage: {} [mode] [host] [port]", program);
    std::println("");
    std::println("Modes:");
    std::println("  xx      - Classical XX pattern (X25519 DH) [default]");
    std::println("  pqxx    - Post-Quantum pqXX pattern (ML-KEM-768)");
    std::println("  xxhfs   - Hybrid XXhfs pattern (X25519 + ML-KEM-768)");
    std::println("");
    std::println("Host: localhost (default)");
    std::println("Port: {} (default)", DEFAULT_PORT);
    std::println("");
    std::println("Examples:");
    std::println("  {}                          # Classical mode, localhost:{}", program, DEFAULT_PORT);
    std::println("  {} pqxx                     # Post-quantum mode", program);
    std::println("  {} xxhfs 192.168.1.10 12346 # Hybrid mode, custom host:port", program);
    std::println("");
    std::println("Note: Client mode must match server mode, or handshake will fail.");
}

int main(int argc, char* argv[]) {
    try {
        std::string mode = "xx";  // Default to classical
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

        asio::io_context io_context;
        NoiseClientMulti client(io_context, config, host, port);
        client.run();

    } catch (const NoiseError& e) {
        std::println("Handshake failed: {}", e.what());
        std::println("Hint: Server may be running in a different mode.");
        std::println("      Make sure both client and server use the same mode (xx, pqxx, or xxhfs).");
        return 1;
    } catch (const std::exception& e) {
        std::println("Error: {}", e.what());
        return 1;
    }

    return 0;
}
