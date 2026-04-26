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
// Noise Protocol Multi-Mode Server Example
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
// Multi-Mode Server
// ============================================================================

class NoiseServerMulti {
public:
    NoiseServerMulti(asio::io_context& io_context, const ModeConfig& config, std::uint16_t port)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
        , config_(config)
        , protocol_(config.protocol_str)
        , prologue_(create_prologue(config.mode))
    {
        // Generate server's static keypair based on mode
        Dh dh(protocol_.dh.String());
        server_static_ = dh.GenerateKeypair();

        std::println("Server static public key generated:");
        print_bytes_hex("Public key", server_static_.public_key);
    }

    void run() {
        print_separator("NOISE PROTOCOL MULTI-MODE SERVER");
        std::println("Mode:     {} ({})", config_.mode, config_.description);
        std::println("Protocol: {}", protocol_.String());
        std::println("Port:     {}", acceptor_.local_endpoint().port());
        std::println("Prologue: {}", to_string(prologue_));
        std::println("\nPress Ctrl+C to stop\n");

        while (true) {
            try {
                handle_client();
            } catch (const NoiseError& e) {
                std::println("Handshake error: {}", e.what());
                std::println("Hint: Client may be using a different mode (server mode: '{}')", config_.mode);
                std::println("Waiting for next client...\n");
            } catch (const std::exception& e) {
                std::println("Session error: {}", e.what());
                std::println("Waiting for next client...\n");
            }
        }
    }

private:
    void handle_client() {
        std::println("{}", std::string(60, '-'));
        std::println("Waiting for client connection...");

        // Accept incoming connection
        tcp::socket socket(acceptor_.get_executor());
        acceptor_.accept(socket);

        auto remote = socket.remote_endpoint();
        std::println("Client connected from {}:{}", remote.address().to_string(), remote.port());

        // Perform handshake with prologue binding
        auto [rx, tx] = perform_handshake(socket);

        std::println("\nHandshake complete! Mode '{}' verified.", config_.mode);
        std::println("Starting secure transport...");
        std::println("{}", std::string(60, '-'));

        // Enter transport phase
        transport_loop(socket, rx, tx);
    }

    std::pair<CipherState, CipherState> perform_handshake(tcp::socket& socket) {
        std::println("\nPerforming {} handshake (responder)...", config_.mode);

        // Create handshake state with prologue for mode binding
        HandshakeConfig hs_config{
            .protocol = protocol_,
            .isInitiator = false,
            .prologue = prologue_,  // Mode binding - must match client
            .localStatic = server_static_
        };
        HandshakeState hs(hs_config);

        // XX/XXhfs: 3 messages        pqXX: 4 messages
        // -> e                         -> e
        // <- e, ee, s, es              <- ekem, s
        // -> s, se                     -> skem, s
        //                              <- skem

        // Message 1: Receive from client
        std::println("  <- Receiving handshake message 1...");
        auto msg1 = recv_framed(socket);
        auto payload1 = hs.ReadMessage(msg1);
        std::println("     Received {} bytes", msg1.size());

        // Message 2: Send to client
        std::println("  -> Sending handshake message 2...");
        auto msg2 = hs.WriteMessage({});
        send_framed(socket, msg2);
        std::println("     Sent {} bytes", msg2.size());

        // Message 3: Receive from client
        std::println("  <- Receiving handshake message 3...");
        auto msg3 = recv_framed(socket);
        [[maybe_unused]] auto payload3 = hs.ReadMessage(msg3);  // May throw if mode mismatch
        std::println("     Received {} bytes", msg3.size());

        // Message 4: pqXX requires a 4th message (responder sends <- skem)
        if (config_.mode == "pqxx") {
            std::println("  -> Sending handshake message 4...");
            auto msg4 = hs.WriteMessage({});
            send_framed(socket, msg4);
            std::println("     Sent {} bytes", msg4.size());
        }

        // Verify handshake completed
        auto status = hs.GetStatus();
        if (!status.IsComplete()) {
            throw std::runtime_error("Handshake did not complete");
        }

        if (!status.cipherStates.has_value()) {
            throw std::runtime_error("No cipher states available after handshake");
        }

        // Display client's identity
        std::println("\n  Client authenticated:");
        print_bytes_hex("  Remote static key", status.remoteStatic);
        print_bytes_hex("  Handshake hash", status.handshakeHash);

        // For responder: first = Rx, second = Tx
        return {status.cipherStates->first, status.cipherStates->second};
    }

    void transport_loop(tcp::socket& socket, CipherState& rx, CipherState& tx) {
        std::uint32_t message_count = 0;

        while (true) {
            try {
                // Receive encrypted message from client
                auto ciphertext = recv_framed(socket);
                auto plaintext = rx.DecryptWithAd({}, ciphertext);
                std::string message = to_string(plaintext);

                message_count++;

                // Check for quit command
                if (message == "quit") {
                    std::println("\nClient requested disconnect.");
                    std::println("Session ended. {} messages exchanged.\n", message_count - 1);
                    return;
                }

                std::println("  Received #{}: \"{}\"", message_count, message);

                // Create echo response
                std::string response = std::format("Server echo #{} [{}]: {}",
                    message_count, config_.mode, message);
                auto response_bytes = to_bytes(response);

                // Encrypt and send response
                auto response_ciphertext = tx.EncryptWithAd({}, response_bytes);
                send_framed(socket, response_ciphertext);

                std::println("  Sent:     \"{}\"", response);

            } catch (const asio::system_error& e) {
                if (e.code() == asio::error::eof) {
                    std::println("\nClient disconnected.");
                } else {
                    std::println("\nConnection error: {}", e.what());
                }
                std::println("Session ended. {} messages exchanged.\n", message_count);
                return;
            }
        }
    }

    tcp::acceptor acceptor_;
    ModeConfig config_;
    Protocol protocol_;
    std::vector<std::uint8_t> prologue_;
    KeyPair server_static_;
};

// ============================================================================
// Main
// ============================================================================

void print_usage(const char* program) {
    std::println("Usage: {} [mode] [port]", program);
    std::println("");
    std::println("Modes:");
    std::println("  xx      - Classical XX pattern (X25519 DH) [default]");
    std::println("  pqxx    - Post-Quantum pqXX pattern (ML-KEM-768)");
    std::println("  xxhfs   - Hybrid XXhfs pattern (X25519 + ML-KEM-768)");
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
        std::string mode = "xx";  // Default to classical
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

        asio::io_context io_context;
        NoiseServerMulti server(io_context, config, port);
        server.run();

    } catch (const std::exception& e) {
        std::println("Fatal error: {}", e.what());
        return 1;
    }

    return 0;
}
