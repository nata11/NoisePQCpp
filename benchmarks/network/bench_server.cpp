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
// NoisePQC++ Network Benchmark Server
// Handles handshakes for benchmarking purposes
//

#include "bench_network_common.hpp"

import std;
import noise;

using namespace Noise;
using namespace NoiseBench::Network;

// ============================================================================
// Benchmark Server
// ============================================================================

class BenchServer {
public:
    BenchServer(asio::io_context& io_context,
                const ModeConfig& config,
                std::uint16_t port,
                std::optional<std::size_t> max_connections = std::nullopt,
                bool quiet = false)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
        , config_(config)
        , protocol_(config.protocol_str)
        , prologue_(create_prologue(config.mode))
        , max_connections_(max_connections)
        , quiet_(quiet) {

        // Generate server's static keypair
        if (pattern_needs_static(config.mode)) {
            server_static_ = protocol_.dh.GenerateKeypair();
        }

        if (!quiet_) {
            std::println("Benchmark Server Started");
            std::println("  Mode:     {} ({})", config_.mode, config_.description);
            std::println("  Protocol: {}", protocol_.String());
            std::println("  Port:     {}", port);
            if (max_connections_) {
                std::println("  Max Connections: {}", *max_connections_);
            }
        }
    }

    void run() {
        std::size_t connection_count = 0;

        while (!max_connections_ || connection_count < *max_connections_) {
            try {
                handle_client();
                connection_count++;
            } catch (const std::exception& e) {
                if (!quiet_) {
                    std::println("Session error: {}", e.what());
                }
            }
        }

        if (!quiet_) {
            std::println("Server finished after {} connections", connection_count);
        }
    }

    // Get the server's static public key (for pre-shared key scenarios)
    const PublicKey& get_static_public_key() const {
        return server_static_.public_key;
    }

private:
    void handle_client() {
        tcp::socket socket(acceptor_.get_executor());
        acceptor_.accept(socket);

        if (!quiet_) {
            auto remote = socket.remote_endpoint();
            std::println("Client connected from {}:{}", remote.address().to_string(), remote.port());
        }

        perform_handshake(socket);
    }

    void perform_handshake(tcp::socket& socket) {
        // Create handshake state
        HandshakeConfig hs_config{
            .protocol = protocol_,
            .isInitiator = false,
            .prologue = prologue_,
            .localStatic = server_static_
        };

        // For KK patterns, we need the client's static key (sent out-of-band)
        // In benchmark scenarios, the client sends it as the first message
        if (responder_needs_remote_static(config_.mode)) {
            auto client_static_data = recv_framed(socket);
            hs_config.remoteStatic = PublicKey(client_static_data.begin(), client_static_data.end());
        }

        HandshakeState hs(hs_config);

        // Execute handshake messages
        while (!hs.GetStatus().IsComplete()) {
            if (!hs.IsInitiator()) {
                // Responder: read first, then write (except for first message)
                auto msg = recv_framed(socket);
                hs.ReadMessage(msg);

                if (!hs.GetStatus().IsComplete()) {
                    auto response = hs.WriteMessage({});
                    send_framed(socket, response);
                }
            }
        }

        if (!quiet_) {
            std::println("Handshake complete");
        }
    }

    tcp::acceptor acceptor_;
    ModeConfig config_;
    Protocol protocol_;
    std::vector<std::uint8_t> prologue_;
    KeyPair server_static_;
    std::optional<std::size_t> max_connections_;
    bool quiet_;
};

// ============================================================================
// Main
// ============================================================================

void print_usage(const char* program) {
    std::println("Usage: {} [options]", program);
    std::println("\nOptions:");
    std::println("  --mode <mode>     Handshake mode (required)");
    std::println("                    Classical: nn, xx, ik, kk");
    std::println("                    PQ: pqnn, pqxx, pqik, pqkk");
    std::println("                    HFS: nnhfs, xxhfs, ikhfs, kkhfs");
    std::println("  --port <port>     Server port (default: {})", DEFAULT_PORT);
    std::println("  --count <n>       Max connections before exit (default: unlimited)");
    std::println("  --quiet           Suppress output except errors");
    std::println("  --help            Show this help");
}

int main(int argc, char* argv[]) {
    std::string mode;
    std::uint16_t port = DEFAULT_PORT;
    std::optional<std::size_t> max_connections;
    bool quiet = false;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "--mode" && i + 1 < argc) {
            mode = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--count" && i + 1 < argc) {
            max_connections = static_cast<std::size_t>(std::stoi(argv[++i]));
        } else if (arg == "--quiet") {
            quiet = true;
        } else if (arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (mode.empty()) {
        std::println(stderr, "Error: --mode is required");
        print_usage(argv[0]);
        return 1;
    }

    try {
        auto config = get_mode_config(mode);
        asio::io_context io_context;
        BenchServer server(io_context, config, port, max_connections, quiet);
        server.run();
    } catch (const std::exception& e) {
        std::println(stderr, "Error: {}", e.what());
        return 1;
    }

    return 0;
}
