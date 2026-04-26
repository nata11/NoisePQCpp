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
// Noise Protocol Server Example
// Demonstrates server-side XX handshake and encrypted transport using ASIO
//

#include "asio_common.hpp"
import std;
import noise;

using namespace Noise;
using namespace NoiseAsio;

class NoiseServer {
public:
    NoiseServer(asio::io_context& io_context, std::uint16_t port)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
        , protocol_(std::string(PROTOCOL_STRING))
    {
        // Generate server's static keypair (reused across all connections)
        Dh dh(protocol_.dh.String());
        server_static_ = dh.GenerateKeypair();

        std::println("Server static public key generated:");
        print_bytes_hex("Public key", server_static_.public_key);
    }

    void run() {
        print_separator("NOISE PROTOCOL SERVER");
        std::println("Protocol: {}", protocol_.String());
        std::println("Listening on port {}...", acceptor_.local_endpoint().port());
        std::println("Press Ctrl+C to stop\n");

        while (true) {
            try {
                handle_client();
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

        // Perform XX handshake as responder
        auto [rx, tx] = perform_handshake(socket);

        std::println("\nHandshake complete! Starting secure transport...");
        std::println("{}", std::string(60, '-'));

        // Enter transport phase
        transport_loop(socket, rx, tx);
    }

    std::pair<CipherState, CipherState> perform_handshake(tcp::socket& socket) {
        std::println("\nPerforming XX handshake (responder)...");

        // Create handshake state for this connection
        HandshakeConfig config{
            .protocol = protocol_,
            .isInitiator = false,  // Server is responder
            .localStatic = server_static_
        };
        HandshakeState hs(config);

        // XX Pattern:
        // -> e                    (recv msg1)
        // <- e, ee, s, es         (send msg2)
        // -> s, se                (recv msg3)

        // Message 1: Receive from client
        std::println("  <- Receiving handshake message 1...");
        auto msg1 = recv_framed(socket);
        auto payload1 = hs.ReadMessage(msg1);
        std::println("     Received {} bytes, payload: {} bytes", msg1.size(), payload1.size());

        // Message 2: Send to client
        std::println("  -> Sending handshake message 2...");
        auto msg2 = hs.WriteMessage({});  // Empty payload for handshake
        send_framed(socket, msg2);
        std::println("     Sent {} bytes", msg2.size());

        // Message 3: Receive from client
        std::println("  <- Receiving handshake message 3...");
        auto msg3 = recv_framed(socket);
        auto payload3 = hs.ReadMessage(msg3);
        std::println("     Received {} bytes, payload: {} bytes", msg3.size(), payload3.size());

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

        // For responder: first = Rx (receive), second = Tx (send)
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
                std::string response = std::format("Server echo #{}: {}", message_count, message);
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
    Protocol protocol_;
    KeyPair server_static_;
};

int main(int argc, char* argv[]) {
    try {
        std::uint16_t port = DEFAULT_PORT;

        // Parse optional port argument
        if (argc > 1) {
            port = static_cast<std::uint16_t>(std::stoi(argv[1]));
        }

        asio::io_context io_context;
        NoiseServer server(io_context, port);
        server.run();

    } catch (const std::exception& e) {
        std::println("Fatal error: {}", e.what());
        return 1;
    }

    return 0;
}
