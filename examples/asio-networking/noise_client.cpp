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
// Noise Protocol Client Example
// Demonstrates client-side XX handshake and encrypted transport using ASIO
//

#include "asio_common.hpp"
import std;
import noise;

using namespace Noise;
using namespace NoiseAsio;

class NoiseClient {
public:
    NoiseClient(asio::io_context& io_context, const std::string& host, std::uint16_t port)
        : socket_(io_context)
        , protocol_(std::string(PROTOCOL_STRING))
    {
        // Generate client's static keypair
        Dh dh(protocol_.dh.String());
        client_static_ = dh.GenerateKeypair();

        std::println("Client static public key generated:");
        print_bytes_hex("Public key", client_static_.public_key);

        // Connect to server
        connect(host, port);
    }

    void run() {
        // Perform XX handshake as initiator
        auto [tx, rx] = perform_handshake();

        std::println("\nHandshake complete! Starting secure transport...");
        std::println("{}", std::string(60, '-'));
        std::println("Enter messages to send (or 'quit' to exit):\n");

        // Enter transport phase
        transport_loop(tx, rx);
    }

private:
    void connect(const std::string& host, std::uint16_t port) {
        print_separator("NOISE PROTOCOL CLIENT");
        std::println("Protocol: {}", protocol_.String());
        std::println("Connecting to {}:{}...", host, port);

        tcp::resolver resolver(socket_.get_executor());
        auto endpoints = resolver.resolve(host, std::to_string(port));
        asio::connect(socket_, endpoints);

        std::println("Connected to server!");
    }

    std::pair<CipherState, CipherState> perform_handshake() {
        std::println("\nPerforming XX handshake (initiator)...");

        // Create handshake state for this connection
        HandshakeConfig config{
            .protocol = protocol_,
            .isInitiator = true,  // Client is initiator
            .localStatic = client_static_
        };
        HandshakeState hs(config);

        // XX Pattern:
        // -> e                    (send msg1)
        // <- e, ee, s, es         (recv msg2)
        // -> s, se                (send msg3)

        // Message 1: Send to server
        std::println("  -> Sending handshake message 1...");
        auto msg1 = hs.WriteMessage({});  // Empty payload for handshake
        send_framed(socket_, msg1);
        std::println("     Sent {} bytes", msg1.size());

        // Message 2: Receive from server
        std::println("  <- Receiving handshake message 2...");
        auto msg2 = recv_framed(socket_);
        auto payload2 = hs.ReadMessage(msg2);
        std::println("     Received {} bytes, payload: {} bytes", msg2.size(), payload2.size());

        // Message 3: Send to server
        std::println("  -> Sending handshake message 3...");
        auto msg3 = hs.WriteMessage({});  // Empty payload for handshake
        send_framed(socket_, msg3);
        std::println("     Sent {} bytes", msg3.size());

        // Verify handshake completed
        auto status = hs.GetStatus();
        if (!status.IsComplete()) {
            throw std::runtime_error("Handshake did not complete");
        }

        if (!status.cipherStates.has_value()) {
            throw std::runtime_error("No cipher states available after handshake");
        }

        // Display server's identity
        std::println("\n  Server authenticated:");
        print_bytes_hex("  Remote static key", status.remoteStatic);
        print_bytes_hex("  Handshake hash", status.handshakeHash);

        // For initiator: first = Tx (send), second = Rx (receive)
        return {status.cipherStates->first, status.cipherStates->second};
    }

    void transport_loop(CipherState& tx, CipherState& rx) {
        std::uint32_t message_count = 0;
        std::string input;

        while (true) {
            // Prompt for input
            std::print("> ");
            std::cout.flush();

            if (!std::getline(std::cin, input)) {
                // EOF or error
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

            std::println("  Client msg #{}: \"{}\"", message_count, input);

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
    Protocol protocol_;
    KeyPair client_static_;
};

void print_usage(const char* program) {
    std::println("Usage: {} [host] [port]", program);
    std::println("  host  - Server hostname (default: localhost)");
    std::println("  port  - Server port (default: {})", DEFAULT_PORT);
}

int main(int argc, char* argv[]) {
    try {
        std::string host = "localhost";
        std::uint16_t port = DEFAULT_PORT;

        // Parse optional arguments
        if (argc > 1) {
            if (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help") {
                print_usage(argv[0]);
                return 0;
            }
            host = argv[1];
        }
        if (argc > 2) {
            port = static_cast<std::uint16_t>(std::stoi(argv[2]));
        }

        asio::io_context io_context;
        NoiseClient client(io_context, host, port);
        client.run();

    } catch (const std::exception& e) {
        std::println("Error: {}", e.what());
        return 1;
    }

    return 0;
}
