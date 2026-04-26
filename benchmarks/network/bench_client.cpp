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
// NoisePQC++ Network Benchmark Client
// Performs timed handshakes with instrumentation
//

#include "bench_network_common.hpp"

import std;
import noise;

using namespace Noise;
using namespace NoiseBench::Network;

// ============================================================================
// Benchmark Client
// ============================================================================

class BenchClient {
public:
    BenchClient(const ModeConfig& config,
                const std::string& host,
                std::uint16_t port,
                std::chrono::milliseconds artificial_latency = std::chrono::milliseconds{0})
        : config_(config)
        , protocol_(config.protocol_str)
        , prologue_(create_prologue(config.mode))
        , host_(host)
        , port_(port)
        , latency_(artificial_latency) {

        // Generate client's static keypair if needed
        if (pattern_needs_static(config.mode)) {
            client_static_ = protocol_.dh.GenerateKeypair();
        }
    }

    // Set remote static public key (for IK, KK patterns)
    void set_remote_static(const PublicKey& remote_static) {
        remote_static_ = remote_static;
    }

    HandshakeTiming run_timed_handshake() {
        HandshakeTiming timing;
        timing.message_count = static_cast<std::uint32_t>(config_.expected_messages);

        try {
            asio::io_context io_context;
            tcp::socket socket(io_context);

            // Connect to server
            auto connect_start = std::chrono::high_resolution_clock::now();
            tcp::resolver resolver(io_context);
            auto endpoints = resolver.resolve(host_, std::to_string(port_));
            asio::connect(socket, endpoints);
            timing.connect_time = std::chrono::high_resolution_clock::now() - connect_start;

            // Start handshake timing
            auto handshake_start = std::chrono::high_resolution_clock::now();

            // For KK patterns, send our static key out-of-band first
            if (responder_needs_remote_static(config_.mode)) {
                send_framed(socket, client_static_.public_key);
                timing.bytes_sent += client_static_.public_key.size() + 4;
            }

            // Create handshake state
            HandshakeConfig hs_config{
                .protocol = protocol_,
                .isInitiator = true,
                .prologue = prologue_,
                .localStatic = client_static_
            };

            // Set remote static for IK/KK patterns
            if (initiator_needs_remote_static(config_.mode)) {
                hs_config.remoteStatic = remote_static_;
            }

            HandshakeState hs(hs_config);

            // Execute handshake messages
            while (!hs.GetStatus().IsComplete()) {
                // Initiator: write first, then read
                auto msg = hs.WriteMessage({});
                latency_.inject();
                send_framed(socket, msg);
                timing.bytes_sent += msg.size() + 4;

                if (!hs.GetStatus().IsComplete()) {
                    auto response = recv_framed(socket);
                    timing.bytes_received += response.size() + 4;
                    hs.ReadMessage(response);
                }
            }

            timing.total_rtt = std::chrono::high_resolution_clock::now() - handshake_start;
            timing.success = true;

        } catch (const std::exception& e) {
            timing.success = false;
        }

        return timing;
    }

    // Run multiple handshakes and collect timing data
    std::vector<HandshakeTiming> run_benchmark(std::size_t iterations) {
        std::vector<HandshakeTiming> results;
        results.reserve(iterations);

        for (std::size_t i = 0; i < iterations; ++i) {
            results.push_back(run_timed_handshake());
        }

        return results;
    }

    const PublicKey& get_static_public_key() const {
        return client_static_.public_key;
    }

private:
    ModeConfig config_;
    Protocol protocol_;
    std::vector<std::uint8_t> prologue_;
    std::string host_;
    std::uint16_t port_;
    LatencyInjector latency_;
    KeyPair client_static_;
    PublicKey remote_static_;
};

// ============================================================================
// Main
// ============================================================================

void print_usage(const char* program) {
    std::println("Usage: {} [options]", program);
    std::println("\nOptions:");
    std::println("  --mode <mode>      Handshake mode (required)");
    std::println("                     Classical: nn, xx, ik, kk");
    std::println("                     PQ: pqnn, pqxx, pqik, pqkk");
    std::println("                     HFS: nnhfs, xxhfs, ikhfs, kkhfs");
    std::println("  --host <host>      Server host (default: localhost)");
    std::println("  --port <port>      Server port (default: {})", DEFAULT_PORT);
    std::println("  --iterations <n>   Number of handshakes (default: 100)");
    std::println("  --latency <ms>     Artificial latency in milliseconds (default: 0)");
    std::println("  --output <file>    CSV output file (default: stdout)");
    std::println("  --quiet            Suppress progress output");
    std::println("  --help             Show this help");
}

int main(int argc, char* argv[]) {
    std::string mode;
    std::string host = "localhost";
    std::uint16_t port = DEFAULT_PORT;
    std::size_t iterations = 100;
    std::chrono::milliseconds latency{0};
    std::string output_file;
    bool quiet = false;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "--mode" && i + 1 < argc) {
            mode = argv[++i];
        } else if (arg == "--host" && i + 1 < argc) {
            host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--iterations" && i + 1 < argc) {
            iterations = static_cast<std::size_t>(std::stoi(argv[++i]));
        } else if (arg == "--latency" && i + 1 < argc) {
            latency = std::chrono::milliseconds(std::stoi(argv[++i]));
        } else if (arg == "--output" && i + 1 < argc) {
            output_file = argv[++i];
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

        if (!quiet) {
            std::println("Benchmark Client");
            std::println("  Mode:       {} ({})", config.mode, config.description);
            std::println("  Server:     {}:{}", host, port);
            std::println("  Iterations: {}", iterations);
            std::println("  Latency:    {} ms", latency.count());
        }

        BenchClient client(config, host, port, latency);

        // Run benchmark
        auto results = client.run_benchmark(iterations);

        // Calculate statistics
        auto stats = calculate_stats(results);

        if (!quiet) {
            std::println("\nResults:");
            std::println("  Success:    {}/{}", stats.count, iterations);
            std::println("  Mean RTT:   {:.2f} us", stats.mean_ns / 1000.0);
            std::println("  Std Dev:    {:.2f} us", stats.std_dev_ns / 1000.0);
            std::println("  Min RTT:    {:.2f} us", stats.min_ns / 1000.0);
            std::println("  Max RTT:    {:.2f} us", stats.max_ns / 1000.0);
            std::println("  P50 RTT:    {:.2f} us", stats.p50_ns / 1000.0);
            std::println("  P95 RTT:    {:.2f} us", stats.p95_ns / 1000.0);
            std::println("  P99 RTT:    {:.2f} us", stats.p99_ns / 1000.0);
        }

        // Write CSV output
        if (!output_file.empty()) {
            CSVWriter writer(output_file);
            for (const auto& timing : results) {
                writer.write_result(config, latency, timing);
            }
            if (!quiet) {
                std::println("\nResults written to: {}", output_file);
            }
        }

    } catch (const std::exception& e) {
        std::println(stderr, "Error: {}", e.what());
        return 1;
    }

    return 0;
}
