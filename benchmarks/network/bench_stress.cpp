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
// NoisePQC++ Network Stress Test
// Multi-client concurrent handshake benchmarking
//

#include "bench_network_common.hpp"

import std;
import noise;

using namespace Noise;
using namespace NoiseBench::Network;

// ============================================================================
// Stress Test Configuration
// ============================================================================

struct StressConfig {
    std::string mode;
    std::string host;
    std::uint16_t port;
    std::size_t num_clients;
    std::size_t iterations_per_client;
    std::chrono::milliseconds ramp_up_delay{10};
};

// ============================================================================
// Stress Test Results
// ============================================================================

struct StressResults {
    BenchmarkStats stats;
    std::chrono::nanoseconds total_duration;
    double handshakes_per_second;
    std::size_t total_bytes_sent{0};
    std::size_t total_bytes_received{0};
};

// ============================================================================
// Client Worker Thread
// ============================================================================

void client_worker(
    const ModeConfig& config,
    const std::string& host,
    std::uint16_t port,
    std::size_t iterations,
    std::vector<HandshakeTiming>& results,
    std::mutex& results_mutex,
    std::atomic<std::size_t>& completed_count) {

    Protocol protocol(config.protocol_str);
    auto prologue = create_prologue(config.mode);
    KeyPair client_static;

    if (pattern_needs_static(config.mode)) {
        client_static = protocol.dh.GenerateKeypair();
    }

    for (std::size_t i = 0; i < iterations; ++i) {
        HandshakeTiming timing;
        timing.message_count = static_cast<std::uint32_t>(config.expected_messages);

        try {
            asio::io_context io_context;
            tcp::socket socket(io_context);

            // Connect
            auto connect_start = std::chrono::high_resolution_clock::now();
            tcp::resolver resolver(io_context);
            auto endpoints = resolver.resolve(host, std::to_string(port));
            asio::connect(socket, endpoints);
            timing.connect_time = std::chrono::high_resolution_clock::now() - connect_start;

            // Handshake
            auto handshake_start = std::chrono::high_resolution_clock::now();

            // For KK patterns, send our static key out-of-band first
            if (responder_needs_remote_static(config.mode)) {
                send_framed(socket, client_static.public_key);
                timing.bytes_sent += client_static.public_key.size() + 4;
            }

            HandshakeConfig hs_config{
                .protocol = protocol,
                .isInitiator = true,
                .prologue = prologue,
                .localStatic = client_static
            };

            HandshakeState hs(hs_config);

            while (!hs.GetStatus().IsComplete()) {
                auto msg = hs.WriteMessage({});
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

        } catch (const std::exception&) {
            timing.success = false;
        }

        {
            std::lock_guard<std::mutex> lock(results_mutex);
            results.push_back(timing);
        }

        completed_count++;
    }
}

// ============================================================================
// Run Stress Test
// ============================================================================

StressResults run_stress_test(const StressConfig& stress_config, bool quiet) {
    auto config = get_mode_config(stress_config.mode);

    std::vector<HandshakeTiming> all_results;
    std::mutex results_mutex;
    std::atomic<std::size_t> completed_count{0};
    std::vector<std::thread> threads;

    std::size_t total_handshakes = stress_config.num_clients * stress_config.iterations_per_client;

    if (!quiet) {
        std::println("Starting stress test...");
        std::println("  Mode:            {} ({})", config.mode, config.description);
        std::println("  Clients:         {}", stress_config.num_clients);
        std::println("  Per-client:      {}", stress_config.iterations_per_client);
        std::println("  Total:           {}", total_handshakes);
    }

    auto start_time = std::chrono::high_resolution_clock::now();

    // Launch client threads
    for (std::size_t i = 0; i < stress_config.num_clients; ++i) {
        threads.emplace_back(
            client_worker,
            std::ref(config),
            stress_config.host,
            stress_config.port,
            stress_config.iterations_per_client,
            std::ref(all_results),
            std::ref(results_mutex),
            std::ref(completed_count)
        );

        // Ramp-up delay between thread spawns
        if (stress_config.ramp_up_delay.count() > 0 && i + 1 < stress_config.num_clients) {
            std::this_thread::sleep_for(stress_config.ramp_up_delay);
        }
    }

    // Wait for all threads
    for (auto& t : threads) {
        t.join();
    }

    auto end_time = std::chrono::high_resolution_clock::now();

    // Calculate results
    StressResults results;
    results.total_duration = end_time - start_time;
    results.stats = calculate_stats(all_results);

    // Calculate throughput
    double duration_sec = static_cast<double>(results.total_duration.count()) / 1e9;
    results.handshakes_per_second = static_cast<double>(results.stats.count) / duration_sec;

    // Sum bytes
    for (const auto& t : all_results) {
        results.total_bytes_sent += t.bytes_sent;
        results.total_bytes_received += t.bytes_received;
    }

    return results;
}

// ============================================================================
// Main
// ============================================================================

void print_usage(const char* program) {
    std::println("Usage: {} [options]", program);
    std::println("\nOptions:");
    std::println("  --mode <mode>       Handshake mode (required)");
    std::println("                      Classical: nn, xx, ik, kk");
    std::println("                      PQ: pqnn, pqxx, pqik, pqkk");
    std::println("                      HFS: nnhfs, xxhfs, ikhfs, kkhfs");
    std::println("  --host <host>       Server host (default: localhost)");
    std::println("  --port <port>       Server port (default: {})", DEFAULT_PORT);
    std::println("  --clients <n>       Number of concurrent clients (default: 10)");
    std::println("  --iterations <n>    Iterations per client (default: 10)");
    std::println("  --ramp-up <ms>      Delay between thread spawns (default: 10)");
    std::println("  --output <file>     CSV output file");
    std::println("  --quiet             Suppress progress output");
    std::println("  --help              Show this help");
}

int main(int argc, char* argv[]) {
    StressConfig stress_config;
    stress_config.host = "localhost";
    stress_config.port = DEFAULT_PORT;
    stress_config.num_clients = 10;
    stress_config.iterations_per_client = 10;
    stress_config.ramp_up_delay = std::chrono::milliseconds{10};

    std::string output_file;
    bool quiet = false;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "--mode" && i + 1 < argc) {
            stress_config.mode = argv[++i];
        } else if (arg == "--host" && i + 1 < argc) {
            stress_config.host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            stress_config.port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--clients" && i + 1 < argc) {
            stress_config.num_clients = static_cast<std::size_t>(std::stoi(argv[++i]));
        } else if (arg == "--iterations" && i + 1 < argc) {
            stress_config.iterations_per_client = static_cast<std::size_t>(std::stoi(argv[++i]));
        } else if (arg == "--ramp-up" && i + 1 < argc) {
            stress_config.ramp_up_delay = std::chrono::milliseconds(std::stoi(argv[++i]));
        } else if (arg == "--output" && i + 1 < argc) {
            output_file = argv[++i];
        } else if (arg == "--quiet") {
            quiet = true;
        } else if (arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (stress_config.mode.empty()) {
        std::println(stderr, "Error: --mode is required");
        print_usage(argv[0]);
        return 1;
    }

    try {
        auto results = run_stress_test(stress_config, quiet);

        if (!quiet) {
            std::println("\nStress Test Results:");
            std::println("  Duration:         {:.2f} sec",
                static_cast<double>(results.total_duration.count()) / 1e9);
            std::println("  Success:          {}/{} ({:.1f}%)",
                results.stats.count,
                stress_config.num_clients * stress_config.iterations_per_client,
                100.0 * static_cast<double>(results.stats.count) /
                static_cast<double>(stress_config.num_clients * stress_config.iterations_per_client));
            std::println("  Throughput:       {:.2f} handshakes/sec", results.handshakes_per_second);
            std::println("  Mean RTT:         {:.2f} us", results.stats.mean_ns / 1000.0);
            std::println("  Std Dev:          {:.2f} us", results.stats.std_dev_ns / 1000.0);
            std::println("  P95 RTT:          {:.2f} us", results.stats.p95_ns / 1000.0);
            std::println("  P99 RTT:          {:.2f} us", results.stats.p99_ns / 1000.0);
            std::println("  Total Bytes Sent: {} KB", results.total_bytes_sent / 1024);
            std::println("  Total Bytes Recv: {} KB", results.total_bytes_received / 1024);
        }

        // Output CSV summary line
        if (!output_file.empty()) {
            std::ofstream out(output_file, std::ios::app);
            // mode,clients,iterations,duration_sec,success,errors,throughput,mean_us,p95_us,p99_us
            out << stress_config.mode << ","
                << stress_config.num_clients << ","
                << stress_config.iterations_per_client << ","
                << static_cast<double>(results.total_duration.count()) / 1e9 << ","
                << results.stats.count << ","
                << results.stats.errors << ","
                << results.handshakes_per_second << ","
                << results.stats.mean_ns / 1000.0 << ","
                << results.stats.p95_ns / 1000.0 << ","
                << results.stats.p99_ns / 1000.0 << "\n";

            if (!quiet) {
                std::println("\nResults appended to: {}", output_file);
            }
        }

    } catch (const std::exception& e) {
        std::println(stderr, "Error: {}", e.what());
        return 1;
    }

    return 0;
}
