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
// Common Network Benchmark Utilities for NoisePQC++
//

#ifndef NOISEPQC_BENCH_NETWORK_COMMON_HPP
#define NOISEPQC_BENCH_NETWORK_COMMON_HPP

#include <asio.hpp>
import std;
import noise;

namespace NoiseBench::Network {

using asio::ip::tcp;
using namespace Noise;

// ============================================================================
// Constants
// ============================================================================

constexpr std::uint16_t DEFAULT_PORT = 12346;
constexpr std::size_t MAX_MESSAGE_SIZE = 65535;

// ============================================================================
// Mode Configuration
// ============================================================================

struct ModeConfig {
    std::string mode;           // "xx", "pqxx", "xxhfs" etc.
    std::string protocol_str;   // Full protocol string
    std::string description;    // Human-readable description
    std::size_t expected_messages; // Number of handshake messages
};

inline ModeConfig get_mode_config(std::string_view mode) {
    // Classical patterns
    if (mode == "nn") {
        return {"nn", "Noise_NN_25519_ChaChaPoly_BLAKE2s",
                "Classical NN (X25519)", 2};
    }
    if (mode == "xx") {
        return {"xx", "Noise_XX_25519_ChaChaPoly_BLAKE2s",
                "Classical XX (X25519)", 3};
    }
    if (mode == "ik") {
        return {"ik", "Noise_IK_25519_ChaChaPoly_BLAKE2s",
                "Classical IK (X25519)", 2};
    }
    if (mode == "kk") {
        return {"kk", "Noise_KK_25519_ChaChaPoly_BLAKE2s",
                "Classical KK (X25519)", 2};
    }

    // Post-Quantum patterns
    if (mode == "pqnn") {
        return {"pqnn", "Noise_pqNN_M768_ChaChaPoly_BLAKE2s",
                "Post-Quantum pqNN (ML-KEM-768)", 2};
    }
    if (mode == "pqxx") {
        return {"pqxx", "Noise_pqXX_M768_ChaChaPoly_BLAKE2s",
                "Post-Quantum pqXX (ML-KEM-768)", 4};
    }
    if (mode == "pqik") {
        return {"pqik", "Noise_pqIK_M768_ChaChaPoly_BLAKE2s",
                "Post-Quantum pqIK (ML-KEM-768)", 2};
    }
    if (mode == "pqkk") {
        return {"pqkk", "Noise_pqKK_M768_ChaChaPoly_BLAKE2s",
                "Post-Quantum pqKK (ML-KEM-768)", 2};
    }

    // HFS (Hybrid Forward Secrecy) patterns
    if (mode == "nnhfs") {
        return {"nnhfs", "Noise_NNhfs_25519+M768_ChaChaPoly_BLAKE2s",
                "Hybrid NNhfs (X25519+ML-KEM-768)", 2};
    }
    if (mode == "xxhfs") {
        return {"xxhfs", "Noise_XXhfs_25519+M768_ChaChaPoly_BLAKE2s",
                "Hybrid XXhfs (X25519+ML-KEM-768)", 3};
    }
    if (mode == "ikhfs") {
        return {"ikhfs", "Noise_IKhfs_25519+M768_ChaChaPoly_BLAKE2s",
                "Hybrid IKhfs (X25519+ML-KEM-768)", 2};
    }
    if (mode == "kkhfs") {
        return {"kkhfs", "Noise_KKhfs_25519+M768_ChaChaPoly_BLAKE2s",
                "Hybrid KKhfs (X25519+ML-KEM-768)", 2};
    }

    throw std::invalid_argument(std::format("Unknown mode: '{}'", mode));
}

// Check if pattern requires static keys
inline bool pattern_needs_static(std::string_view mode) {
    return mode != "nn" && mode != "pqnn" && mode != "nnhfs";
}

// Check if initiator needs remote static (IK, KK patterns)
inline bool initiator_needs_remote_static(std::string_view mode) {
    return mode == "ik" || mode == "kk" ||
           mode == "pqik" || mode == "pqkk" ||
           mode == "ikhfs" || mode == "kkhfs";
}

// Check if responder needs remote static (KK patterns only)
inline bool responder_needs_remote_static(std::string_view mode) {
    return mode == "kk" || mode == "pqkk" || mode == "kkhfs";
}

// ============================================================================
// Timing Metrics
// ============================================================================

struct HandshakeTiming {
    std::chrono::nanoseconds total_rtt{0};
    std::chrono::nanoseconds connect_time{0};
    std::size_t bytes_sent{0};
    std::size_t bytes_received{0};
    std::uint32_t message_count{0};
    bool success{false};
};

// ============================================================================
// Message Framing (same format as examples/asio-networking/asio_common.hpp)
// ============================================================================

inline void send_framed(tcp::socket& socket, std::span<const std::uint8_t> data) {
    if (data.size() > MAX_MESSAGE_SIZE) {
        throw NoiseError("Message exceeds maximum size");
    }

    std::uint32_t length = static_cast<std::uint32_t>(data.size());
    std::array<std::uint8_t, 4> header{
        static_cast<std::uint8_t>((length >> 24) & 0xFF),
        static_cast<std::uint8_t>((length >> 16) & 0xFF),
        static_cast<std::uint8_t>((length >> 8) & 0xFF),
        static_cast<std::uint8_t>(length & 0xFF)
    };

    asio::write(socket, asio::buffer(header));
    if (!data.empty()) {
        asio::write(socket, asio::buffer(data.data(), data.size()));
    }
}

inline std::vector<std::uint8_t> recv_framed(tcp::socket& socket) {
    std::array<std::uint8_t, 4> header{};
    asio::read(socket, asio::buffer(header));

    std::uint32_t length =
        (static_cast<std::uint32_t>(header[0]) << 24) |
        (static_cast<std::uint32_t>(header[1]) << 16) |
        (static_cast<std::uint32_t>(header[2]) << 8) |
        static_cast<std::uint32_t>(header[3]);

    if (length > MAX_MESSAGE_SIZE) {
        throw NoiseError("Received message exceeds maximum size");
    }

    std::vector<std::uint8_t> data(length);
    if (length > 0) {
        asio::read(socket, asio::buffer(data));
    }
    return data;
}

// ============================================================================
// CSV Output
// ============================================================================

class CSVWriter {
public:
    explicit CSVWriter(const std::string& filename)
        : m_file(filename) {
        if (!m_file.is_open()) {
            throw std::runtime_error(std::format("Failed to open file: {}", filename));
        }
        // Write header
        m_file << "mode,pattern,latency_ms,rtt_ns,connect_ns,bytes_sent,bytes_received,messages,success\n";
    }

    void write_result(const ModeConfig& config,
                      std::chrono::milliseconds artificial_latency,
                      const HandshakeTiming& timing) {
        m_file << config.mode << ","
               << config.mode << ","  // pattern name same as mode
               << artificial_latency.count() << ","
               << timing.total_rtt.count() << ","
               << timing.connect_time.count() << ","
               << timing.bytes_sent << ","
               << timing.bytes_received << ","
               << timing.message_count << ","
               << (timing.success ? "true" : "false") << "\n";
        m_file.flush();
    }

    ~CSVWriter() {
        if (m_file.is_open()) {
            m_file.close();
        }
    }

private:
    std::ofstream m_file;
};

// ============================================================================
// Latency Injection
// ============================================================================

class LatencyInjector {
public:
    explicit LatencyInjector(std::chrono::milliseconds delay)
        : m_delay(delay) {}

    void inject() const {
        if (m_delay.count() > 0) {
            std::this_thread::sleep_for(m_delay);
        }
    }

    std::chrono::milliseconds get_delay() const { return m_delay; }

private:
    std::chrono::milliseconds m_delay;
};

// ============================================================================
// Prologue for Mode Binding
// ============================================================================

inline std::vector<std::uint8_t> create_prologue(std::string_view mode) {
    std::string prologue_str = std::format("NOISEPQC_BENCH:{}", mode);
    return std::vector<std::uint8_t>(prologue_str.begin(), prologue_str.end());
}

// ============================================================================
// Statistics Helpers
// ============================================================================

struct BenchmarkStats {
    double mean_ns{0};
    double std_dev_ns{0};
    double min_ns{0};
    double max_ns{0};
    double p50_ns{0};
    double p95_ns{0};
    double p99_ns{0};
    std::size_t count{0};
    std::size_t errors{0};
};

inline BenchmarkStats calculate_stats(std::vector<HandshakeTiming>& timings) {
    BenchmarkStats stats;

    // Filter successful timings
    std::vector<double> rtt_values;
    for (const auto& t : timings) {
        if (t.success) {
            rtt_values.push_back(static_cast<double>(t.total_rtt.count()));
        } else {
            stats.errors++;
        }
    }

    stats.count = rtt_values.size();
    if (stats.count == 0) return stats;

    // Sort for percentiles
    std::ranges::sort(rtt_values);

    // Calculate mean
    double sum = 0;
    for (double v : rtt_values) sum += v;
    stats.mean_ns = sum / static_cast<double>(stats.count);

    // Calculate std dev
    double sq_sum = 0;
    for (double v : rtt_values) {
        double diff = v - stats.mean_ns;
        sq_sum += diff * diff;
    }
    stats.std_dev_ns = std::sqrt(sq_sum / static_cast<double>(stats.count));

    // Min/max
    stats.min_ns = rtt_values.front();
    stats.max_ns = rtt_values.back();

    // Percentiles
    auto percentile = [&](double p) -> double {
        std::size_t idx = static_cast<std::size_t>(p * static_cast<double>(stats.count - 1));
        return rtt_values[idx];
    };

    stats.p50_ns = percentile(0.50);
    stats.p95_ns = percentile(0.95);
    stats.p99_ns = percentile(0.99);

    return stats;
}

} // namespace NoiseBench::Network

#endif // NOISEPQC_BENCH_NETWORK_COMMON_HPP
