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
// Common Benchmark Utilities for NoisePQC++
//

#ifndef NOISEPQC_BENCH_COMMON_HPP
#define NOISEPQC_BENCH_COMMON_HPP

#include <benchmark/benchmark.h>

import std;
import noise;

namespace NoiseBench {

using namespace Noise;

// ============================================================================
// Pattern Information
// ============================================================================

struct PatternInfo {
    std::string_view name;
    std::size_t messageCount;
    bool initiatorNeedsStatic;
    bool responderNeedsStatic;
    bool initiatorNeedsRemoteStatic;
    bool responderNeedsRemoteStatic;
};

// Classical DH pattern configurations
inline constexpr std::array<PatternInfo, 4> CLASSICAL_PATTERNS = {{
    {"NN", 2, false, false, false, false},
    {"XX", 3, true, true, false, false},
    {"IK", 2, true, true, true, false},
    {"KK", 2, true, true, true, true},
}};

// Post-Quantum KEM pattern configurations
inline constexpr std::array<PatternInfo, 4> PQ_PATTERNS = {{
    {"pqNN", 2, false, false, false, false},
    {"pqXX", 4, true, true, false, false},
    {"pqIK", 2, true, true, true, false},
    {"pqKK", 2, true, true, true, true},
}};

// HFS pattern configurations (same as classical but with HFS suffix)
inline constexpr std::array<PatternInfo, 4> HFS_PATTERNS = {{
    {"NNhfs", 2, false, false, false, false},
    {"XXhfs", 3, true, true, false, false},
    {"IKhfs", 2, true, true, true, false},
    {"KKhfs", 2, true, true, true, true},
}};

// ============================================================================
// Handshake Execution
// ============================================================================

// Execute a complete handshake between initiator and responder
// Returns total bytes exchanged during the handshake
inline std::size_t execute_handshake(
    HandshakeState& initiator,
    HandshakeState& responder) {

    std::size_t totalBytes = 0;

    // Alternating message exchange until both complete
    bool initiatorTurn = true;

    while (!initiator.GetStatus().IsComplete() || !responder.GetStatus().IsComplete()) {
        if (initiatorTurn && !initiator.GetStatus().IsComplete()) {
            // Initiator sends
            auto msg = initiator.WriteMessage({});
            totalBytes += msg.size();

            // Responder receives
            responder.ReadMessage(msg);
            initiatorTurn = false;
        } else if (!initiatorTurn && !responder.GetStatus().IsComplete()) {
            // Responder sends
            auto msg = responder.WriteMessage({});
            totalBytes += msg.size();

            // Initiator receives
            initiator.ReadMessage(msg);
            initiatorTurn = true;
        } else {
            // Switch turn if current party is done
            initiatorTurn = !initiatorTurn;
        }
    }

    return totalBytes;
}

// ============================================================================
// Protocol String Builders
// ============================================================================

// Build classical DH protocol string
inline std::string build_classical_protocol(
    std::string_view pattern,
    std::string_view dh_algo,
    std::string_view cipher = "ChaChaPoly",
    std::string_view hash = "BLAKE2s") {
    return std::format("Noise_{}_{}_{}_{}", pattern, dh_algo, cipher, hash);
}

// Build PQ KEM protocol string
inline std::string build_pq_protocol(
    std::string_view pattern,
    std::string_view kem_algo,
    std::string_view cipher = "ChaChaPoly",
    std::string_view hash = "BLAKE2s") {
    return std::format("Noise_{}_{}_{}_{}", pattern, kem_algo, cipher, hash);
}

// Build HFS hybrid protocol string
inline std::string build_hfs_protocol(
    std::string_view pattern,
    std::string_view dh_algo,
    std::string_view kem_algo,
    std::string_view cipher = "ChaChaPoly",
    std::string_view hash = "BLAKE2s") {
    return std::format("Noise_{}_{}+{}_{}_{}", pattern, dh_algo, kem_algo, cipher, hash);
}

// ============================================================================
// Benchmark Helpers
// ============================================================================

// Get algorithm name for display
inline std::string_view get_dh_name(int index) {
    static constexpr std::array<std::string_view, 2> names = {"25519", "448"};
    return names[static_cast<std::size_t>(index)];
}

inline std::string_view get_kem_name(int index) {
    static constexpr std::array<std::string_view, 3> names = {"M512", "M768", "M1024"};
    return names[static_cast<std::size_t>(index)];
}

// ============================================================================
// Benchmark Result Tracking
// ============================================================================

// Add custom counters for benchmark results
// totalBytes should be the accumulated total across all iterations
inline void add_handshake_counters(
    benchmark::State& state,
    std::size_t messageCount,
    std::size_t totalBytes) {

    // Messages per handshake (constant)
    state.counters["messages"] = static_cast<double>(messageCount);

    // Bytes per handshake (totalBytes accumulated, divide by iterations)
    state.counters["bytes_per_hs"] = benchmark::Counter(
        static_cast<double>(totalBytes),
        benchmark::Counter::kAvgIterations);
}

} // namespace NoiseBench

#endif // NOISEPQC_BENCH_COMMON_HPP
