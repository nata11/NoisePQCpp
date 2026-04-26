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
// NoisePQC++ Handshake Benchmarks
// Measures local handshake performance for Classical, PQ, and HFS patterns
//

#include "bench_common.hpp"

import std;
import noise;

using namespace Noise;
using namespace NoiseBench;

// ============================================================================
// Classical DH Handshake Benchmarks
// ============================================================================

// Benchmark classical handshake patterns with X25519 or X448
// Arguments: [0] = DH algorithm (0=X25519, 1=X448), [1] = pattern index
static void BM_Classical_Handshake(benchmark::State& state) {
    const int dhAlgoIndex = static_cast<int>(state.range(0));
    const int patternIndex = static_cast<int>(state.range(1));

    const auto dhAlgo = get_dh_name(dhAlgoIndex);
    const auto& patternInfo = CLASSICAL_PATTERNS[static_cast<std::size_t>(patternIndex)];

    // Build protocol string
    auto protocolStr = build_classical_protocol(patternInfo.name, dhAlgo);
    Protocol protocol(protocolStr);

    // Pre-generate keys outside timing loop
    auto aliceStatic = patternInfo.initiatorNeedsStatic
        ? protocol.dh.GenerateKeypair() : KeyPair{};
    auto bobStatic = patternInfo.responderNeedsStatic
        ? protocol.dh.GenerateKeypair() : KeyPair{};

    std::size_t totalBytes = 0;

    for (auto _ : state) {
        // Setup initiator
        HandshakeConfig aliceCfg{
            .protocol = protocol,
            .isInitiator = true,
            .localStatic = aliceStatic,
            .remoteStatic = patternInfo.initiatorNeedsRemoteStatic
                ? bobStatic.public_key : PublicKey{}
        };

        // Setup responder
        HandshakeConfig bobCfg{
            .protocol = protocol,
            .isInitiator = false,
            .localStatic = bobStatic,
            .remoteStatic = patternInfo.responderNeedsRemoteStatic
                ? aliceStatic.public_key : PublicKey{}
        };

        HandshakeState alice(aliceCfg);
        HandshakeState bob(bobCfg);

        totalBytes += execute_handshake(alice, bob);

        auto& aliceHash = alice.GetStatus().handshakeHash;
        auto& bobHash = bob.GetStatus().handshakeHash;
        benchmark::DoNotOptimize(aliceHash.data());
        benchmark::DoNotOptimize(bobHash.data());
        benchmark::ClobberMemory();
    }

    // Set metrics
    state.SetBytesProcessed(static_cast<std::int64_t>(totalBytes));
    add_handshake_counters(state, patternInfo.messageCount, totalBytes);
}

// Register Classical benchmarks: X25519
BENCHMARK(BM_Classical_Handshake)->Name("Classical/NN/X25519")->Args({0, 0})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_Classical_Handshake)->Name("Classical/XX/X25519")->Args({0, 1})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_Classical_Handshake)->Name("Classical/IK/X25519")->Args({0, 2})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_Classical_Handshake)->Name("Classical/KK/X25519")->Args({0, 3})->Unit(benchmark::kMicrosecond);

// Register Classical benchmarks: X448
BENCHMARK(BM_Classical_Handshake)->Name("Classical/NN/X448")->Args({1, 0})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_Classical_Handshake)->Name("Classical/XX/X448")->Args({1, 1})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_Classical_Handshake)->Name("Classical/IK/X448")->Args({1, 2})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_Classical_Handshake)->Name("Classical/KK/X448")->Args({1, 3})->Unit(benchmark::kMicrosecond);

// ============================================================================
// Post-Quantum KEM Handshake Benchmarks
// ============================================================================

// Benchmark PQ handshake patterns with ML-KEM (M512, M768, M1024)
// Arguments: [0] = KEM level (0=M512, 1=M768, 2=M1024), [1] = pattern index
static void BM_PQ_Handshake(benchmark::State& state) {
    const int kemLevelIndex = static_cast<int>(state.range(0));
    const int patternIndex = static_cast<int>(state.range(1));

    const auto kemAlgo = get_kem_name(kemLevelIndex);
    const auto& patternInfo = PQ_PATTERNS[static_cast<std::size_t>(patternIndex)];

    // Build protocol string
    auto protocolStr = build_pq_protocol(patternInfo.name, kemAlgo);
    Protocol protocol(protocolStr);

    // Pre-generate keys outside timing loop
    auto aliceStatic = patternInfo.initiatorNeedsStatic
        ? protocol.dh.GenerateKeypair() : KeyPair{};
    auto bobStatic = patternInfo.responderNeedsStatic
        ? protocol.dh.GenerateKeypair() : KeyPair{};

    std::size_t totalBytes = 0;

    for (auto _ : state) {
        // Setup initiator
        HandshakeConfig aliceCfg{
            .protocol = protocol,
            .isInitiator = true,
            .localStatic = aliceStatic,
            .remoteStatic = patternInfo.initiatorNeedsRemoteStatic
                ? bobStatic.public_key : PublicKey{}
        };

        // Setup responder
        HandshakeConfig bobCfg{
            .protocol = protocol,
            .isInitiator = false,
            .localStatic = bobStatic,
            .remoteStatic = patternInfo.responderNeedsRemoteStatic
                ? aliceStatic.public_key : PublicKey{}
        };

        HandshakeState alice(aliceCfg);
        HandshakeState bob(bobCfg);

        totalBytes += execute_handshake(alice, bob);

        auto& aliceHash = alice.GetStatus().handshakeHash;
        auto& bobHash = bob.GetStatus().handshakeHash;
        benchmark::DoNotOptimize(aliceHash.data());
        benchmark::DoNotOptimize(bobHash.data());
        benchmark::ClobberMemory();
    }

    // Set metrics
    state.SetBytesProcessed(static_cast<std::int64_t>(totalBytes));
    add_handshake_counters(state, patternInfo.messageCount, totalBytes);
}

// Register PQ benchmarks: ML-KEM-512
BENCHMARK(BM_PQ_Handshake)->Name("PQ/pqNN/M512")->Args({0, 0})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_PQ_Handshake)->Name("PQ/pqXX/M512")->Args({0, 1})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_PQ_Handshake)->Name("PQ/pqIK/M512")->Args({0, 2})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_PQ_Handshake)->Name("PQ/pqKK/M512")->Args({0, 3})->Unit(benchmark::kMicrosecond);

// Register PQ benchmarks: ML-KEM-768
BENCHMARK(BM_PQ_Handshake)->Name("PQ/pqNN/M768")->Args({1, 0})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_PQ_Handshake)->Name("PQ/pqXX/M768")->Args({1, 1})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_PQ_Handshake)->Name("PQ/pqIK/M768")->Args({1, 2})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_PQ_Handshake)->Name("PQ/pqKK/M768")->Args({1, 3})->Unit(benchmark::kMicrosecond);

// Register PQ benchmarks: ML-KEM-1024
BENCHMARK(BM_PQ_Handshake)->Name("PQ/pqNN/M1024")->Args({2, 0})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_PQ_Handshake)->Name("PQ/pqXX/M1024")->Args({2, 1})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_PQ_Handshake)->Name("PQ/pqIK/M1024")->Args({2, 2})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_PQ_Handshake)->Name("PQ/pqKK/M1024")->Args({2, 3})->Unit(benchmark::kMicrosecond);

// ============================================================================
// Hybrid Forward Secrecy (HFS) Handshake Benchmarks
// ============================================================================

// Benchmark HFS patterns combining classical DH with ML-KEM
// Arguments: [0] = DH algorithm (0=X25519, 1=X448), [1] = KEM level (0=M512, 1=M768, 2=M1024), [2] = pattern index
static void BM_HFS_Handshake(benchmark::State& state) {
    const int dhAlgoIndex = static_cast<int>(state.range(0));
    const int kemLevelIndex = static_cast<int>(state.range(1));
    const int patternIndex = static_cast<int>(state.range(2));

    const auto dhAlgo = get_dh_name(dhAlgoIndex);
    const auto kemAlgo = get_kem_name(kemLevelIndex);
    const auto& patternInfo = HFS_PATTERNS[static_cast<std::size_t>(patternIndex)];

    // Build HFS protocol string
    auto protocolStr = build_hfs_protocol(patternInfo.name, dhAlgo, kemAlgo);
    Protocol protocol(protocolStr);

    // Pre-generate keys outside timing loop (use DH for static keys in HFS)
    Dh dh(dhAlgo);
    auto aliceStatic = patternInfo.initiatorNeedsStatic
        ? dh.GenerateKeypair() : KeyPair{};
    auto bobStatic = patternInfo.responderNeedsStatic
        ? dh.GenerateKeypair() : KeyPair{};

    std::size_t totalBytes = 0;

    for (auto _ : state) {
        // Setup initiator
        HandshakeConfig aliceCfg{
            .protocol = protocol,
            .isInitiator = true,
            .localStatic = aliceStatic,
            .remoteStatic = patternInfo.initiatorNeedsRemoteStatic
                ? bobStatic.public_key : PublicKey{}
        };

        // Setup responder
        HandshakeConfig bobCfg{
            .protocol = protocol,
            .isInitiator = false,
            .localStatic = bobStatic,
            .remoteStatic = patternInfo.responderNeedsRemoteStatic
                ? aliceStatic.public_key : PublicKey{}
        };

        HandshakeState alice(aliceCfg);
        HandshakeState bob(bobCfg);

        totalBytes += execute_handshake(alice, bob);

        auto& aliceHash = alice.GetStatus().handshakeHash;
        auto& bobHash = bob.GetStatus().handshakeHash;
        benchmark::DoNotOptimize(aliceHash.data());
        benchmark::DoNotOptimize(bobHash.data());
        benchmark::ClobberMemory();
    }

    // Set metrics
    state.SetBytesProcessed(static_cast<std::int64_t>(totalBytes));
    add_handshake_counters(state, patternInfo.messageCount, totalBytes);
}

// Register HFS benchmarks: X25519 + M768 (recommended combination)
BENCHMARK(BM_HFS_Handshake)->Name("HFS/NNhfs/X25519+M768")->Args({0, 1, 0})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_HFS_Handshake)->Name("HFS/XXhfs/X25519+M768")->Args({0, 1, 1})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_HFS_Handshake)->Name("HFS/IKhfs/X25519+M768")->Args({0, 1, 2})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_HFS_Handshake)->Name("HFS/KKhfs/X25519+M768")->Args({0, 1, 3})->Unit(benchmark::kMicrosecond);

// Register HFS benchmarks: X448 + M1024 (high security combination)
BENCHMARK(BM_HFS_Handshake)->Name("HFS/NNhfs/X448+M1024")->Args({1, 2, 0})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_HFS_Handshake)->Name("HFS/XXhfs/X448+M1024")->Args({1, 2, 1})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_HFS_Handshake)->Name("HFS/IKhfs/X448+M1024")->Args({1, 2, 2})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_HFS_Handshake)->Name("HFS/KKhfs/X448+M1024")->Args({1, 2, 3})->Unit(benchmark::kMicrosecond);

// Additional HFS combinations for comprehensive analysis
// X25519 + M512 (fast hybrid)
BENCHMARK(BM_HFS_Handshake)->Name("HFS/NNhfs/X25519+M512")->Args({0, 0, 0})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_HFS_Handshake)->Name("HFS/XXhfs/X25519+M512")->Args({0, 0, 1})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_HFS_Handshake)->Name("HFS/IKhfs/X25519+M512")->Args({0, 0, 2})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_HFS_Handshake)->Name("HFS/KKhfs/X25519+M512")->Args({0, 0, 3})->Unit(benchmark::kMicrosecond);

// X25519 + M1024 (mixed security level)
BENCHMARK(BM_HFS_Handshake)->Name("HFS/NNhfs/X25519+M1024")->Args({0, 2, 0})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_HFS_Handshake)->Name("HFS/XXhfs/X25519+M1024")->Args({0, 2, 1})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_HFS_Handshake)->Name("HFS/IKhfs/X25519+M1024")->Args({0, 2, 2})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_HFS_Handshake)->Name("HFS/KKhfs/X25519+M1024")->Args({0, 2, 3})->Unit(benchmark::kMicrosecond);

// ============================================================================
// Key Generation Benchmarks (for reference)
// ============================================================================

static void BM_KeyGen_X25519(benchmark::State& state) {
    Dh dh("25519");
    for (auto _ : state) {
        auto kp = dh.GenerateKeypair();
        benchmark::DoNotOptimize(kp);
    }
}
BENCHMARK(BM_KeyGen_X25519)->Name("KeyGen/X25519")->Unit(benchmark::kNanosecond);

static void BM_KeyGen_X448(benchmark::State& state) {
    Dh dh("448");
    for (auto _ : state) {
        auto kp = dh.GenerateKeypair();
        benchmark::DoNotOptimize(kp);
    }
}
BENCHMARK(BM_KeyGen_X448)->Name("KeyGen/X448")->Unit(benchmark::kNanosecond);

static void BM_KeyGen_M512(benchmark::State& state) {
    Dh dh("M512");
    for (auto _ : state) {
        auto kp = dh.GenerateKeypair();
        benchmark::DoNotOptimize(kp);
    }
}
BENCHMARK(BM_KeyGen_M512)->Name("KeyGen/ML-KEM-512")->Unit(benchmark::kNanosecond);

static void BM_KeyGen_M768(benchmark::State& state) {
    Dh dh("M768");
    for (auto _ : state) {
        auto kp = dh.GenerateKeypair();
        benchmark::DoNotOptimize(kp);
    }
}
BENCHMARK(BM_KeyGen_M768)->Name("KeyGen/ML-KEM-768")->Unit(benchmark::kNanosecond);

static void BM_KeyGen_M1024(benchmark::State& state) {
    Dh dh("M1024");
    for (auto _ : state) {
        auto kp = dh.GenerateKeypair();
        benchmark::DoNotOptimize(kp);
    }
}
BENCHMARK(BM_KeyGen_M1024)->Name("KeyGen/ML-KEM-1024")->Unit(benchmark::kNanosecond);

BENCHMARK_MAIN();
