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
// Basic Benchmarks (SHA-256 hashing, X25519 key generation and DH) using Google Benchmark
//

#include <benchmark/benchmark.h>

import std;
import noise;

using namespace Noise;

// Benchmark: SHA256 hashing (one-shot)
static void BM_SHA256_Hash(benchmark::State& state) {
    std::vector<std::uint8_t> data(static_cast<std::size_t>(state.range(0)), 0x42);
    Hash hash(HashAlgo::SHA256);

    for (auto _ : state) {
        auto digest = hash.hash_function->process(data);
        benchmark::DoNotOptimize(digest);
    }
    state.SetBytesProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_SHA256_Hash)->Range(64, 8192);

// Benchmark: X25519 key generation
static void BM_X25519_KeyGen(benchmark::State& state) {
    Dh dh(KeyAlgo::X25519);

    for (auto _ : state) {
        auto keypair = dh.GenerateKeypair();
        benchmark::DoNotOptimize(keypair);
    }
}
BENCHMARK(BM_X25519_KeyGen);

// Benchmark: X25519 DH operation
static void BM_X25519_DH(benchmark::State& state) {
    Dh dh(KeyAlgo::X25519);
    auto alice = dh.GenerateKeypair();
    auto bob = dh.GenerateKeypair();

    for (auto _ : state) {
        auto shared = dh.DH(alice, bob);
        benchmark::DoNotOptimize(shared);
    }
}
BENCHMARK(BM_X25519_DH);

BENCHMARK_MAIN();
