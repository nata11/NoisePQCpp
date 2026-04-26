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
// ML-KEM Sandbox - Comprehensive ML-KEM integration demonstration
//

#include "botan_all.h"
#include <chrono>
import noise;
import std;

using namespace Noise;
using namespace std::chrono;

void print_separator(const std::string& title) {
    std::println("\n{:=^80}", "");
    std::println("{:^80}", title);
    std::println("{:=^80}\n", "");
}

void print_hex_truncated(const std::vector<std::uint8_t>& data, size_t max_bytes = 32) {
    const size_t bytes_to_show = std::min(data.size(), max_bytes);
    for (size_t i = 0; i < bytes_to_show; ++i) {
        std::print("{:02x}", data[i]);
    }
    if (data.size() > max_bytes) {
        std::print("... ({} more bytes)", data.size() - max_bytes);
    }
}

int main() {
    std::println("\n{:*^80}", " ML-KEM Sandbox ");
    std::println("{:^80}", "Demonstrating ML-KEM Integration");
    std::println("{:*^80}\n", "");

    // =======================================================================
    // Part 1: Key Generation for All 3 Levels
    // =======================================================================
    print_separator("Part 1: Key Generation for All 3 ML-KEM Levels");

    std::println("Generating keypairs for ML-KEM-512, ML-KEM-768, and ML-KEM-1024...\n");

    Dh dh512(M512);
    Dh dh768(M768);
    Dh dh1024(M1024);

    auto kp512 = dh512.GenerateKeypair();
    auto kp768 = dh768.GenerateKeypair();
    auto kp1024 = dh1024.GenerateKeypair();

    std::println("ML-KEM-512:");
    std::println("  Private Key Size: {:>5} bytes", kp512.private_key.size());
    std::println("  Public Key Size:  {:>5} bytes", kp512.public_key.size());
    std::print("  Public Key (hex):  ");
    print_hex_truncated(kp512.public_key);
    std::println("\n");

    std::println("ML-KEM-768:");
    std::println("  Private Key Size: {:>5} bytes", kp768.private_key.size());
    std::println("  Public Key Size:  {:>5} bytes", kp768.public_key.size());
    std::print("  Public Key (hex):  ");
    print_hex_truncated(kp768.public_key);
    std::println("\n");

    std::println("ML-KEM-1024:");
    std::println("  Private Key Size: {:>5} bytes", kp1024.private_key.size());
    std::println("  Public Key Size:  {:>5} bytes", kp1024.public_key.size());
    std::print("  Public Key (hex):  ");
    print_hex_truncated(kp1024.public_key);
    std::println("\n");

    // =======================================================================
    // Part 2: Size Comparison Display
    // =======================================================================
    print_separator("Part 2: Size Comparison Across Algorithms");

    Dh dh25519(X25519);
    Dh dh448(X448);

    auto kp25519 = dh25519.GenerateKeypair();
    auto kp448 = dh448.GenerateKeypair();

    std::println("{:<15} {:>12} {:>12} {:>15}",
                 "Algorithm", "Private Key", "Public Key", "Shared Secret");
    std::println("{:-^60}", "");
    std::println("{:<15} {:>12} {:>12} {:>15}",
                 "X25519", kp25519.private_key.size(), kp25519.public_key.size(), dh25519.Size());
    std::println("{:<15} {:>12} {:>12} {:>15}",
                 "X448", kp448.private_key.size(), kp448.public_key.size(), dh448.Size());
    std::println("{:<15} {:>12} {:>12} {:>15}",
                 "ML-KEM-512", kp512.private_key.size(), kp512.public_key.size(), dh512.Size());
    std::println("{:<15} {:>12} {:>12} {:>15}",
                 "ML-KEM-768", kp768.private_key.size(), kp768.public_key.size(), dh768.Size());
    std::println("{:<15} {:>12} {:>12} {:>15}",
                 "ML-KEM-1024", kp1024.private_key.size(), kp1024.public_key.size(), dh1024.Size());

    std::println("\nNote: For ML-KEM algorithms, 'Shared Secret' is the output size, not public key size.");
    std::println("ML-KEM ciphertext sizes: 512={}, 768={}, 1024={}", 768, 1088, 1568);

    // =======================================================================
    // Part 3: KEM Encapsulation/Decapsulation
    // =======================================================================
    print_separator("Part 3: KEM Encapsulation/Decapsulation Demonstration");

    std::println("Demonstrating ML-KEM-512 KEM operations...\n");

    // Alice generates a key pair
    std::println("Alice generates ML-KEM-512 keypair");
    Dh alice_dh(M512);
    auto alice_keys = alice_dh.GenerateKeypair();
    std::println("  Alice's public key size: {} bytes", alice_keys.public_key.size());

    // Bob encapsulates a shared secret using Alice's public key
    std::println("\nBob encapsulates a shared secret using Alice's public key");
    auto [encapsulated_key, bob_shared_secret] = alice_dh.Encapsulate(alice_keys.public_key);
    std::println("  Encapsulated key size: {} bytes", encapsulated_key.size());
    std::println("  Bob's shared secret size: {} bytes", bob_shared_secret.size());
    std::print("  Bob's shared secret (hex): ");
    print_hex_truncated(bob_shared_secret, bob_shared_secret.size());
    std::println("");

    // Alice decapsulates to recover the same shared secret
    std::println("\nAlice decapsulates using her private key");
    auto alice_shared_secret = alice_dh.Decapsulate(alice_keys.private_key, encapsulated_key);
    std::println("  Alice's shared secret size: {} bytes", alice_shared_secret.size());
    std::print("  Alice's shared secret (hex): ");
    print_hex_truncated(alice_shared_secret, alice_shared_secret.size());
    std::println("");

    // Verify they match
    bool secrets_match = (alice_shared_secret == bob_shared_secret);
    if (secrets_match) {
        std::println("\n✓ SUCCESS: Both parties derived the same shared secret!");
    } else {
        std::println("\n✗ FAILED: Shared secrets don't match!");
    }

    // =======================================================================
    // Part 4: Performance Comparison
    // =======================================================================
    print_separator("Part 4: Performance Benchmarks");

    const int iterations = 100;

    std::println("Running {} iterations for each operation...\n", iterations);

    // Benchmark ML-KEM-512
    auto start = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        dh512.GenerateKeypair();
    }
    auto keygen_512_duration = duration_cast<microseconds>(high_resolution_clock::now() - start);

    start = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        auto [enc_key, secret] = dh512.Encapsulate(kp512.public_key);
    }
    auto encap_512_duration = duration_cast<microseconds>(high_resolution_clock::now() - start);

    start = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        auto secret = dh512.Decapsulate(kp512.private_key, encapsulated_key);
    }
    auto decap_512_duration = duration_cast<microseconds>(high_resolution_clock::now() - start);

    // Benchmark ML-KEM-768
    start = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        dh768.GenerateKeypair();
    }
    auto keygen_768_duration = duration_cast<microseconds>(high_resolution_clock::now() - start);

    auto [enc_key_768, secret_768] = dh768.Encapsulate(kp768.public_key);
    start = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        auto [enc_key, secret] = dh768.Encapsulate(kp768.public_key);
    }
    auto encap_768_duration = duration_cast<microseconds>(high_resolution_clock::now() - start);

    start = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        auto secret = dh768.Decapsulate(kp768.private_key, enc_key_768);
    }
    auto decap_768_duration = duration_cast<microseconds>(high_resolution_clock::now() - start);

    // Benchmark ML-KEM-1024
    start = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        dh1024.GenerateKeypair();
    }
    auto keygen_1024_duration = duration_cast<microseconds>(high_resolution_clock::now() - start);

    auto [enc_key_1024, secret_1024] = dh1024.Encapsulate(kp1024.public_key);
    start = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        auto [enc_key, secret] = dh1024.Encapsulate(kp1024.public_key);
    }
    auto encap_1024_duration = duration_cast<microseconds>(high_resolution_clock::now() - start);

    start = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        auto secret = dh1024.Decapsulate(kp1024.private_key, enc_key_1024);
    }
    auto decap_1024_duration = duration_cast<microseconds>(high_resolution_clock::now() - start);

    // Display results
    std::println("{:<15} {:>18} {:>18} {:>18}",
                 "Algorithm", "KeyGen (avg μs)", "Encap (avg μs)", "Decap (avg μs)");
    std::println("{:-^75}", "");
    std::println("{:<15} {:>18.2f} {:>18.2f} {:>18.2f}",
                 "ML-KEM-512",
                 keygen_512_duration.count() / (double)iterations,
                 encap_512_duration.count() / (double)iterations,
                 decap_512_duration.count() / (double)iterations);
    std::println("{:<15} {:>18.2f} {:>18.2f} {:>18.2f}",
                 "ML-KEM-768",
                 keygen_768_duration.count() / (double)iterations,
                 encap_768_duration.count() / (double)iterations,
                 decap_768_duration.count() / (double)iterations);
    std::println("{:<15} {:>18.2f} {:>18.2f} {:>18.2f}",
                 "ML-KEM-1024",
                 keygen_1024_duration.count() / (double)iterations,
                 encap_1024_duration.count() / (double)iterations,
                 decap_1024_duration.count() / (double)iterations);

    std::println("\nNote: Higher security levels (768, 1024) have slower performance but stronger security.");

    // =======================================================================
    // Part 5: Error Handling Demonstration
    // =======================================================================
    print_separator("Part 5: Error Handling");

    std::println("Testing that DH() throws error for ML-KEM algorithms...");
    try {
        auto result = dh512.DH(kp512.private_key, kp512.public_key);
        std::println("✗ UNEXPECTED: DH() should have thrown an error");
    } catch (const NoiseError& e) {
        std::println("✓ SUCCESS: DH() correctly throws error for ML-KEM");
        std::println("  Error message: {}", e.what());
    }

    std::println("\nTesting that Encapsulate() throws error for DH algorithms...");
    try {
        auto result = dh25519.Encapsulate(kp25519.public_key);
        std::println("✗ UNEXPECTED: Encapsulate() should have thrown an error");
    } catch (const NoiseError& e) {
        std::println("✓ SUCCESS: Encapsulate() correctly throws error for DH algorithms");
        std::println("  Error message: {}", e.what());
    }

    // =======================================================================
    // Summary
    // =======================================================================
    print_separator("ML-KEM Sandbox Complete");
    std::println("All ML-KEM functionality has been demonstrated:");
    std::println("  ✓ Key generation for all 3 security levels (512, 768, 1024)");
    std::println("  ✓ Size comparisons across different algorithms");
    std::println("  ✓ KEM encapsulation/decapsulation operations");
    std::println("  ✓ Performance benchmarks");
    std::println("  ✓ Error handling verification");
    std::println("\nML-KEM integration is ready for use in the Noise protocol!\n");

    return 0;
}
