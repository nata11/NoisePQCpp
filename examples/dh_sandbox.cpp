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
// DH Sandbox - Test all DH module functionality
//

#include "botan_all.h"
import noise;
import std;

using namespace Noise;

void print_separator(const std::string& title) {
    std::println("\n{:=^80}", "");
    std::println("{:^80}", title);
    std::println("{:=^80}\n", "");
}

void print_keypair_info(const KeyPair& kp, const std::string& name) {
    std::println("  {} Private Key Size: {} bytes", name, kp.private_key.size());
    std::println("  {} Public Key Size:  {} bytes", name, kp.public_key.size());
    std::println("  {} Private Key (hex): {}", name,
                 Botan::hex_encode(kp.private_key.data(), kp.private_key.size(), true));
    std::println("  {} Public Key (hex):  {}", name,
                 Botan::hex_encode(kp.public_key.data(), kp.public_key.size(), true));
}

void print_shared_secret(const std::vector<std::uint8_t>& ss, const std::string& name) {
    std::println("  {} Shared Secret Size: {} bytes", name, ss.size());
    std::println("  {} Shared Secret (hex): {}", name,
                 Botan::hex_encode(ss.data(), ss.size(), true));
}

int main() {
    std::println("\n{:*^80}", " DH Module Sandbox ");
    std::println("{:^80}", "Testing all DH constructors and methods");
    std::println("{:*^80}\n", "");

    // =======================================================================
    // Test 1: Default Constructor
    // =======================================================================
    print_separator("Test 1: Default Constructor");

    try {
        std::println("Creating Dh with default constructor");
        Dh dh;
        std::println("  Algorithm: {}", dh.String());

        if (dh.String() == "25519") {
            std::println("✓ SUCCESS: Default is 25519\n");
        }
        else {
            std::println("✗ FAILED: Default is not 25519\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 2: Explicit Constructor with string_view
    // =======================================================================
    print_separator("Test 2: Explicit Constructor with string_view");

    try {
        std::println("Creating Dh with 25519 string");
        Dh dh1(X25519);
        std::println("  Algorithm: {}", dh1.String());
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Creating Dh with 448 string");
        Dh dh2(X448);
        std::println("  Algorithm: {}", dh2.String());
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 3: Constructor from KeyAlgo enum
    // =======================================================================
    print_separator("Test 3: Constructor from KeyAlgo enum");

    try {
        std::println("Creating Dh with KeyAlgo::X25519");
        Dh dh1(KeyAlgo::X25519);
        std::println("  Algorithm: {}", dh1.String());
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Creating Dh with KeyAlgo::X448");
        Dh dh2(KeyAlgo::X448);
        std::println("  Algorithm: {}", dh2.String());
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 4: Copy Constructor
    // =======================================================================
    print_separator("Test 4: Copy Constructor");

    try {
        std::println("Creating Dh with X448 and copying it");
        Dh dh1(X448);
        Dh dh2(dh1);

        std::println("  Original Algorithm: {}", dh1.String());
        std::println("  Copied Algorithm:   {}", dh2.String());

        if (dh1.String() == dh2.String()) {
            std::println("✓ SUCCESS: Both have same algorithm\n");
        }
        else {
            std::println("✗ FAILED: Algorithms differ\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 5: Move Constructor
    // =======================================================================
    print_separator("Test 5: Move Constructor");

    try {
        std::println("Creating Dh with X25519 and moving it");
        Dh dh1(X25519);
        Dh dh2(std::move(dh1));

        std::println("  Moved-to Algorithm: {}", dh2.String());
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 6: GenerateKeypair for X25519
    // =======================================================================
    print_separator("Test 6: GenerateKeypair for X25519");

    try {
        std::println("Generating X25519 keypair");
        Dh dh(KeyAlgo::X25519);
        auto keypair = dh.GenerateKeypair();

        std::println("  Private Key Size: {} bytes", keypair.private_key.size());
        std::println("  Public Key Size:  {} bytes", keypair.public_key.size());
        std::println("  IsEmpty: {}", keypair.IsEmpty());

        if (keypair.private_key.size() == 32 && keypair.public_key.size() == 32 && !keypair.IsEmpty()) {
            std::println("✓ SUCCESS: Correct key sizes (32 bytes each)\n");
        }
        else {
            std::println("✗ FAILED: Incorrect key sizes\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 7: GenerateKeypair for X448
    // =======================================================================
    print_separator("Test 7: GenerateKeypair for X448");

    try {
        std::println("Generating X448 keypair");
        Dh dh(KeyAlgo::X448);
        auto keypair = dh.GenerateKeypair();

        std::println("  Private Key Size: {} bytes", keypair.private_key.size());
        std::println("  Public Key Size:  {} bytes", keypair.public_key.size());
        std::println("  IsEmpty: {}", keypair.IsEmpty());

        if (keypair.private_key.size() == 56 && keypair.public_key.size() == 56 && !keypair.IsEmpty()) {
            std::println("✓ SUCCESS: Correct key sizes (56 bytes each)\n");
        }
        else {
            std::println("✗ FAILED: Incorrect key sizes\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 8: Multiple key generations produce different keys
    // =======================================================================
    print_separator("Test 8: Multiple Key Generations Produce Different Keys");

    try {
        std::println("Generating two X25519 keypairs");
        Dh dh(KeyAlgo::X25519);
        auto keypair1 = dh.GenerateKeypair();
        auto keypair2 = dh.GenerateKeypair();

        bool priv_different = (keypair1.private_key != keypair2.private_key);
        bool pub_different = (keypair1.public_key != keypair2.public_key);

        std::println("  Private keys different: {}", priv_different);
        std::println("  Public keys different:  {}", pub_different);

        if (priv_different && pub_different) {
            std::println("✓ SUCCESS: Keys are different\n");
        }
        else {
            std::println("✗ FAILED: Keys are the same\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 9: DH operation with X25519 (span overload)
    // =======================================================================
    print_separator("Test 9: DH Operation with X25519 (span overload)");

    try {
        std::println("Performing X25519 DH key exchange");
        Dh dh(KeyAlgo::X25519);

        auto alice = dh.GenerateKeypair();
        auto bob = dh.GenerateKeypair();

        std::println("\nAlice's keys:");
        print_keypair_info(alice, "Alice");

        std::println("\nBob's keys:");
        print_keypair_info(bob, "Bob");

        auto shared_alice = dh.DH(alice.private_key, bob.public_key);
        auto shared_bob = dh.DH(bob.private_key, alice.public_key);

        std::println("\nShared secrets:");
        print_shared_secret(shared_alice, "Alice");
        print_shared_secret(shared_bob, "Bob");

        bool equal = (shared_alice == shared_bob);
        std::println("\n  Shared secrets equal: {}", equal);
        std::println("  Shared secret size: {} bytes", shared_alice.size());

        if (equal && shared_alice.size() == 32) {
            std::println("✓ SUCCESS: Both parties computed same 32-byte shared secret\n");
        }
        else {
            std::println("✗ FAILED: Shared secrets don't match or wrong size\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 10: DH operation with X448 (span overload)
    // =======================================================================
    print_separator("Test 10: DH Operation with X448 (span overload)");

    try {
        std::println("Performing X448 DH key exchange");
        Dh dh(KeyAlgo::X448);

        auto alice = dh.GenerateKeypair();
        auto bob = dh.GenerateKeypair();

        auto shared_alice = dh.DH(alice.private_key, bob.public_key);
        auto shared_bob = dh.DH(bob.private_key, alice.public_key);

        std::println("  Alice's shared secret size: {} bytes", shared_alice.size());
        std::println("  Bob's shared secret size:   {} bytes", shared_bob.size());

        bool equal = (shared_alice == shared_bob);
        std::println("  Shared secrets equal: {}", equal);

        if (equal && shared_alice.size() == 56) {
            std::println("✓ SUCCESS: Both parties computed same 56-byte shared secret\n");
        }
        else {
            std::println("✗ FAILED: Shared secrets don't match or wrong size\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 11: DH operation with KeyPair overload
    // =======================================================================
    print_separator("Test 11: DH Operation with KeyPair Overload");

    try {
        std::println("Testing KeyPair overload vs span overload");
        Dh dh(KeyAlgo::X25519);

        auto alice = dh.GenerateKeypair();
        auto bob = dh.GenerateKeypair();

        auto shared_keypair = dh.DH(alice, bob);
        auto shared_span = dh.DH(alice.private_key, bob.public_key);

        std::println("  KeyPair overload result size: {} bytes", shared_keypair.size());
        std::println("  Span overload result size:    {} bytes", shared_span.size());

        bool equal = (shared_keypair == shared_span);
        std::println("  Results equal: {}", equal);

        if (equal) {
            std::println("✓ SUCCESS: Both overloads produce same result\n");
        }
        else {
            std::println("✗ FAILED: Overloads produce different results\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 12: String() method
    // =======================================================================
    print_separator("Test 12: String() Method");

    try {
        std::println("Testing String() method");
        Dh dh1(KeyAlgo::X25519);
        Dh dh2(KeyAlgo::X448);

        std::println("  X25519 Dh String(): {}", dh1.String());
        std::println("  X448 Dh String():   {}", dh2.String());

        if (dh1.String() == "25519" && dh2.String() == "448") {
            std::println("✓ SUCCESS: String() returns correct algorithm names\n");
        }
        else {
            std::println("✗ FAILED: String() returns incorrect names\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 13: PrintKeys() method
    // =======================================================================
    print_separator("Test 13: PrintKeys() Method");

    try {
        std::println("Testing PrintKeys() method");
        Dh dh(KeyAlgo::X25519);
        auto keypair = dh.GenerateKeypair();

        std::println("\nCalling PrintKeys():");
        dh.PrintKeys(keypair);
        std::println("\n✓ SUCCESS: PrintKeys() executed without error\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 14: KeyPair IsEmpty() method
    // =======================================================================
    print_separator("Test 14: KeyPair IsEmpty() Method");

    try {
        std::println("Testing KeyPair IsEmpty() method");

        KeyPair empty_kp;
        std::println("  Default KeyPair IsEmpty: {}", empty_kp.IsEmpty());

        Dh dh(KeyAlgo::X25519);
        auto generated_kp = dh.GenerateKeypair();
        std::println("  Generated KeyPair IsEmpty: {}", generated_kp.IsEmpty());

        KeyPair partial_kp;
        partial_kp.private_key = {0x01, 0x02, 0x03};
        std::println("  Partial KeyPair IsEmpty: {}", partial_kp.IsEmpty());

        if (empty_kp.IsEmpty() && !generated_kp.IsEmpty() && !partial_kp.IsEmpty()) {
            std::println("✓ SUCCESS: IsEmpty() works correctly\n");
        }
        else {
            std::println("✗ FAILED: IsEmpty() behavior incorrect\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 15: Deterministic DH output for same inputs
    // =======================================================================
    print_separator("Test 15: Deterministic DH Output");

    try {
        std::println("Testing DH determinism");
        Dh dh(KeyAlgo::X25519);

        auto alice = dh.GenerateKeypair();
        auto bob = dh.GenerateKeypair();

        auto shared1 = dh.DH(alice.private_key, bob.public_key);
        auto shared2 = dh.DH(alice.private_key, bob.public_key);
        auto shared3 = dh.DH(alice.private_key, bob.public_key);

        bool all_equal = (shared1 == shared2) && (shared2 == shared3);
        std::println("  All three DH operations equal: {}", all_equal);

        if (all_equal) {
            std::println("✓ SUCCESS: DH is deterministic\n");
        }
        else {
            std::println("✗ FAILED: DH is not deterministic\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 16: Different peers produce different shared secrets
    // =======================================================================
    print_separator("Test 16: Different Peers Produce Different Secrets");

    try {
        std::println("Testing that different peers produce different shared secrets");
        Dh dh(KeyAlgo::X25519);

        auto alice = dh.GenerateKeypair();
        auto bob = dh.GenerateKeypair();
        auto charlie = dh.GenerateKeypair();

        auto shared_alice_bob = dh.DH(alice.private_key, bob.public_key);
        auto shared_alice_charlie = dh.DH(alice.private_key, charlie.public_key);
        auto shared_bob_charlie = dh.DH(bob.private_key, charlie.public_key);

        bool all_different = (shared_alice_bob != shared_alice_charlie) &&
            (shared_alice_charlie != shared_bob_charlie) &&
            (shared_alice_bob != shared_bob_charlie);

        std::println("  Alice-Bob shared secret:     {} bytes", shared_alice_bob.size());
        std::println("  Alice-Charlie shared secret: {} bytes", shared_alice_charlie.size());
        std::println("  Bob-Charlie shared secret:   {} bytes", shared_bob_charlie.size());
        std::println("  All different: {}", all_different);

        if (all_different) {
            std::println("✓ SUCCESS: Different peers produce different secrets\n");
        }
        else {
            std::println("✗ FAILED: Shared secrets are not all different\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 17: Shared secret is not equal to any input key
    // =======================================================================
    print_separator("Test 17: Shared Secret Not Equal to Input Keys");

    try {
        std::println("Testing that shared secret differs from all input keys");
        Dh dh(KeyAlgo::X25519);

        auto alice = dh.GenerateKeypair();
        auto bob = dh.GenerateKeypair();

        auto shared = dh.DH(alice.private_key, bob.public_key);

        bool not_alice_priv = (shared != alice.private_key);
        bool not_alice_pub = (shared != alice.public_key);
        bool not_bob_priv = (shared != bob.private_key);
        bool not_bob_pub = (shared != bob.public_key);

        std::println("  Shared != Alice's private: {}", not_alice_priv);
        std::println("  Shared != Alice's public:  {}", not_alice_pub);
        std::println("  Shared != Bob's private:   {}", not_bob_priv);
        std::println("  Shared != Bob's public:    {}", not_bob_pub);

        if (not_alice_priv && not_alice_pub && not_bob_priv && not_bob_pub) {
            std::println("✓ SUCCESS: Shared secret differs from all input keys\n");
        }
        else {
            std::println("✗ FAILED: Shared secret matches an input key\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 18: Different algorithms produce different key sizes
    // =======================================================================
    print_separator("Test 18: Different Algorithms Produce Different Key Sizes");

    try {
        std::println("Testing key sizes for different algorithms");
        Dh dh25519(KeyAlgo::X25519);
        Dh dh448(KeyAlgo::X448);

        auto kp25519 = dh25519.GenerateKeypair();
        auto kp448 = dh448.GenerateKeypair();

        std::println("  X25519 private key size: {} bytes", kp25519.private_key.size());
        std::println("  X25519 public key size:  {} bytes", kp25519.public_key.size());
        std::println("  X448 private key size:   {} bytes", kp448.private_key.size());
        std::println("  X448 public key size:    {} bytes", kp448.public_key.size());

        bool correct_sizes = (kp25519.private_key.size() == 32) &&
            (kp25519.public_key.size() == 32) &&
            (kp448.private_key.size() == 56) &&
            (kp448.public_key.size() == 56);

        if (correct_sizes) {
            std::println("✓ SUCCESS: All key sizes are correct\n");
        }
        else {
            std::println("✗ FAILED: Incorrect key sizes\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 19: Error case - Invalid algorithm
    // =======================================================================
    print_separator("Test 19: Error Case - Invalid Algorithm");

    try {
        std::println("Testing invalid algorithm name");
        Dh dh("InvalidAlgo");
        std::println("✗ UNEXPECTED: Should have thrown an error\n");
    }
    catch (const std::exception& e) {
        std::println("✓ EXPECTED error: {}\n", e.what());
    }

    // =======================================================================
    // Test 20: Error case - Mismatched key lengths
    // =======================================================================
    print_separator("Test 20: Error Case - Mismatched Key Lengths");

    try {
        std::println("Testing DH with mismatched key lengths");
        Dh dh(KeyAlgo::X25519);
        auto keypair = dh.GenerateKeypair();

        std::vector<std::uint8_t> wrong_key(16, 0x42); // Only 16 bytes instead of 32

        auto result = dh.DH(keypair.private_key, wrong_key);
        std::println("✗ UNEXPECTED: Should have thrown an error\n");
    }
    catch (const std::exception& e) {
        std::println("✓ EXPECTED error: {}\n", e.what());
    }

    // =======================================================================
    // Test 21: Edge case - Zero-filled keys
    // =======================================================================
    print_separator("Test 21: Edge Case - Zero-Filled Keys");

    try {
        std::println("Testing DH with zero-filled key");
        Dh dh(KeyAlgo::X25519);
        auto keypair = dh.GenerateKeypair();

        std::vector<std::uint8_t> zero_key(32, 0);
        auto shared = dh.DH(zero_key, keypair.public_key);

        std::println("  Shared secret size: {} bytes", shared.size());
        std::println("✓ SUCCESS: DH works with zero key (though not cryptographically useful)\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 22: Private and public keys are different
    // =======================================================================
    print_separator("Test 22: Private and Public Keys Are Different");

    try {
        std::println("Testing that private and public keys are different");
        Dh dh(KeyAlgo::X25519);
        auto keypair = dh.GenerateKeypair();

        bool keys_different = (keypair.private_key != keypair.public_key);
        std::println("  Private != Public: {}", keys_different);

        if (keys_different) {
            std::println("✓ SUCCESS: Private and public keys are different\n");
        }
        else {
            std::println("✗ FAILED: Private and public keys are the same\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 23: Keys are not all zeros
    // =======================================================================
    print_separator("Test 23: Generated Keys Are Not All Zeros");

    try {
        std::println("Testing that generated keys are not all zeros");
        Dh dh(KeyAlgo::X25519);
        auto keypair = dh.GenerateKeypair();

        bool priv_has_nonzero = std::ranges::any_of(keypair.private_key,
                                                    [](auto byte) { return byte != 0; });
        bool pub_has_nonzero = std::ranges::any_of(keypair.public_key,
                                                   [](auto byte) { return byte != 0; });

        std::println("  Private key has non-zero bytes: {}", priv_has_nonzero);
        std::println("  Public key has non-zero bytes:  {}", pub_has_nonzero);

        if (priv_has_nonzero && pub_has_nonzero) {
            std::println("✓ SUCCESS: Keys contain non-zero bytes\n");
        }
        else {
            std::println("✗ FAILED: Keys are all zeros\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Summary
    // =======================================================================
    print_separator("DH Sandbox Complete");
    std::println("All DH functionality has been tested.");
    std::println("Review the output above for any failures.\n");

    return 0;
}
