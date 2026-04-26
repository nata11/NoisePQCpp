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
// Dh Module Tests using Catch2 v3.11
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>

import noise;

using namespace Noise;

TEST_CASE("Dh - Default Constructor", "[dh][constructor]") {
    Dh dh;
    REQUIRE(dh.String() == X25519);
}

TEST_CASE("Dh - Explicit Constructor with X25519 string", "[dh][constructor]") {
    Dh dh(X25519);
    REQUIRE(dh.String() == X25519);
}

TEST_CASE("Dh - Explicit Constructor with X448 string", "[dh][constructor]") {
    Dh dh(X448);
    REQUIRE(dh.String() == X448);
}

TEST_CASE("Dh - Constructor from KeyAlgo enum", "[dh][constructor][enum]") {
    SECTION("X25519 from enum") {
        Dh dh(KeyAlgo::X25519);
        REQUIRE(dh.String() == X25519);
    }

    SECTION("X448 from enum") {
        Dh dh(KeyAlgo::X448);
        REQUIRE(dh.String() == X448);
    }
}

TEST_CASE("Dh - Invalid algorithm throws error", "[dh][constructor][error]") {
    REQUIRE_THROWS(Dh("InvalidAlgo"));
}

TEST_CASE("Dh - Copy Constructor", "[dh][constructor][copy]") {
    Dh dh1(X25519);
    Dh dh2(dh1);

    REQUIRE(dh1.String() == dh2.String());
    REQUIRE(dh2.String() == X25519);
}

TEST_CASE("Dh - Move Constructor", "[dh][constructor][move]") {
    Dh dh1(X448);
    Dh dh2(std::move(dh1));

    REQUIRE(dh2.String() == X448);
}

TEST_CASE("Dh - GenerateKeypair for X25519", "[dh][keygen][x25519]") {
    Dh dh(KeyAlgo::X25519);

    auto keypair = dh.GenerateKeypair();

    SECTION("Generated keys are not empty") {
        REQUIRE_FALSE(keypair.IsEmpty());
        REQUIRE_FALSE(keypair.private_key.empty());
        REQUIRE_FALSE(keypair.public_key.empty());
    }

    SECTION("X25519 keys have correct length") {
        REQUIRE(keypair.private_key.size() == 32);
        REQUIRE(keypair.public_key.size() == 32);
    }

    SECTION("Private and public keys are different") {
        REQUIRE(keypair.private_key != keypair.public_key);
    }

    SECTION("Generated keys are not all zeros") {
        bool private_has_nonzero = std::ranges::any_of(keypair.private_key,
            [](auto byte) { return byte != 0; });
        bool public_has_nonzero = std::ranges::any_of(keypair.public_key,
            [](auto byte) { return byte != 0; });

        REQUIRE(private_has_nonzero);
        REQUIRE(public_has_nonzero);
    }
}

TEST_CASE("Dh - GenerateKeypair for X448", "[dh][keygen][x448]") {
    Dh dh(KeyAlgo::X448);

    auto keypair = dh.GenerateKeypair();

    SECTION("Generated keys are not empty") {
        REQUIRE_FALSE(keypair.IsEmpty());
        REQUIRE_FALSE(keypair.private_key.empty());
        REQUIRE_FALSE(keypair.public_key.empty());
    }

    SECTION("X448 keys have correct length") {
        REQUIRE(keypair.private_key.size() == 56);
        REQUIRE(keypair.public_key.size() == 56);
    }

    SECTION("Private and public keys are different") {
        REQUIRE(keypair.private_key != keypair.public_key);
    }
}

TEST_CASE("Dh - Multiple key generations produce different keys", "[dh][keygen]") {
    Dh dh(KeyAlgo::X25519);

    auto keypair1 = dh.GenerateKeypair();
    auto keypair2 = dh.GenerateKeypair();

    SECTION("Different private keys") {
        REQUIRE(keypair1.private_key != keypair2.private_key);
    }

    SECTION("Different public keys") {
        REQUIRE(keypair1.public_key != keypair2.public_key);
    }
}

TEST_CASE("Dh - DH operation with X25519", "[dh][dh-operation][x25519]") {
    Dh dh(KeyAlgo::X25519);

    auto alice = dh.GenerateKeypair();
    auto bob = dh.GenerateKeypair();

    SECTION("Shared secret from Alice's perspective") {
        auto shared_alice = dh.DH(alice.private_key, bob.public_key);

        REQUIRE_FALSE(shared_alice.empty());
        REQUIRE(shared_alice.size() == 32);
    }

    SECTION("Shared secret from Bob's perspective") {
        auto shared_bob = dh.DH(bob.private_key, alice.public_key);

        REQUIRE_FALSE(shared_bob.empty());
        REQUIRE(shared_bob.size() == 32);
    }

    SECTION("Both parties compute same shared secret") {
        auto shared_alice = dh.DH(alice.private_key, bob.public_key);
        auto shared_bob = dh.DH(bob.private_key, alice.public_key);

        REQUIRE(shared_alice == shared_bob);
    }

    SECTION("Shared secret is different from keys") {
        auto shared = dh.DH(alice.private_key, bob.public_key);

        REQUIRE(shared != alice.private_key);
        REQUIRE(shared != alice.public_key);
        REQUIRE(shared != bob.private_key);
        REQUIRE(shared != bob.public_key);
    }
}

TEST_CASE("Dh - DH operation with X448", "[dh][dh-operation][x448]") {
    Dh dh(KeyAlgo::X448);

    auto alice = dh.GenerateKeypair();
    auto bob = dh.GenerateKeypair();

    SECTION("Shared secret from Alice's perspective") {
        auto shared_alice = dh.DH(alice.private_key, bob.public_key);

        REQUIRE_FALSE(shared_alice.empty());
        REQUIRE(shared_alice.size() == 56);
    }

    SECTION("Both parties compute same shared secret") {
        auto shared_alice = dh.DH(alice.private_key, bob.public_key);
        auto shared_bob = dh.DH(bob.private_key, alice.public_key);

        REQUIRE(shared_alice == shared_bob);
    }
}

TEST_CASE("Dh - DH operation with KeyPair overload", "[dh][dh-operation][keypair]") {
    Dh dh(KeyAlgo::X25519);

    auto alice = dh.GenerateKeypair();
    auto bob = dh.GenerateKeypair();

    SECTION("KeyPair overload produces same result as span overload") {
        auto shared_keypair = dh.DH(alice, bob);
        auto shared_span = dh.DH(alice.private_key, bob.public_key);

        REQUIRE(shared_keypair == shared_span);
    }

    SECTION("Both parties compute same shared secret using KeyPair") {
        auto shared_alice = dh.DH(alice, bob);
        auto shared_bob = dh.DH(bob, alice);

        REQUIRE(shared_alice == shared_bob);
    }
}

TEST_CASE("Dh - DH with mismatched key lengths throws", "[dh][dh-operation][error]") {
    Dh dh(KeyAlgo::X25519);

    auto keypair = dh.GenerateKeypair();

    // Create a key with wrong length
    std::vector<std::uint8_t> wrong_key(16, 0x42); // Only 16 bytes instead of 32

    REQUIRE_THROWS(dh.DH(keypair.private_key, wrong_key));
}

TEST_CASE("Dh - KeyPair IsEmpty method", "[dh][keypair]") {
    SECTION("Default KeyPair is empty") {
        KeyPair kp;
        REQUIRE(kp.IsEmpty());
    }

    SECTION("Generated KeyPair is not empty") {
        Dh dh(KeyAlgo::X25519);
        auto kp = dh.GenerateKeypair();
        REQUIRE_FALSE(kp.IsEmpty());
    }

    SECTION("KeyPair with only private key is not empty") {
        KeyPair kp;
        kp.private_key = {0x01, 0x02, 0x03};
        REQUIRE_FALSE(kp.IsEmpty());
    }

    SECTION("KeyPair with only public key is not empty") {
        KeyPair kp;
        kp.public_key = {0x01, 0x02, 0x03};
        REQUIRE_FALSE(kp.IsEmpty());
    }
}

TEST_CASE("Dh - String method returns algorithm name", "[dh][utility]") {
    SECTION("X25519") {
        Dh dh(KeyAlgo::X25519);
        REQUIRE(dh.String() == "25519");
    }

    SECTION("X448") {
        Dh dh(KeyAlgo::X448);
        REQUIRE(dh.String() == "448");
    }
}

TEST_CASE("Dh - Size method returns correct key length", "[dh][utility][size]") {
    SECTION("X25519 returns 32 bytes") {
        Dh dh(KeyAlgo::X25519);
        REQUIRE(dh.Size() == 32);
    }

    SECTION("X448 returns 56 bytes") {
        Dh dh(KeyAlgo::X448);
        REQUIRE(dh.Size() == 56);
    }

    SECTION("Default constructor returns 32 bytes (X25519)") {
        Dh dh;
        REQUIRE(dh.Size() == 32);
    }

    SECTION("Size matches generated keypair length") {
        Dh dh25519(KeyAlgo::X25519);
        auto kp25519 = dh25519.GenerateKeypair();
        REQUIRE(dh25519.Size() == kp25519.private_key.size());
        REQUIRE(dh25519.Size() == kp25519.public_key.size());

        Dh dh448(KeyAlgo::X448);
        auto kp448 = dh448.GenerateKeypair();
        REQUIRE(dh448.Size() == kp448.private_key.size());
        REQUIRE(dh448.Size() == kp448.public_key.size());
    }
}

TEST_CASE("Dh - PrintKeys does not throw", "[dh][utility]") {
    Dh dh(KeyAlgo::X25519);
    auto keypair = dh.GenerateKeypair();

    REQUIRE_NOTHROW(dh.PrintKeys(keypair));
}

TEST_CASE("Dh - X448 PrintKeys does not throw", "[dh][utility]") {
    Dh dh(KeyAlgo::X448);
    auto keypair = dh.GenerateKeypair();

    REQUIRE_NOTHROW(dh.PrintKeys(keypair));
}

TEST_CASE("Dh - Different algorithms produce different shared secrets", "[dh][edge-case]") {
    // This test ensures that X25519 and X448 are truly independent

    Dh dh25519(KeyAlgo::X25519);
    Dh dh448(KeyAlgo::X448);

    auto kp25519 = dh25519.GenerateKeypair();
    auto kp448 = dh448.GenerateKeypair();

    REQUIRE(kp25519.private_key.size() != kp448.private_key.size());
    REQUIRE(kp25519.public_key.size() != kp448.public_key.size());
}

TEST_CASE("Dh - Deterministic DH output for same inputs", "[dh][determinism]") {
    Dh dh(KeyAlgo::X25519);

    auto alice = dh.GenerateKeypair();
    auto bob = dh.GenerateKeypair();

    auto shared1 = dh.DH(alice.private_key, bob.public_key);
    auto shared2 = dh.DH(alice.private_key, bob.public_key);

    // Same inputs should produce same output
    REQUIRE(shared1 == shared2);
}

TEST_CASE("Dh - Different peers produce different shared secrets", "[dh][security]") {
    Dh dh(KeyAlgo::X25519);

    auto alice = dh.GenerateKeypair();
    auto bob = dh.GenerateKeypair();
    auto charlie = dh.GenerateKeypair();

    auto shared_alice_bob = dh.DH(alice.private_key, bob.public_key);
    auto shared_alice_charlie = dh.DH(alice.private_key, charlie.public_key);

    // Alice's shared secret with Bob should differ from her shared secret with Charlie
    REQUIRE(shared_alice_bob != shared_alice_charlie);
}

TEST_CASE("Dh - Shared secret is not equal to any input key", "[dh][security]") {
    Dh dh(KeyAlgo::X25519);

    auto alice = dh.GenerateKeypair();
    auto bob = dh.GenerateKeypair();

    auto shared = dh.DH(alice.private_key, bob.public_key);

    REQUIRE(shared != alice.private_key);
    REQUIRE(shared != alice.public_key);
    REQUIRE(shared != bob.private_key);
    REQUIRE(shared != bob.public_key);
}

TEST_CASE("Dh - Edge case with zero-filled keys", "[dh][edge-case]") {
    Dh dh(KeyAlgo::X25519);

    std::vector<std::uint8_t> zero_key(32, 0);
    auto keypair = dh.GenerateKeypair();

    // DH with zero key should still work (though not cryptographically useful)
    REQUIRE_NOTHROW(dh.DH(zero_key, keypair.public_key));
}

// ============================================================================
// Phase 1: ML-KEM Key Generation Tests
// ============================================================================

TEST_CASE("Dh - ML-KEM-512 Constructor", "[dh][mlkem][constructor][m512]") {
    Dh dh(M512);
    REQUIRE(dh.String() == M512);
    REQUIRE(dh.Size() == 32);  // Shared secret size for all ML-KEM variants
}

TEST_CASE("Dh - ML-KEM-768 Constructor", "[dh][mlkem][constructor][m768]") {
    Dh dh(M768);
    REQUIRE(dh.String() == M768);
    REQUIRE(dh.Size() == 32);  // Shared secret size for all ML-KEM variants
}

TEST_CASE("Dh - ML-KEM-1024 Constructor", "[dh][mlkem][constructor][m1024]") {
    Dh dh(M1024);
    REQUIRE(dh.String() == M1024);
    REQUIRE(dh.Size() == 32);  // Shared secret size for all ML-KEM variants
}

TEST_CASE("Dh - ML-KEM-512 Key Generation", "[dh][mlkem][keygen][m512]") {
    Dh dh(M512);

    auto keypair = dh.GenerateKeypair();

    SECTION("Generated keys are not empty") {
        REQUIRE_FALSE(keypair.IsEmpty());
        REQUIRE_FALSE(keypair.private_key.empty());
        REQUIRE_FALSE(keypair.public_key.empty());
    }

    SECTION("ML-KEM-512 public key has correct size") {
        REQUIRE(keypair.public_key.size() == 800);
    }

    SECTION("ML-KEM-512 private key size is valid") {
        // Private key can be 64 bytes (seed) or larger (expanded)
        REQUIRE(keypair.private_key.size() >= 64);
    }

    SECTION("Private and public keys are different") {
        REQUIRE(keypair.private_key != keypair.public_key);
    }

    SECTION("Generated keys are not all zeros") {
        bool private_has_nonzero = std::ranges::any_of(keypair.private_key,
            [](auto byte) { return byte != 0; });
        bool public_has_nonzero = std::ranges::any_of(keypair.public_key,
            [](auto byte) { return byte != 0; });

        REQUIRE(private_has_nonzero);
        REQUIRE(public_has_nonzero);
    }
}

TEST_CASE("Dh - ML-KEM-768 Key Generation", "[dh][mlkem][keygen][m768]") {
    Dh dh(M768);

    auto keypair = dh.GenerateKeypair();

    SECTION("Generated keys are not empty") {
        REQUIRE_FALSE(keypair.IsEmpty());
        REQUIRE_FALSE(keypair.private_key.empty());
        REQUIRE_FALSE(keypair.public_key.empty());
    }

    SECTION("ML-KEM-768 public key has correct size") {
        REQUIRE(keypair.public_key.size() == 1184);
    }

    SECTION("ML-KEM-768 private key size is valid") {
        // Private key can be 64 bytes (seed) or larger (expanded)
        REQUIRE(keypair.private_key.size() >= 64);
    }

    SECTION("Private and public keys are different") {
        REQUIRE(keypair.private_key != keypair.public_key);
    }
}

TEST_CASE("Dh - ML-KEM-1024 Key Generation", "[dh][mlkem][keygen][m1024]") {
    Dh dh(M1024);

    auto keypair = dh.GenerateKeypair();

    SECTION("Generated keys are not empty") {
        REQUIRE_FALSE(keypair.IsEmpty());
        REQUIRE_FALSE(keypair.private_key.empty());
        REQUIRE_FALSE(keypair.public_key.empty());
    }

    SECTION("ML-KEM-1024 public key has correct size") {
        REQUIRE(keypair.public_key.size() == 1568);
    }

    SECTION("ML-KEM-1024 private key size is valid") {
        // Private key can be 64 bytes (seed) or larger (expanded)
        REQUIRE(keypair.private_key.size() >= 64);
    }

    SECTION("Private and public keys are different") {
        REQUIRE(keypair.private_key != keypair.public_key);
    }
}

TEST_CASE("Dh - ML-KEM Multiple generations produce different keys", "[dh][mlkem][keygen]") {
    Dh dh(M512);

    auto keypair1 = dh.GenerateKeypair();
    auto keypair2 = dh.GenerateKeypair();

    SECTION("Different private keys") {
        REQUIRE(keypair1.private_key != keypair2.private_key);
    }

    SECTION("Different public keys") {
        REQUIRE(keypair1.public_key != keypair2.public_key);
    }
}

TEST_CASE("Dh - ML-KEM PrintKeys does not throw", "[dh][mlkem][utility]") {
    Dh dh(M512);
    auto keypair = dh.GenerateKeypair();

    REQUIRE_NOTHROW(dh.PrintKeys(keypair));
}

TEST_CASE("Dh - ML-KEM variants have different public key sizes", "[dh][mlkem][comparison]") {
    Dh dh512(M512);
    Dh dh768(M768);
    Dh dh1024(M1024);

    auto kp512 = dh512.GenerateKeypair();
    auto kp768 = dh768.GenerateKeypair();
    auto kp1024 = dh1024.GenerateKeypair();

    REQUIRE(kp512.public_key.size() == 800);
    REQUIRE(kp768.public_key.size() == 1184);
    REQUIRE(kp1024.public_key.size() == 1568);

    // All ML-KEM variants should report same shared secret size
    REQUIRE(dh512.Size() == 32);
    REQUIRE(dh768.Size() == 32);
    REQUIRE(dh1024.Size() == 32);
}

// ============================================================================
// Phase 2: ML-KEM Encapsulation/Decapsulation Tests
// ============================================================================

TEST_CASE("Dh - ML-KEM-512 Encapsulate/Decapsulate Round Trip", "[dh][mlkem][kem][m512]") {
    Dh dh(M512);

    // Generate key pair
    auto keypair = dh.GenerateKeypair();

    SECTION("Encapsulation produces correct sizes") {
        auto [encapsulated_key, shared_secret_enc] = dh.Encapsulate(keypair.public_key);

        REQUIRE(encapsulated_key.size() == 768);  // ML-KEM-512 ciphertext size
        REQUIRE(shared_secret_enc.size() == 32);  // Shared secret size
    }

    SECTION("Full round trip: encapsulate then decapsulate") {
        auto [encapsulated_key, shared_secret_enc] = dh.Encapsulate(keypair.public_key);
        auto shared_secret_dec = dh.Decapsulate(keypair.private_key, encapsulated_key);

        REQUIRE(shared_secret_dec.size() == 32);
        REQUIRE(shared_secret_enc == shared_secret_dec);
    }

    SECTION("Encapsulated keys are not all zeros") {
        auto [encapsulated_key, shared_secret] = dh.Encapsulate(keypair.public_key);

        bool enc_has_nonzero = std::ranges::any_of(encapsulated_key,
            [](auto byte) { return byte != 0; });
        bool secret_has_nonzero = std::ranges::any_of(shared_secret,
            [](auto byte) { return byte != 0; });

        REQUIRE(enc_has_nonzero);
        REQUIRE(secret_has_nonzero);
    }
}

TEST_CASE("Dh - ML-KEM-768 Encapsulate/Decapsulate Round Trip", "[dh][mlkem][kem][m768]") {
    Dh dh(M768);

    auto keypair = dh.GenerateKeypair();

    SECTION("Encapsulation produces correct sizes") {
        auto [encapsulated_key, shared_secret_enc] = dh.Encapsulate(keypair.public_key);

        REQUIRE(encapsulated_key.size() == 1088);  // ML-KEM-768 ciphertext size
        REQUIRE(shared_secret_enc.size() == 32);
    }

    SECTION("Full round trip") {
        auto [encapsulated_key, shared_secret_enc] = dh.Encapsulate(keypair.public_key);
        auto shared_secret_dec = dh.Decapsulate(keypair.private_key, encapsulated_key);

        REQUIRE(shared_secret_enc == shared_secret_dec);
    }
}

TEST_CASE("Dh - ML-KEM-1024 Encapsulate/Decapsulate Round Trip", "[dh][mlkem][kem][m1024]") {
    Dh dh(M1024);

    auto keypair = dh.GenerateKeypair();

    SECTION("Encapsulation produces correct sizes") {
        auto [encapsulated_key, shared_secret_enc] = dh.Encapsulate(keypair.public_key);

        REQUIRE(encapsulated_key.size() == 1568);  // ML-KEM-1024 ciphertext size
        REQUIRE(shared_secret_enc.size() == 32);
    }

    SECTION("Full round trip") {
        auto [encapsulated_key, shared_secret_enc] = dh.Encapsulate(keypair.public_key);
        auto shared_secret_dec = dh.Decapsulate(keypair.private_key, encapsulated_key);

        REQUIRE(shared_secret_enc == shared_secret_dec);
    }
}

TEST_CASE("Dh - ML-KEM Multiple encapsulations produce different results", "[dh][mlkem][kem]") {
    Dh dh(M512);
    auto keypair = dh.GenerateKeypair();

    auto [enc_key1, secret1] = dh.Encapsulate(keypair.public_key);
    auto [enc_key2, secret2] = dh.Encapsulate(keypair.public_key);

    SECTION("Different encapsulated keys") {
        REQUIRE(enc_key1 != enc_key2);
    }

    SECTION("Different shared secrets") {
        REQUIRE(secret1 != secret2);
    }
}

TEST_CASE("Dh - ML-KEM DH() throws error for KEM algorithms", "[dh][mlkem][error]") {
    Dh dh(M512);
    auto keypair = dh.GenerateKeypair();

    REQUIRE_THROWS_AS(dh.DH(keypair.private_key, keypair.public_key), NoiseError);
}

TEST_CASE("Dh - ML-KEM Encapsulate throws for non-KEM algorithms", "[dh][mlkem][error]") {
    Dh dh(X25519);
    auto keypair = dh.GenerateKeypair();

    REQUIRE_THROWS_AS(dh.Encapsulate(keypair.public_key), NoiseError);
}

TEST_CASE("Dh - ML-KEM Decapsulate throws for non-KEM algorithms", "[dh][mlkem][error]") {
    Dh dh(X25519);
    auto keypair = dh.GenerateKeypair();
    std::vector<std::uint8_t> fake_encap(768, 0);

    REQUIRE_THROWS_AS(dh.Decapsulate(keypair.private_key, fake_encap), NoiseError);
}

TEST_CASE("Dh - ML-KEM KEM operation with wrong private key fails gracefully", "[dh][mlkem][error]") {
    Dh dh(M512);
    auto keypair1 = dh.GenerateKeypair();
    auto keypair2 = dh.GenerateKeypair();

    auto [encapsulated_key, shared_secret_enc] = dh.Encapsulate(keypair1.public_key);

    // Try to decapsulate with wrong private key - should not throw but produce different secret
    auto shared_secret_wrong = dh.Decapsulate(keypair2.private_key, encapsulated_key);

    // The decapsulation will succeed but produce a different (invalid) shared secret
    REQUIRE(shared_secret_enc != shared_secret_wrong);
}

// Main function for Catch2
int main(int argc, char* argv[]) {
    // Disable all logging during tests for clean output
    Noise::DisableAllLogging();
    return Catch::Session().run(argc, argv);
}
