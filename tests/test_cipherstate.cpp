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
// CipherState Module Tests using Catch2 v3.11
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>

import noise;

using namespace Noise;

TEST_CASE("CipherState - Constructor", "[cipherstate][constructor]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 65535);

    REQUIRE(state.maxMessageSize == 65535);
    REQUIRE(state.nonce == 0);
    REQUIRE_FALSE(state.HasKey());
}

TEST_CASE("CipherState - Copy Constructor", "[cipherstate][constructor][copy]") {
    Cipher cipher(AESGCM);
    CipherState state1(std::move(cipher), 65535);

    // Initialize a key
    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0x42);
    state1.InitializeKey(key);
    state1.SetNonce(5);

    CipherState state2(state1);

    REQUIRE(state2.maxMessageSize == 65535);
    REQUIRE(state2.nonce == 5);
    REQUIRE(state2.HasKey());
    REQUIRE(state2.key == state1.key);
}

TEST_CASE("CipherState - Move Constructor", "[cipherstate][constructor][move]") {
    Cipher cipher(ChaChaPoly);
    CipherState state1(std::move(cipher), 65535);

    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0x99);
    state1.InitializeKey(key);

    CipherState state2(std::move(state1));

    REQUIRE(state2.maxMessageSize == 65535);
    REQUIRE(state2.HasKey());
    REQUIRE(state2.nonce == 0);
}

TEST_CASE("CipherState - InitializeKey", "[cipherstate][key]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 65535);

    REQUIRE_FALSE(state.HasKey());

    std::array<std::uint8_t, 32> key{};
    for (size_t i = 0; i < 32; ++i) {
        key[i] = static_cast<std::uint8_t>(i);
    }

    state.InitializeKey(key);

    REQUIRE(state.HasKey());
    REQUIRE(state.key == key);
    REQUIRE(state.nonce == 0);  // InitializeKey should reset nonce
}

TEST_CASE("CipherState - HasKey", "[cipherstate][key]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 65535);

    SECTION("Initially has no key") {
        REQUIRE_FALSE(state.HasKey());
    }

    SECTION("After initialization has key") {
        std::array<std::uint8_t, 32> key{};
        key[0] = 1;  // At least one non-zero byte
        state.InitializeKey(key);
        REQUIRE(state.HasKey());
    }

    SECTION("All-zero key is detected as no key") {
        std::array<std::uint8_t, 32> zero_key{};  // All zeros
        state.key = zero_key;
        REQUIRE_FALSE(state.HasKey());
    }
}

TEST_CASE("CipherState - SetNonce", "[cipherstate][nonce]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 65535);

    REQUIRE(state.nonce == 0);

    state.SetNonce(42);
    REQUIRE(state.nonce == 42);

    state.SetNonce(1000);
    REQUIRE(state.nonce == 1000);
}

TEST_CASE("CipherState - EncryptWithAd without key returns plaintext", "[cipherstate][encrypt]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 65535);

    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<std::uint8_t> ad{};

    auto result = state.EncryptWithAd(ad, plaintext);

    // Without a key, should return plaintext unchanged
    REQUIRE(result == plaintext);
}

TEST_CASE("CipherState - EncryptWithAd with key", "[cipherstate][encrypt]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 65535);

    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0x55);
    state.InitializeKey(key);

    std::vector<std::uint8_t> plaintext = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f  // "Hello"
    };
    std::vector<std::uint8_t> ad{};

    auto ciphertext = state.EncryptWithAd(ad, plaintext);

    SECTION("Ciphertext is different from plaintext") {
        REQUIRE(ciphertext != plaintext);
        REQUIRE(ciphertext.size() == plaintext.size() + 16);  // +16 for auth tag
    }

    SECTION("Nonce increments after encryption") {
        REQUIRE(state.nonce == 1);
    }
}

TEST_CASE("CipherState - DecryptWithAd without key returns ciphertext", "[cipherstate][decrypt]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 65535);

    std::vector<std::uint8_t> ciphertext = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<std::uint8_t> ad{};

    auto result = state.DecryptWithAd(ad, ciphertext);

    // Without a key, should return ciphertext unchanged
    REQUIRE(result == ciphertext);
}

TEST_CASE("CipherState - Encrypt then Decrypt roundtrip", "[cipherstate][roundtrip]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 65535);

    std::array<std::uint8_t, 32> key{};
    for (size_t i = 0; i < 32; ++i) {
        key[i] = static_cast<std::uint8_t>(i * 3);
    }
    state.InitializeKey(key);

    std::vector<std::uint8_t> plaintext = {
        0x54, 0x65, 0x73, 0x74, 0x20, 0x44, 0x61, 0x74, 0x61  // "Test Data"
    };
    std::vector<std::uint8_t> ad{};

    auto ciphertext = state.EncryptWithAd(ad, plaintext);
    REQUIRE(state.nonce == 1);

    // Create new state with same key for decryption
    Cipher cipher2(ChaChaPoly);
    CipherState state2(std::move(cipher2), 65535);
    state2.InitializeKey(key);

    auto decrypted = state2.DecryptWithAd(ad, ciphertext);

    REQUIRE(decrypted == plaintext);
}

TEST_CASE("CipherState - EncryptWithAd with Associated Data", "[cipherstate][encrypt][ad]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 65535);

    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0x77);
    state.InitializeKey(key);

    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> ad = {0xAA, 0xBB, 0xCC};

    auto ciphertext = state.EncryptWithAd(ad, plaintext);

    SECTION("Decryption with correct AD succeeds") {
        Cipher cipher2(ChaChaPoly);
        CipherState state2(std::move(cipher2), 65535);
        state2.InitializeKey(key);

        auto decrypted = state2.DecryptWithAd(ad, ciphertext);
        REQUIRE(decrypted == plaintext);
    }

    SECTION("Decryption with wrong AD fails") {
        Cipher cipher2(ChaChaPoly);
        CipherState state2(std::move(cipher2), 65535);
        state2.InitializeKey(key);

        std::vector<std::uint8_t> wrong_ad = {0xFF, 0xEE, 0xDD};
        REQUIRE_THROWS_AS(state2.DecryptWithAd(wrong_ad, ciphertext), std::exception);
    }
}

TEST_CASE("CipherState - Nonce increments with each operation", "[cipherstate][nonce]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 65535);

    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0x88);
    state.InitializeKey(key);

    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> ad{};

    REQUIRE(state.nonce == 0);

    auto dummy = state.EncryptWithAd(ad, plaintext);
    REQUIRE(state.nonce == 1);

    dummy = state.EncryptWithAd(ad, plaintext);
    REQUIRE(state.nonce == 2);

    dummy = state.EncryptWithAd(ad, plaintext);
    REQUIRE(state.nonce == 3);
}

TEST_CASE("CipherState - Different nonces produce different ciphertexts", "[cipherstate][nonce]") {
    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0x99);

    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04};
    std::vector<std::uint8_t> ad{};

    // Encrypt with nonce 0
    Cipher cipher1(ChaChaPoly);
    CipherState state1(std::move(cipher1), 65535);
    state1.InitializeKey(key);
    auto ciphertext1 = state1.EncryptWithAd(ad, plaintext);

    // Encrypt with nonce 1 (after one encryption)
    Cipher cipher2(ChaChaPoly);
    CipherState state2(std::move(cipher2), 65535);
    state2.InitializeKey(key);
    auto dummy = state2.EncryptWithAd(ad, plaintext);  // nonce 0
    auto ciphertext2 = state2.EncryptWithAd(ad, plaintext);  // nonce 1

    // Different nonces should produce different ciphertexts
    REQUIRE(ciphertext1 != ciphertext2);
}

TEST_CASE("CipherState - Rekey", "[cipherstate][rekey]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 65535);

    std::array<std::uint8_t, 32> original_key{};
    std::ranges::fill(original_key, 0xAA);
    state.InitializeKey(original_key);

    auto old_key = state.key;

    SECTION("Rekey with default hash algorithm") {
        // Call Rekey without arguments to use default
        state.Rekey();

        // New key should be different
        REQUIRE(state.key != old_key);

        // New key should not be all zeros
        REQUIRE(state.HasKey());
    }

    SECTION("Rekey with explicit HKDF(SHA-256)") {
        // Call Rekey with explicit default algorithm
        state.Rekey("HKDF(SHA-256)");

        // New key should be different
        REQUIRE(state.key != old_key);

        // New key should not be all zeros
        REQUIRE(state.HasKey());
    }

    SECTION("Rekey with custom hash algorithm") {
        // Test with a different hash algorithm
        state.Rekey("HKDF(SHA-512)");

        // New key should be different
        REQUIRE(state.key != old_key);

        // New key should not be all zeros
        REQUIRE(state.HasKey());
    }

    SECTION("Multiple rekeys produce different keys") {
        state.Rekey();
        auto key_after_first_rekey = state.key;

        state.Rekey();
        auto key_after_second_rekey = state.key;

        // Each rekey should produce a different key
        REQUIRE(old_key != key_after_first_rekey);
        REQUIRE(key_after_first_rekey != key_after_second_rekey);
        REQUIRE(old_key != key_after_second_rekey);
    }
}

TEST_CASE("CipherState - Rekey without key does nothing", "[cipherstate][rekey]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 65535);

    REQUIRE_FALSE(state.HasKey());

    SECTION("Rekey without key using default algorithm") {
        // Rekey without key should return early
        state.Rekey();

        // Should still have no key
        REQUIRE_FALSE(state.HasKey());
    }

    SECTION("Rekey without key using explicit algorithm") {
        // Rekey without key should return early
        state.Rekey("HKDF(SHA-256)");

        // Should still have no key
        REQUIRE_FALSE(state.HasKey());
    }
}

TEST_CASE("CipherState - Reset", "[cipherstate][reset]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 65535);

    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0xBB);
    state.InitializeKey(key);
    state.SetNonce(10);

    REQUIRE(state.HasKey());
    REQUIRE(state.nonce == 10);

    state.Reset();

    // After reset, key should be zeroed
    REQUIRE_FALSE(state.HasKey());

    // Note: Reset does not reset nonce, only key
    REQUIRE(state.nonce == 10);
}

TEST_CASE("CipherState - Empty plaintext", "[cipherstate][edge-case]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 65535);

    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0xCC);
    state.InitializeKey(key);

    std::vector<std::uint8_t> plaintext{};
    std::vector<std::uint8_t> ad{};

    auto ciphertext = state.EncryptWithAd(ad, plaintext);

    // Even empty plaintext produces ciphertext (auth tag)
    REQUIRE(ciphertext.size() == 16);

    Cipher cipher2(ChaChaPoly);
    CipherState state2(std::move(cipher2), 65535);
    state2.InitializeKey(key);

    auto decrypted = state2.DecryptWithAd(ad, ciphertext);
    REQUIRE(decrypted.empty());
}

TEST_CASE("CipherState - Large plaintext", "[cipherstate][edge-case]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 1024 * 1024 * 2);  // 2MB max

    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0xDD);
    state.InitializeKey(key);

    // Create 100KB plaintext
    std::vector<std::uint8_t> plaintext(100 * 1024);
    for (size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<std::uint8_t>(i % 256);
    }

    std::vector<std::uint8_t> ad{};

    auto ciphertext = state.EncryptWithAd(ad, plaintext);

    Cipher cipher2(ChaChaPoly);
    CipherState state2(std::move(cipher2), 1024 * 1024 * 2);
    state2.InitializeKey(key);

    auto decrypted = state2.DecryptWithAd(ad, ciphertext);

    REQUIRE(decrypted == plaintext);
}

TEST_CASE("CipherState - Works with AES-GCM", "[cipherstate][aesgcm]") {
    Cipher cipher(AESGCM);
    CipherState state(std::move(cipher), 65535);

    std::array<std::uint8_t, 32> key{};
    for (size_t i = 0; i < 32; ++i) {
        key[i] = static_cast<std::uint8_t>(i * 2);
    }
    state.InitializeKey(key);

    std::vector<std::uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    std::vector<std::uint8_t> ad{};

    auto ciphertext = state.EncryptWithAd(ad, plaintext);

    Cipher cipher2(AESGCM);
    CipherState state2(std::move(cipher2), 65535);
    state2.InitializeKey(key);

    auto decrypted = state2.DecryptWithAd(ad, ciphertext);

    REQUIRE(decrypted == plaintext);
}

TEST_CASE("CipherState - Multiple sequential encryptions", "[cipherstate][sequence]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 65535);

    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0xEE);
    state.InitializeKey(key);

    std::vector<std::uint8_t> ad{};

    // Encrypt multiple messages
    std::vector<std::vector<std::uint8_t>> ciphertexts;
    for (int i = 0; i < 5; ++i) {
        std::vector<std::uint8_t> plaintext = {
            static_cast<std::uint8_t>(i),
            static_cast<std::uint8_t>(i + 1),
            static_cast<std::uint8_t>(i + 2)
        };
        auto ciphertext = state.EncryptWithAd(ad, plaintext);
        ciphertexts.push_back(ciphertext);
    }

    REQUIRE(state.nonce == 5);

    // All ciphertexts should be different (due to nonce)
    for (size_t i = 0; i < ciphertexts.size(); ++i) {
        for (size_t j = i + 1; j < ciphertexts.size(); ++j) {
            REQUIRE(ciphertexts[i] != ciphertexts[j]);
        }
    }
}

TEST_CASE("CipherState - std::span compatibility", "[cipherstate][span]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 65535);

    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0xFF);
    state.InitializeKey(key);

    SECTION("Works with std::vector") {
        std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03};
        std::vector<std::uint8_t> ad = {0xAA};

        auto ciphertext = state.EncryptWithAd(ad, plaintext);
        REQUIRE(ciphertext.size() > plaintext.size());
    }

    SECTION("Works with std::array") {
        std::array<std::uint8_t, 3> plaintext = {0x01, 0x02, 0x03};
        std::array<std::uint8_t, 1> ad = {0xAA};

        auto ciphertext = state.EncryptWithAd(ad, plaintext);
        REQUIRE(ciphertext.size() > plaintext.size());
    }

    SECTION("Works with raw pointer span") {
        std::uint8_t plaintext_arr[] = {0x01, 0x02, 0x03};
        std::uint8_t ad_arr[] = {0xAA};

        std::span<std::uint8_t> plaintext_span(plaintext_arr, 3);
        std::span<std::uint8_t> ad_span(ad_arr, 1);

        auto ciphertext = state.EncryptWithAd(ad_span, plaintext_span);
        REQUIRE(ciphertext.size() > 3);
    }
}

TEST_CASE("CipherState - 2-argument return-value overload", "[cipherstate][overload][public]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 65535);

    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0xAA);
    state.InitializeKey(key);

    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<std::uint8_t> ad = {0xAA, 0xBB};

    SECTION("EncryptWithAd returns new vector") {
        auto ciphertext = state.EncryptWithAd(ad, plaintext);

        REQUIRE(ciphertext.size() == plaintext.size() + 16);
        REQUIRE(ciphertext != plaintext);
        REQUIRE(state.nonce == 1);
    }

    SECTION("DecryptWithAd returns new vector") {
        auto ciphertext = state.EncryptWithAd(ad, plaintext);

        Cipher cipher2(ChaChaPoly);
        CipherState state2(std::move(cipher2), 65535);
        state2.InitializeKey(key);

        auto decrypted = state2.DecryptWithAd(ad, ciphertext);

        REQUIRE(decrypted == plaintext);
        REQUIRE(state2.nonce == 1);
    }

    SECTION("Multiple calls return independent vectors") {
        auto ct1 = state.EncryptWithAd(ad, plaintext);
        auto ct2 = state.EncryptWithAd(ad, plaintext);

        // Different nonces produce different ciphertexts
        REQUIRE(ct1 != ct2);
        REQUIRE(state.nonce == 2);
    }
}

TEST_CASE("CipherState - 3-argument buffer overload through SymmetricState", "[cipherstate][overload][private]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    SymmetricState ss(cipher, hash);

    std::string protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
    ss.InitializeSymmetric(std::span(reinterpret_cast<const std::uint8_t*>(protocol_name.data()), protocol_name.size()));

    std::vector<std::uint8_t> input_km(32, 0xBB);
    ss.MixKey(input_km);

    SECTION("EncryptAndHash uses 3-argument private method") {
        std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
        std::vector<std::uint8_t> dst;

        auto old_h = ss.h;
        ss.EncryptAndHash(dst, plaintext);

        REQUIRE(dst.size() == plaintext.size() + 16);
        REQUIRE(ss.h != old_h); // Hash is updated
        REQUIRE(ss.cs.nonce == 1);
    }

    SECTION("DecryptAndHash uses 3-argument private method") {
        std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
        std::vector<std::uint8_t> ciphertext;
        ss.EncryptAndHash(ciphertext, plaintext);

        // Create receiving side
        Cipher cipher2(ChaChaPoly);
        Hash hash2(SHA256);
        SymmetricState ss2(cipher2, hash2);
        ss2.InitializeSymmetric(std::span(reinterpret_cast<const std::uint8_t*>(protocol_name.data()), protocol_name.size()));
        ss2.MixKey(input_km);

        std::vector<std::uint8_t> decrypted;
        ss2.DecryptAndHash(decrypted, ciphertext);

        REQUIRE(decrypted == plaintext);
        REQUIRE(ss.h == ss2.h); // Both sides have same hash
    }

    SECTION("Buffer appending works correctly") {
        std::vector<std::uint8_t> plaintext1 = {0x01, 0x02};
        std::vector<std::uint8_t> plaintext2 = {0x03, 0x04};
        std::vector<std::uint8_t> dst;

        ss.EncryptAndHash(dst, plaintext1);
        auto size_after_first = dst.size();
        REQUIRE(size_after_first == plaintext1.size() + 16);

        ss.EncryptAndHash(dst, plaintext2);
        auto size_after_second = dst.size();

        // Second encryption appends to existing buffer
        REQUIRE(size_after_second == size_after_first + plaintext2.size() + 16);
        REQUIRE(ss.cs.nonce == 2);
    }
}

TEST_CASE("CipherState - 2-argument vs 3-argument overload consistency", "[cipherstate][overload][consistency]") {
    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0xCC);

    std::vector<std::uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    std::vector<std::uint8_t> ad = {0xAA, 0xBB, 0xCC};

    SECTION("Both overloads produce identical ciphertexts") {
        // Test 2-argument public overload
        Cipher cipher1(ChaChaPoly);
        CipherState state1(std::move(cipher1), 65535);
        state1.InitializeKey(key);
        auto ct_from_2arg = state1.EncryptWithAd(ad, plaintext);

        // Test 3-argument private overload through SymmetricState
        Cipher cipher2(ChaChaPoly);
        Hash hash(SHA256);
        SymmetricState ss(cipher2, hash);
        std::string protocol_name = "Test";
        ss.InitializeSymmetric(std::span(reinterpret_cast<const std::uint8_t*>(protocol_name.data()), protocol_name.size()));
        ss.cs.InitializeKey(key);
        ss.cs.SetNonce(0);

        std::vector<std::uint8_t> ct_from_3arg;
        ss.EncryptAndHash(ct_from_3arg, plaintext);

        // Both should have same nonce after encryption
        REQUIRE(state1.nonce == 1);
        REQUIRE(ss.cs.nonce == 1);
    }

    SECTION("Both overloads handle empty plaintext identically") {
        std::vector<std::uint8_t> empty_plaintext{};

        Cipher cipher1(ChaChaPoly);
        CipherState state1(std::move(cipher1), 65535);
        state1.InitializeKey(key);
        auto ct1 = state1.EncryptWithAd(ad, empty_plaintext);

        Cipher cipher2(ChaChaPoly);
        Hash hash(SHA256);
        SymmetricState ss(cipher2, hash);
        std::string protocol_name = "Test";
        ss.InitializeSymmetric(std::span(reinterpret_cast<const std::uint8_t*>(protocol_name.data()), protocol_name.size()));
        ss.cs.InitializeKey(key);
        ss.cs.SetNonce(0);

        std::vector<std::uint8_t> ct2;
        ss.EncryptAndHash(ct2, empty_plaintext);

        // Both produce only auth tag (16 bytes) for empty plaintext
        REQUIRE(ct1.size() == 16);
    }

    SECTION("Decryption works across both overloads") {
        // Encrypt with 2-argument overload
        Cipher cipher1(ChaChaPoly);
        CipherState state1(std::move(cipher1), 65535);
        state1.InitializeKey(key);
        auto ciphertext = state1.EncryptWithAd(ad, plaintext);

        // Decrypt with 2-argument overload (different CipherState instance)
        Cipher cipher2(ChaChaPoly);
        CipherState state2(std::move(cipher2), 65535);
        state2.InitializeKey(key);

        auto decrypted = state2.DecryptWithAd(ad, ciphertext);

        REQUIRE(decrypted == plaintext);
    }
}

TEST_CASE("CipherState - 2-argument overload without key", "[cipherstate][overload][plaintext]") {
    Cipher cipher(ChaChaPoly);
    CipherState state(std::move(cipher), 65535);

    // Don't set a key
    REQUIRE_FALSE(state.HasKey());

    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> ad{};

    SECTION("EncryptWithAd returns plaintext when no key") {
        auto result = state.EncryptWithAd(ad, plaintext);
        REQUIRE(result == plaintext);
        REQUIRE(state.nonce == 0); // Nonce doesn't increment without key
    }

    SECTION("DecryptWithAd returns ciphertext when no key") {
        auto result = state.DecryptWithAd(ad, plaintext);
        REQUIRE(result == plaintext);
        REQUIRE(state.nonce == 0);
    }
}

TEST_CASE("CipherState - 3-argument buffer overload appends correctly", "[cipherstate][overload][buffer]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);
    SymmetricState ss(cipher, hash);

    std::string protocol_name = "Noise";
    ss.InitializeSymmetric(std::span(reinterpret_cast<const std::uint8_t*>(protocol_name.data()), protocol_name.size()));

    std::vector<std::uint8_t> input_km(32, 0xDD);
    ss.MixKey(input_km);

    SECTION("Appends to non-empty buffer") {
        std::vector<std::uint8_t> dst = {0xFF, 0xFE, 0xFD}; // Pre-existing data
        std::vector<std::uint8_t> plaintext = {0x01, 0x02};

        ss.EncryptAndHash(dst, plaintext);

        // Should have: 3 pre-existing bytes + 2 plaintext bytes + 16 auth tag bytes
        REQUIRE(dst.size() == 3 + 2 + 16);

        // First 3 bytes should be unchanged
        REQUIRE(dst[0] == 0xFF);
        REQUIRE(dst[1] == 0xFE);
        REQUIRE(dst[2] == 0xFD);
    }

    SECTION("Multiple appends accumulate") {
        std::vector<std::uint8_t> dst;
        std::vector<std::uint8_t> msg1 = {0x01};
        std::vector<std::uint8_t> msg2 = {0x02, 0x03};
        std::vector<std::uint8_t> msg3 = {0x04, 0x05, 0x06};

        ss.EncryptAndHash(dst, msg1);
        auto size1 = dst.size();
        REQUIRE(size1 == 1 + 16); // 1 byte + auth tag

        ss.EncryptAndHash(dst, msg2);
        auto size2 = dst.size();
        REQUIRE(size2 == size1 + 2 + 16); // previous + 2 bytes + auth tag

        ss.EncryptAndHash(dst, msg3);
        auto size3 = dst.size();
        REQUIRE(size3 == size2 + 3 + 16); // previous + 3 bytes + auth tag

        REQUIRE(ss.cs.nonce == 3);
    }
}

TEST_CASE("CipherState - Both overloads respect nonce", "[cipherstate][overload][nonce]") {
    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0xEE);

    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> ad{};

    SECTION("2-argument overload increments nonce") {
        Cipher cipher(ChaChaPoly);
        CipherState state(std::move(cipher), 65535);
        state.InitializeKey(key);

        REQUIRE(state.nonce == 0);
        auto ct1 = state.EncryptWithAd(ad, plaintext);
        REQUIRE(state.nonce == 1);
        auto ct2 = state.EncryptWithAd(ad, plaintext);
        REQUIRE(state.nonce == 2);
        auto ct3 = state.EncryptWithAd(ad, plaintext);
        REQUIRE(state.nonce == 3);

        // All ciphertexts should be different due to different nonces
        REQUIRE(ct1 != ct2);
        REQUIRE(ct2 != ct3);
        REQUIRE(ct1 != ct3);
    }

    SECTION("3-argument overload increments nonce") {
        Cipher cipher(ChaChaPoly);
        Hash hash(SHA256);
        SymmetricState ss(cipher, hash);

        std::string protocol_name = "Test";
        ss.InitializeSymmetric(std::span(reinterpret_cast<const std::uint8_t*>(protocol_name.data()), protocol_name.size()));
        ss.MixKey(std::vector<std::uint8_t>(32, 0xAA));

        REQUIRE(ss.cs.nonce == 0);

        std::vector<std::uint8_t> dst;
        ss.EncryptAndHash(dst, plaintext);
        REQUIRE(ss.cs.nonce == 1);

        ss.EncryptAndHash(dst, plaintext);
        REQUIRE(ss.cs.nonce == 2);

        ss.EncryptAndHash(dst, plaintext);
        REQUIRE(ss.cs.nonce == 3);
    }
}

// Main function for Catch2
int main(int argc, char* argv[]) {
    // Disable all logging during tests for clean output
    Noise::DisableAllLogging();
    return Catch::Session().run(argc, argv);
}

