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
// Cipher Module Tests using Catch2 v3
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>

import noise;

using namespace Noise;

TEST_CASE("Cipher - Default Constructor", "[cipher][constructor]") {
    Cipher cipher;
    REQUIRE(cipher.String() == ChaChaPoly);
}

TEST_CASE("Cipher - Explicit Constructor with ChaCha20-Poly1305 string", "[cipher][constructor]") {
    Cipher cipher(ChaChaPoly);
    REQUIRE(cipher.String() == ChaChaPoly);
}

TEST_CASE("Cipher - Explicit Constructor with AES-GCM string", "[cipher][constructor]") {
    Cipher cipher(AESGCM);
    REQUIRE(cipher.String() == AESGCM);
}

TEST_CASE("Cipher - Constructor from CipherAlgo enum", "[cipher][constructor][enum]") {
    SECTION("ChaCha20-Poly1305 from enum") {
        Cipher cipher(CipherAlgo::ChaChaPoly);
        REQUIRE(cipher.String() == ChaChaPoly);
    }

    SECTION("AES-256-GCM from enum") {
        Cipher cipher(CipherAlgo::AESGCM);
        REQUIRE(cipher.String() == AESGCM);
    }
}

TEST_CASE("Cipher - Copy Constructor", "[cipher][constructor][copy]") {
    Cipher cipher1(ChaChaPoly);
    Cipher cipher2(cipher1);

    REQUIRE(cipher1.String() == cipher2.String());
    REQUIRE(cipher2.String() == ChaChaPoly);
}

TEST_CASE("Cipher - Move Constructor", "[cipher][constructor][move]") {
    Cipher cipher1(AESGCM);
    Cipher cipher2(std::move(cipher1));

    REQUIRE(cipher2.String() == AESGCM);
}

TEST_CASE("Cipher - Encrypt and Decrypt with ChaCha20-Poly1305", "[cipher][encryption][chacha]") {
    Cipher cipher(ChaChaPoly);

    // Create a 32-byte key
    std::array<std::uint8_t, 32> key{};
    for (size_t i = 0; i < 32; ++i) {
        key[i] = static_cast<std::uint8_t>(i);
    }

    // Plaintext
    std::vector<std::uint8_t> plaintext = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64  // "Hello World"
    };

    // Empty AD
    std::vector<std::uint8_t> ad{};

    // Nonce
    std::uint64_t nonce = 0;

    SECTION("Encryption produces ciphertext") {
        std::vector<std::uint8_t> ciphertext;
        cipher.Encrypt(ciphertext, key, nonce, ad, plaintext);

        // Ciphertext should be longer than plaintext (includes authentication tag)
        REQUIRE(ciphertext.size() == plaintext.size() + 16);  // ChaCha20-Poly1305 adds 16-byte tag

        // Ciphertext should be different from plaintext
        REQUIRE(ciphertext != plaintext);
    }

    SECTION("Encrypt then Decrypt recovers original plaintext") {
        std::vector<std::uint8_t> ciphertext;
        cipher.Encrypt(ciphertext, key, nonce, ad, plaintext);
        std::vector<std::uint8_t> decrypted;
        cipher.Decrypt(decrypted, key, nonce, ad, ciphertext);

        REQUIRE(decrypted == plaintext);
    }
}

TEST_CASE("Cipher - Encrypt and Decrypt with AES-GCM", "[cipher][encryption][aesgcm]") {
    Cipher cipher(AESGCM);

    // Create a 32-byte key
    std::array<std::uint8_t, 32> key{};
    for (size_t i = 0; i < 32; ++i) {
        key[i] = static_cast<std::uint8_t>(i * 2);
    }

    // Plaintext
    std::vector<std::uint8_t> plaintext = {
        0x54, 0x65, 0x73, 0x74, 0x20, 0x44, 0x61, 0x74, 0x61  // "Test Data"
    };

    // Empty AD
    std::vector<std::uint8_t> ad{};

    // Nonce
    std::uint64_t nonce = 42;

    SECTION("Encryption produces ciphertext") {
        std::vector<std::uint8_t> ciphertext;
        cipher.Encrypt(ciphertext, key, nonce, ad, plaintext);

        // Ciphertext should be longer than plaintext
        REQUIRE(ciphertext.size() == plaintext.size() + 16);  // AES-GCM adds 16-byte tag

        // Ciphertext should be different from plaintext
        REQUIRE(ciphertext != plaintext);
    }

    SECTION("Encrypt then Decrypt recovers original plaintext") {
        std::vector<std::uint8_t> ciphertext;
        cipher.Encrypt(ciphertext, key, nonce, ad, plaintext);
        std::vector<std::uint8_t> decrypted;
        cipher.Decrypt(decrypted, key, nonce, ad, ciphertext);

        REQUIRE(decrypted == plaintext);
    }
}

TEST_CASE("Cipher - Encryption with Associated Data", "[cipher][encryption][ad]") {
    Cipher cipher(ChaChaPoly);

    std::array<std::uint8_t, 32> key{};
    for (size_t i = 0; i < 32; ++i) {
        key[i] = static_cast<std::uint8_t>(i + 100);
    }

    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<std::uint8_t> ad = {0xAA, 0xBB, 0xCC, 0xDD};  // Associated data
    std::uint64_t nonce = 1;

    SECTION("Encryption with AD succeeds") {
        std::vector<std::uint8_t> ciphertext;
        cipher.Encrypt(ciphertext, key, nonce, ad, plaintext);
        std::vector<std::uint8_t> decrypted;
        cipher.Decrypt(decrypted, key, nonce, ad, ciphertext);

        REQUIRE(decrypted == plaintext);
    }

    SECTION("Decryption with wrong AD fails") {
        std::vector<std::uint8_t> ciphertext;
        cipher.Encrypt(ciphertext, key, nonce, ad, plaintext);

        std::vector<std::uint8_t> wrong_ad = {0xFF, 0xEE, 0xDD, 0xCC};

        // Decryption with wrong AD should throw (Botan throws on auth failure)
        std::vector<std::uint8_t> result;
        REQUIRE_THROWS(cipher.Decrypt(result, key, nonce, wrong_ad, ciphertext));
    }
}

TEST_CASE("Cipher - Different nonces produce different ciphertexts", "[cipher][nonce]") {
    Cipher cipher(ChaChaPoly);

    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0x42);


    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<std::uint8_t> ad{};

    std::vector<std::uint8_t> ciphertext1;
    cipher.Encrypt(ciphertext1, key, 0, ad, plaintext);
    std::vector<std::uint8_t> ciphertext2;
    cipher.Encrypt(ciphertext2, key, 1, ad, plaintext);

    // Same plaintext with different nonces should produce different ciphertexts
    REQUIRE(ciphertext1 != ciphertext2);
}

TEST_CASE("Cipher - Different keys produce different ciphertexts", "[cipher][key]") {
    Cipher cipher(ChaChaPoly);

    std::array<std::uint8_t, 32> key1{};
    std::ranges::fill(key1, 0x11);

    std::array<std::uint8_t, 32> key2{};
    std::ranges::fill(key2, 0x22);

    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<std::uint8_t> ad{};
    std::uint64_t nonce = 0;

    std::vector<std::uint8_t> ciphertext1;
    cipher.Encrypt(ciphertext1, key1, nonce, ad, plaintext);
    std::vector<std::uint8_t> ciphertext2;
    cipher.Encrypt(ciphertext2, key2, nonce, ad, plaintext);

    // Same plaintext with different keys should produce different ciphertexts
    REQUIRE(ciphertext1 != ciphertext2);
}


TEST_CASE("Cipher - Reset clears state", "[cipher][reset]") {
    Cipher cipher(ChaChaPoly);

    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0x55);

    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> ad{};

    SECTION("Reset after encryption works correctly") {
        // Encrypt something
        std::vector<std::uint8_t> ciphertext;
        cipher.Encrypt(ciphertext, key, 0, ad, plaintext);

        // Reset should not throw
        REQUIRE_NOTHROW(cipher.Reset());

        // After reset, encryption should still work
        std::vector<std::uint8_t> ciphertext2;
        cipher.Encrypt(ciphertext2, key, 0, ad, plaintext);

        // Should produce the same result (same key, nonce, plaintext)
        REQUIRE(ciphertext == ciphertext2);
    }

    SECTION("Reset clears internal state completely") {
        // Do one encryption
        std::vector<std::uint8_t> ciphertext1;
        cipher.Encrypt(ciphertext1, key, 0, ad, plaintext);

        // Reset
        cipher.Reset();

        // Encrypt again with different nonce
        std::vector<std::uint8_t> ciphertext2;
        cipher.Encrypt(ciphertext2, key, 1, ad, plaintext);

        // Should be different (different nonce)
        REQUIRE(ciphertext1 != ciphertext2);

        // Both should decrypt correctly
        std::vector<std::uint8_t> decrypted1;
        cipher.Decrypt(decrypted1, key, 0, ad, ciphertext1);
        std::vector<std::uint8_t> decrypted2;
        cipher.Decrypt(decrypted2, key, 1, ad, ciphertext2);

        REQUIRE(decrypted1 == plaintext);
        REQUIRE(decrypted2 == plaintext);
    }

    SECTION("Multiple resets don't break cipher") {
        cipher.Reset();
        cipher.Reset();
        cipher.Reset();

        // Should still work after multiple resets
        std::vector<std::uint8_t> ciphertext;
        cipher.Encrypt(ciphertext, key, 0, ad, plaintext);
        std::vector<std::uint8_t> decrypted;
        cipher.Decrypt(decrypted, key, 0, ad, ciphertext);

        REQUIRE(decrypted == plaintext);
    }
}

TEST_CASE("Cipher - Empty plaintext", "[cipher][edge-case]") {
    Cipher cipher(ChaChaPoly);

    std::array<std::uint8_t, 32> key{};
    std::vector<std::uint8_t> plaintext{};  // Empty
    std::vector<std::uint8_t> ad{};
    std::uint64_t nonce = 0;

    std::vector<std::uint8_t> ciphertext;
    cipher.Encrypt(ciphertext, key, nonce, ad, plaintext);

    // Ciphertext should only contain the authentication tag (16 bytes)
    REQUIRE(ciphertext.size() == 16);

    // Decrypt should recover empty plaintext
    std::vector<std::uint8_t> decrypted;
    cipher.Decrypt(decrypted, key, nonce, ad, ciphertext);
    REQUIRE(decrypted.empty());
}

TEST_CASE("Cipher - Large plaintext", "[cipher][edge-case]") {
    Cipher cipher(ChaChaPoly);

    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0x77);

    // Create a large plaintext (1MB)
    std::vector<std::uint8_t> plaintext(1024 * 1024);
    for (size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<std::uint8_t>(i % 256);
    }

    std::vector<std::uint8_t> ad{};
    std::uint64_t nonce = 0;

    std::vector<std::uint8_t> ciphertext;
    cipher.Encrypt(ciphertext, key, nonce, ad, plaintext);
    std::vector<std::uint8_t> decrypted;
    cipher.Decrypt(decrypted, key, nonce, ad, ciphertext);

    REQUIRE(decrypted == plaintext);
}

TEST_CASE("Cipher - String method returns correct algorithm name", "[cipher][utility]") {
    SECTION("ChaCha20-Poly1305") {
        Cipher cipher(ChaChaPoly);
        REQUIRE(cipher.String() == "ChaChaPoly");
    }

    SECTION("AES-256-GCM") {
        Cipher cipher(AESGCM);
        REQUIRE(cipher.String() == "AESGCM");
    }
}

TEST_CASE("Cipher - GetAeadTagSize returns correct tag size", "[cipher][utility]") {
    SECTION("ChaCha20-Poly1305 tag size") {
        Cipher cipher(CipherAlgo::ChaChaPoly);
        REQUIRE(cipher.GetAeadTagSize() == 16);
    }

    SECTION("AES-256-GCM tag size") {
        Cipher cipher(CipherAlgo::AESGCM);
        REQUIRE(cipher.GetAeadTagSize() == 16);
    }
}

TEST_CASE("Cipher - Decryption with wrong key fails", "[cipher][security][edge-case]") {
    Cipher cipher(ChaChaPoly);

    std::array<std::uint8_t, 32> key1{};
    std::ranges::fill(key1, 0x11);

    std::array<std::uint8_t, 32> key2{};
    std::ranges::fill(key2, 0x22);

    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<std::uint8_t> ad{};
    std::uint64_t nonce = 0;

    std::vector<std::uint8_t> ciphertext;
    cipher.Encrypt(ciphertext, key1, nonce, ad, plaintext);

    // Decryption with wrong key should throw
    std::vector<std::uint8_t> result;
    REQUIRE_THROWS(cipher.Decrypt(result, key2, nonce, ad, ciphertext));
}

TEST_CASE("Cipher - Decryption with wrong nonce fails", "[cipher][security][edge-case]") {
    Cipher cipher(ChaChaPoly);

    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0x33);

    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<std::uint8_t> ad{};

    std::vector<std::uint8_t> ciphertext;
    cipher.Encrypt(ciphertext, key, 0, ad, plaintext);

    // Decryption with wrong nonce should throw
    std::vector<std::uint8_t> result;
    REQUIRE_THROWS(cipher.Decrypt(result, key, 1, ad, ciphertext));
}

TEST_CASE("Cipher - Tampered ciphertext fails authentication", "[cipher][security][edge-case]") {
    Cipher cipher(ChaChaPoly);

    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0x44);

    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<std::uint8_t> ad{};
    std::uint64_t nonce = 0;

    std::vector<std::uint8_t> ciphertext;
    cipher.Encrypt(ciphertext, key, nonce, ad, plaintext);

    // Tamper with the ciphertext
    if (!ciphertext.empty()) {
        ciphertext[0] ^= 0xFF;
    }

    // Decryption of tampered ciphertext should throw
    std::vector<std::uint8_t> result;
    REQUIRE_THROWS(cipher.Decrypt(result, key, nonce, ad, ciphertext));
}

// ============================================================================
// Buffer Overload Tests (Direct Buffer Encryption)
// ============================================================================

TEST_CASE("Cipher - Encrypt with destination buffer - empty dst", "[cipher][buffer-overload]") {
    Cipher cipher;
    std::vector<std::uint8_t> dst;
    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0x01);
    std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};
    std::vector<std::uint8_t> ad;

    cipher.Encrypt(dst, key, 0, ad, plaintext);

    REQUIRE(dst.size() == plaintext.size() + 16);  // plaintext + AEAD tag
}

TEST_CASE("Cipher - Encrypt with destination buffer - pre-populated dst", "[cipher][buffer-overload]") {
    Cipher cipher;
    std::vector<std::uint8_t> dst = {0xAA, 0xBB, 0xCC};  // Pre-existing data
    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0x01);
    std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};
    std::vector<std::uint8_t> ad;

    cipher.Encrypt(dst, key, 0, ad, plaintext);

    REQUIRE(dst.size() == 3 + plaintext.size() + 16);  // pre-existing + plaintext + tag
    REQUIRE(dst[0] == 0xAA);  // Pre-existing data preserved
    REQUIRE(dst[1] == 0xBB);
    REQUIRE(dst[2] == 0xCC);
}

TEST_CASE("Cipher - Decrypt with destination buffer - empty dst", "[cipher][buffer-overload]") {
    Cipher cipher;
    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0x01);
    std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};
    std::vector<std::uint8_t> ad;

    std::vector<std::uint8_t> ciphertext;
    cipher.Encrypt(ciphertext, key, 0, ad, plaintext);

    std::vector<std::uint8_t> dst;
    cipher.Decrypt(dst, key, 0, ad, ciphertext);

    REQUIRE(dst == plaintext);
}

TEST_CASE("Cipher - Decrypt with destination buffer - pre-populated dst", "[cipher][buffer-overload]") {
    Cipher cipher;
    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0x01);
    std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};
    std::vector<std::uint8_t> ad;

    std::vector<std::uint8_t> ciphertext;
    cipher.Encrypt(ciphertext, key, 0, ad, plaintext);

    std::vector<std::uint8_t> dst = {0xAA, 0xBB, 0xCC};  // Pre-existing data
    cipher.Decrypt(dst, key, 0, ad, ciphertext);

    REQUIRE(dst.size() == 3 + plaintext.size());
    REQUIRE(dst[0] == 0xAA);  // Pre-existing preserved
    REQUIRE(dst[1] == 0xBB);
    REQUIRE(dst[2] == 0xCC);
    REQUIRE(std::vector<std::uint8_t>(dst.begin() + 3, dst.end()) == plaintext);
}

TEST_CASE("Cipher - Encrypt/Decrypt roundtrip with AD", "[cipher][buffer-overload]") {
    Cipher cipher;
    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0x01);
    std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};
    std::vector<std::uint8_t> ad = {0x01, 0x02};

    // Encrypt with buffer overload
    std::vector<std::uint8_t> ciphertext;
    cipher.Encrypt(ciphertext, key, 42, ad, plaintext);

    // Decrypt with buffer overload
    std::vector<std::uint8_t> decrypted;
    cipher.Decrypt(decrypted, key, 42, ad, ciphertext);

    REQUIRE(decrypted == plaintext);
}

TEST_CASE("Cipher - Multiple encrypts to same destination buffer", "[cipher][buffer-overload]") {
    Cipher cipher;
    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0x01);
    std::vector<std::uint8_t> plaintext1 = {'A', 'B', 'C'};
    std::vector<std::uint8_t> plaintext2 = {'D', 'E', 'F'};
    std::vector<std::uint8_t> ad;

    std::vector<std::uint8_t> dst;
    cipher.Encrypt(dst, key, 0, ad, plaintext1);
    const std::size_t sizeAfterFirst = dst.size();

    cipher.Encrypt(dst, key, 1, ad, plaintext2);

    REQUIRE(dst.size() == sizeAfterFirst + plaintext2.size() + 16);
}

// ============================================================================
// Error-model tests
// ============================================================================

TEST_CASE("Cipher - Decrypt failure leaves dst unchanged", "[cipher][security][error]") {
    Cipher cipher(ChaChaPoly);
    std::array<std::uint8_t, 32> key{};
    std::ranges::fill(key, 0x42);
    const std::vector<std::uint8_t> plaintext = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    const std::vector<std::uint8_t> ad = {0xA0};
    const std::vector<std::uint8_t> prefix = {0xAA, 0xBB, 0xCC};

    std::vector<std::uint8_t> ciphertext;
    cipher.Encrypt(ciphertext, key, 7, ad, plaintext);

    SECTION("Tampered ciphertext") {
        auto tampered = ciphertext;
        tampered.back() ^= 0x80;  // flip a tag bit

        std::vector<std::uint8_t> dst = prefix;
        REQUIRE_THROWS_AS(cipher.Decrypt(dst, key, 7, ad, tampered), DecryptionError);
        REQUIRE(dst == prefix);
    }

    SECTION("Ciphertext shorter than the tag") {
        const std::vector<std::uint8_t> shortCt(ciphertext.begin(), ciphertext.begin() + 5);

        std::vector<std::uint8_t> dst = prefix;
        REQUIRE_THROWS_AS(cipher.Decrypt(dst, key, 7, ad, shortCt), DecryptionError);
        REQUIRE(dst == prefix);
    }

    SECTION("The untouched ciphertext still decrypts into the same dst") {
        std::vector<std::uint8_t> dst = prefix;
        cipher.Decrypt(dst, key, 7, ad, ciphertext);
        REQUIRE(dst.size() == prefix.size() + plaintext.size());
        REQUIRE(std::vector<std::uint8_t>(dst.begin() + 3, dst.end()) == plaintext);
    }
}

TEST_CASE("Cipher - Only Noise cipher names are accepted", "[cipher][constructor][allowlist]") {
    SECTION("Botan spellings and other cases are rejected before any Botan call") {
        REQUIRE_THROWS_AS(Cipher{"AES-256/GCM"}, ProtocolNotSupportedError);
        REQUIRE_THROWS_AS(Cipher{"chachapoly"}, ProtocolNotSupportedError);
    }

    SECTION("The two Noise names construct and report themselves") {
        REQUIRE(Cipher{"ChaChaPoly"}.String() == ChaChaPoly);
        REQUIRE(Cipher{"AESGCM"}.String() == AESGCM);
    }

    SECTION("A copy keeps the algorithm and produces identical ciphertext") {
        for (const std::string_view name : {ChaChaPoly, AESGCM}) {
            INFO("cipher: " << name);
            const Cipher original{name};
            const Cipher copy{original};
            REQUIRE(copy.String() == original.String());

            const std::vector<std::uint8_t> key(32, 0x11);
            const std::vector<std::uint8_t> ad{0x01, 0x02};
            const std::vector<std::uint8_t> plaintext(40, 0x5a);
            std::vector<std::uint8_t> ct1, ct2;
            original.Encrypt(ct1, key, 7, ad, plaintext);
            copy.Encrypt(ct2, key, 7, ad, plaintext);
            REQUIRE(ct1 == ct2);
            REQUIRE(ct1.size() == plaintext.size() + copy.GetAeadTagSize());
        }
    }
}

TEST_CASE("Cipher - in-place Encrypt/Decrypt match at every size and offset", "[cipher][inplace]") {
    // Guard for the in-place AEAD path: the bytes appended after a prefix equal the bytes produced
    // into an empty vector, the prefix is untouched, decrypt round-trips into a prefixed vector,
    // and a tag failure leaves the prefixed vector exactly as it was.
    constexpr std::array<std::size_t, 8> sizes{0, 1, 15, 16, 17, 64, 1024, 65519};
    const std::array<std::vector<std::uint8_t>, 2> prefixes{
        std::vector<std::uint8_t>{},
        std::vector<std::uint8_t>{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6}
    };
    std::array<std::uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i * 7 + 1);
    const std::vector<std::uint8_t> ad{'n', 'o', 'i', 's', 'e', '-', 'a', 'd'};
    constexpr std::uint64_t nonce = 5;

    for (const auto name : {ChaChaPoly, AESGCM}) {
        INFO(name);
        const Cipher cipher{name};
        REQUIRE(cipher.GetAeadTagSize() == 16);

        for (const auto size : sizes) {
            INFO("plaintext size " << size);
            std::vector<std::uint8_t> plaintext(size);
            for (std::size_t i = 0; i < size; ++i) plaintext[i] = static_cast<std::uint8_t>((i * 31 + size) & 0xFF);

            std::vector<std::uint8_t> reference;
            cipher.Encrypt(reference, key, nonce, ad, plaintext);
            CHECK(reference.size() == size + 16);

            for (const auto& prefix : prefixes) {
                INFO("prefix size " << prefix.size());

                // Encrypt appended after the prefix
                auto dst = prefix;
                cipher.Encrypt(dst, key, nonce, ad, plaintext);
                CHECK(dst.size() == prefix.size() + size + 16);
                CHECK(std::ranges::equal(std::span{dst}.first(prefix.size()), prefix));
                CHECK(std::ranges::equal(std::span{dst}.subspan(prefix.size()), reference));

                // Decrypt appended after the prefix
                auto out = prefix;
                cipher.Decrypt(out, key, nonce, ad, reference);
                CHECK(out.size() == prefix.size() + size);
                CHECK(std::ranges::equal(std::span{out}.first(prefix.size()), prefix));
                CHECK(std::ranges::equal(std::span{out}.subspan(prefix.size()), plaintext));

                // One-bit tag flip: DecryptionError, and the prefixed vector is exactly as it was
                auto tampered = reference;
                tampered.back() ^= 0x01;
                auto scratch = prefix;
                CHECK_THROWS_AS(cipher.Decrypt(scratch, key, nonce, ad, tampered), DecryptionError);
                CHECK(scratch == prefix);
            }
        }
    }
}

// Guard: Cipher re-keys its AEAD only when the key changes. The cache must be
// invisible; this case pins exactly the sequences the cache could get wrong (K1, K2, K1;
// encrypt then decrypt with another key; copies; moves; Reset; a rejected key).
TEST_CASE("Cipher - re-keys exactly when the key changes", "[cipher][key][cache]") {
    for (const auto name : {ChaChaPoly, AESGCM}) {
        INFO("cipher " << name);
        std::array<std::uint8_t, 32> k1{};
        std::ranges::fill(k1, 0x11);
        std::array<std::uint8_t, 32> k2{};
        std::ranges::fill(k2, 0x22);
        const std::vector<std::uint8_t> pt = {0x4e, 0x6f, 0x69, 0x73, 0x65, 0x50, 0x51, 0x43};
        const std::vector<std::uint8_t> ad = {0xad, 0x01};
        const std::uint64_t nonce = 7;

        // Reference ciphertexts from fresh ciphers that have only ever seen one key
        const auto fresh = [&](const std::span<const std::uint8_t> k) {
            const Cipher c(name);
            std::vector<std::uint8_t> out;
            c.Encrypt(out, k, nonce, ad, pt);
            return out;
        };
        const auto c1 = fresh(k1);
        const auto c2 = fresh(k2);
        REQUIRE(c1 != c2);

        Cipher cipher(name);
        std::vector<std::uint8_t> out;

        // K1, K2, K1 on one object: each matches its fresh reference
        cipher.Encrypt(out, k1, nonce, ad, pt);
        CHECK(out == c1);
        out.clear();
        cipher.Encrypt(out, k2, nonce, ad, pt);
        CHECK(out == c2);
        out.clear();
        cipher.Encrypt(out, k1, nonce, ad, pt);
        CHECK(out == c1);
        out.clear();

        // Decrypt with K2 right after encrypting with K1
        cipher.Decrypt(out, k2, nonce, ad, c2);
        CHECK(out == pt);
        out.clear();
        // Decrypt with K1 twice in a row, then K2 on the encrypt side
        cipher.Decrypt(out, k1, nonce, ad, c1);
        CHECK(out == pt);
        out.clear();
        cipher.Decrypt(out, k1, nonce, ad, c1);
        CHECK(out == pt);
        out.clear();
        cipher.Encrypt(out, k2, nonce, ad, pt);
        CHECK(out == c2);
        out.clear();

        // A copy of a used cipher (last key K2), given K1
        Cipher copy(cipher);
        copy.Encrypt(out, k1, nonce, ad, pt);
        CHECK(out == c1);
        out.clear();
        copy.Decrypt(out, k2, nonce, ad, c2);
        CHECK(out == pt);
        out.clear();
        // The original is unaffected by the copy
        cipher.Encrypt(out, k2, nonce, ad, pt);
        CHECK(out == c2);
        out.clear();
        cipher.Encrypt(out, k1, nonce, ad, pt);
        CHECK(out == c1);
        out.clear();

        // A moved-to cipher (the source last used K2)
        Cipher moved(std::move(copy));
        moved.Encrypt(out, k2, nonce, ad, pt);
        CHECK(out == c2);
        out.clear();
        moved.Encrypt(out, k1, nonce, ad, pt);
        CHECK(out == c1);
        out.clear();

        // After Reset(), K1 still works
        cipher.Reset();
        cipher.Encrypt(out, k1, nonce, ad, pt);
        CHECK(out == c1);
        out.clear();
        cipher.Decrypt(out, k1, nonce, ad, c1);
        CHECK(out == pt);
        out.clear();

        // A wrong-length key is a NoiseError and leaves dst unchanged
        const std::vector<std::uint8_t> shortKey(31, 0x33);
        const std::vector<std::uint8_t> longKey(33, 0x33);
        std::vector<std::uint8_t> dst = {0xde, 0xad};
        const auto before = dst;
        CHECK_THROWS_AS(cipher.Encrypt(dst, shortKey, nonce, ad, pt), NoiseError);
        CHECK(dst == before);
        CHECK_THROWS_AS(cipher.Encrypt(dst, longKey, nonce, ad, pt), NoiseError);
        CHECK(dst == before);
        CHECK_THROWS_AS(cipher.Decrypt(dst, shortKey, nonce, ad, c1), NoiseError);
        CHECK(dst == before);
        // and the object still encrypts correctly with K1 and K2 afterwards
        cipher.Encrypt(out, k1, nonce, ad, pt);
        CHECK(out == c1);
        out.clear();
        cipher.Encrypt(out, k2, nonce, ad, pt);
        CHECK(out == c2);
    }
}

// Main function for Catch2
int main(int argc, char* argv[]) {
    // Disable all logging during tests for clean output
    Noise::DisableAllLogging();
    return Catch::Session().run(argc, argv);
}

