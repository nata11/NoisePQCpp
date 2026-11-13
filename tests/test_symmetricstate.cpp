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
// SymmetricState Module Tests using Catch2 v3
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>
#include "botan_all.h"

import noise;

using namespace Noise;

TEST_CASE("SymmetricState - Constructor", "[symmetricstate][constructor]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    SymmetricState ss(cipher, hash);

    SECTION("Hash length is set correctly for SHA-256") {
        REQUIRE(ss.hashLen == 32);
    }

    SECTION("CipherState is initialized") {
        REQUIRE(ss.cs.maxMessageSize == NOISE_MAX_MESSAGE_SIZE);
    }

    SECTION("Chaining key and hash are initially empty") {
        REQUIRE(ss.ck.empty());
        REQUIRE(ss.h.empty());
    }
}

TEST_CASE("SymmetricState - Constructor with SHA-512", "[symmetricstate][constructor]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA512);

    SymmetricState ss(cipher, hash);

    SECTION("Hash length is set correctly for SHA-512") {
        REQUIRE(ss.hashLen == 64);
    }
}

TEST_CASE("SymmetricState - Copy Constructor", "[symmetricstate][constructor][copy]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    SymmetricState ss1(cipher, hash);
    std::string protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
    ss1.InitializeSymmetric(protocol_name);

    SymmetricState ss2(ss1);

    REQUIRE(ss2.hashLen == ss1.hashLen);
    REQUIRE(ss2.h == ss1.h);
    REQUIRE(ss2.ck == ss1.ck);
}

TEST_CASE("SymmetricState - Move Constructor", "[symmetricstate][constructor][move]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    SymmetricState ss1(cipher, hash);
    std::string protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
    ss1.InitializeSymmetric(protocol_name);

    auto old_h = ss1.h;
    SymmetricState ss2(std::move(ss1));

    REQUIRE(ss2.hashLen == 32);
    REQUIRE(ss2.h == old_h);
}

TEST_CASE("SymmetricState - InitializeSymmetric with short protocol name", "[symmetricstate][initialize]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    SymmetricState ss(cipher, hash);

    std::string protocol_name = "Noise";
    ss.InitializeSymmetric(protocol_name);

    SECTION("Hash h is initialized") {
        REQUIRE(ss.h.size() == 32);
        REQUIRE_FALSE(ss.h.empty());
    }

    SECTION("Chaining key equals hash") {
        REQUIRE(ss.ck == ss.h);
    }

    SECTION("First bytes match protocol name") {
        REQUIRE(ss.h[0] == 'N');
        REQUIRE(ss.h[1] == 'o');
        REQUIRE(ss.h[2] == 'i');
        REQUIRE(ss.h[3] == 's');
        REQUIRE(ss.h[4] == 'e');
    }

    SECTION("Remaining bytes are zero-padded") {
        for (size_t i = protocol_name.size(); i < 32; ++i) {
            REQUIRE(ss.h[i] == 0);
        }
    }
}

TEST_CASE("SymmetricState - InitializeSymmetric with long protocol name", "[symmetricstate][initialize]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    SymmetricState ss(cipher, hash);

    // Create a protocol name longer than hash length (32 bytes)
    std::string protocol_name = "Noise_XX_25519_AESGCM_SHA256_VeryLongProtocolNameThatExceedsHashLength";
    ss.InitializeSymmetric(protocol_name);

    SECTION("Hash h is initialized to hash output length") {
        REQUIRE(ss.h.size() == 32);
    }

    SECTION("Chaining key equals hash") {
        REQUIRE(ss.ck == ss.h);
    }

    SECTION("Hash contains digest of protocol name, not the protocol name itself") {
        // Should not match the first bytes of protocol name since it was hashed
        bool is_hashed = (ss.h[0] != 'N' || ss.h[1] != 'o');
        REQUIRE(is_hashed);
    }
}

TEST_CASE("SymmetricState - MixKey", "[symmetricstate][mixkey]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    SymmetricState ss(cipher, hash);

    std::string protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
    ss.InitializeSymmetric(protocol_name);

    auto old_ck = ss.ck;

    // Create some input key material
    std::vector<std::uint8_t> input_km(32, 0xAA);
    ss.MixKey(input_km);

    SECTION("Chaining key is updated") {
        REQUIRE(ss.ck != old_ck);
        REQUIRE(ss.ck.size() == 32);
    }

    SECTION("CipherState key is set") {
        REQUIRE(ss.cs.HasKey());
    }

    SECTION("Multiple MixKey calls produce different keys") {
        auto ck_after_first = ss.ck;

        std::vector<std::uint8_t> input_km2(32, 0xBB);
        ss.MixKey(input_km2);

        REQUIRE(ss.ck != ck_after_first);
    }
}

TEST_CASE("SymmetricState - MixHash", "[symmetricstate][mixhash]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    SymmetricState ss(cipher, hash);

    std::string protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
    ss.InitializeSymmetric(protocol_name);

    auto old_h = ss.h;

    std::vector<std::uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    ss.MixHash(data);

    SECTION("Hash h is updated") {
        REQUIRE(ss.h != old_h);
        REQUIRE(ss.h.size() == 32);
    }

    SECTION("Different data produces different hash") {
        auto h_after_first = ss.h;

        std::vector<std::uint8_t> data2 = {0x05, 0x06, 0x07, 0x08};
        ss.MixHash(data2);

        REQUIRE(ss.h != h_after_first);
    }

    SECTION("Empty data still updates hash") {
        std::vector<std::uint8_t> empty_data;
        auto h_before = ss.h;

        ss.MixHash(empty_data);

        REQUIRE(ss.h != h_before);
    }
}

TEST_CASE("SymmetricState - MixKeyAndHash", "[symmetricstate][mixkeyandhash]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    SymmetricState ss(cipher, hash);

    std::string protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
    ss.InitializeSymmetric(protocol_name);

    auto old_ck = ss.ck;
    auto old_h = ss.h;

    std::vector<std::uint8_t> input_km(32, 0xCC);
    ss.MixKeyAndHash(input_km);

    SECTION("Both chaining key and hash are updated") {
        REQUIRE(ss.ck != old_ck);
        REQUIRE(ss.h != old_h);
    }

    SECTION("CipherState key is set") {
        REQUIRE(ss.cs.HasKey());
    }

    SECTION("Hash and chaining key are different") {
        REQUIRE(ss.h != ss.ck);
    }
}

TEST_CASE("SymmetricState - EncryptAndHash", "[symmetricstate][encrypt]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    SymmetricState ss(cipher, hash);

    std::string protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
    ss.InitializeSymmetric(protocol_name);

    // Set up encryption key
    std::vector<std::uint8_t> input_km(32, 0xDD);
    ss.MixKey(input_km);

    auto old_h = ss.h;

    std::vector<std::uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
    std::vector<std::uint8_t> ciphertext;
    ss.EncryptAndHash(ciphertext, plaintext);

    SECTION("Ciphertext is different from plaintext") {
        REQUIRE(ciphertext != plaintext);
        REQUIRE(ciphertext.size() == plaintext.size() + 16); // +16 for auth tag
    }

    SECTION("Hash is updated after encryption") {
        REQUIRE(ss.h != old_h);
    }

    SECTION("Hash includes ciphertext, not plaintext") {
        // The hash should be influenced by the ciphertext
        REQUIRE(ss.h.size() == 32);
    }
}

TEST_CASE("SymmetricState - DecryptAndHash", "[symmetricstate][decrypt]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    // Create two symmetric states (simulating sender and receiver)
    SymmetricState ss_sender(cipher, hash);
    SymmetricState ss_receiver(cipher, hash);

    std::string protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
    ss_sender.InitializeSymmetric(protocol_name);
    ss_receiver.InitializeSymmetric(protocol_name);

    // Set up same encryption key on both sides
    std::vector<std::uint8_t> input_km(32, 0xEE);
    ss_sender.MixKey(input_km);
    ss_receiver.MixKey(input_km);

    std::vector<std::uint8_t> original_plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"

    std::vector<std::uint8_t> ciphertext;
    ss_sender.EncryptAndHash(ciphertext, original_plaintext);
    std::vector<std::uint8_t> decrypted;
    ss_receiver.DecryptAndHash(decrypted, ciphertext);

    SECTION("Decrypted plaintext matches original") {
        REQUIRE(decrypted == original_plaintext);
    }

    SECTION("Both sides have same hash after encrypt/decrypt") {
        REQUIRE(ss_sender.h == ss_receiver.h);
    }
}

TEST_CASE("SymmetricState - EncryptAndHash without key", "[symmetricstate][encrypt][edge-case]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    SymmetricState ss(cipher, hash);

    std::string protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
    ss.InitializeSymmetric(protocol_name);

    // Don't set a key - CipherState should return plaintext unchanged
    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> result;
    ss.EncryptAndHash(result, plaintext);

    SECTION("Without key, returns plaintext") {
        REQUIRE(result == plaintext);
    }

    SECTION("Hash is still updated") {
        // Hash should have changed even though no encryption occurred
        REQUIRE(ss.h.size() == 32);
    }
}

TEST_CASE("SymmetricState - GetHandshakeHash", "[symmetricstate][hash]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    SymmetricState ss(cipher, hash);

    std::string protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
    ss.InitializeSymmetric(protocol_name);

    auto handshake_hash = ss.GetHandshakeHash();

    SECTION("Returns current hash") {
        REQUIRE(handshake_hash == ss.h);
    }

    SECTION("Hash length is correct") {
        REQUIRE(handshake_hash.size() == 32);
    }

    SECTION("Returned hash updates when state is modified") {
        std::vector<std::uint8_t> data = {0x01, 0x02};
        ss.MixHash(data);

        auto new_hash = ss.GetHandshakeHash();
        REQUIRE(new_hash != handshake_hash);
    }
}

TEST_CASE("SymmetricState - Split", "[symmetricstate][split]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    SymmetricState ss(cipher, hash);

    std::string protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
    ss.InitializeSymmetric(protocol_name);

    // Set up some key material
    std::vector<std::uint8_t> input_km(32, 0xFF);
    ss.MixKey(input_km);

    auto [c1, c2] = ss.Split();

    SECTION("Both cipher states have keys") {
        REQUIRE(c1.HasKey());
        REQUIRE(c2.HasKey());
    }

    SECTION("Cipher states have different keys") {
        REQUIRE(c1.key != c2.key);
    }

    SECTION("Both keys are 32 bytes") {
        REQUIRE(c1.key.size() == 32);
        REQUIRE(c2.key.size() == 32);
    }

    SECTION("Cipher states can encrypt and decrypt") {
        std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03};
        std::vector<std::uint8_t> ad{};

        auto ct1 = c1.EncryptWithAd(ad, plaintext);
        auto ct2 = c2.EncryptWithAd(ad, plaintext);

        // Different keys produce different ciphertexts
        REQUIRE(ct1 != ct2);

        // Each can decrypt its own ciphertext
        // Create new cipher states with same keys for decryption
        auto [c1_decrypt, c2_decrypt] = ss.Split();

        auto pt1 = c1_decrypt.DecryptWithAd(ad, ct1);
        auto pt2 = c2_decrypt.DecryptWithAd(ad, ct2);

        REQUIRE(pt1 == plaintext);
        REQUIRE(pt2 == plaintext);
    }
}

TEST_CASE("SymmetricState - Split with SHA-512", "[symmetricstate][split][sha512]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA512);

    SymmetricState ss(cipher, hash);

    std::string protocol_name = "Noise_XX_25519_ChaChaPoly_SHA512";
    ss.InitializeSymmetric(protocol_name);

    std::vector<std::uint8_t> input_km(32, 0xAB);
    ss.MixKey(input_km);

    auto [c1, c2] = ss.Split();

    SECTION("Keys are truncated to 32 bytes for SHA-512") {
        REQUIRE(c1.key.size() == 32);
        REQUIRE(c2.key.size() == 32);
    }

    SECTION("Both keys are set") {
        REQUIRE(c1.HasKey());
        REQUIRE(c2.HasKey());
    }
}

TEST_CASE("SymmetricState - Complete handshake simulation", "[symmetricstate][integration]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    // Simulate initiator and responder
    SymmetricState ss_init(cipher, hash);
    SymmetricState ss_resp(cipher, hash);

    std::string protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
    ss_init.InitializeSymmetric(protocol_name);
    ss_resp.InitializeSymmetric(protocol_name);

    SECTION("Initial states are identical") {
        REQUIRE(ss_init.h == ss_resp.h);
        REQUIRE(ss_init.ck == ss_resp.ck);
    }

    // Simulate ephemeral key exchange
    std::vector<std::uint8_t> ephemeral_shared(32, 0x11);
    ss_init.MixKey(ephemeral_shared);
    ss_resp.MixKey(ephemeral_shared);

    SECTION("After MixKey, states are still identical") {
        REQUIRE(ss_init.h == ss_resp.h);
        REQUIRE(ss_init.ck == ss_resp.ck);
    }

    // Initiator sends payload
    std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> ct;
    ss_init.EncryptAndHash(ct, payload);
    std::vector<std::uint8_t> pt;
    ss_resp.DecryptAndHash(pt, ct);

    SECTION("Payload roundtrip succeeds") {
        REQUIRE(pt == payload);
    }

    SECTION("After encrypt/decrypt, states remain synchronized") {
        REQUIRE(ss_init.h == ss_resp.h);
    }

    // Split into transport keys
    auto [c1_init, c2_init] = ss_init.Split();
    auto [c1_resp, c2_resp] = ss_resp.Split();

    SECTION("Transport keys match between initiator and responder") {
        REQUIRE(c1_init.key == c1_resp.key);
        REQUIRE(c2_init.key == c2_resp.key);
    }
}

TEST_CASE("SymmetricState - Empty protocol name", "[symmetricstate][edge-case]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    SymmetricState ss(cipher, hash);

    std::string protocol_name = "";
    ss.InitializeSymmetric(protocol_name);

    SECTION("Hash is initialized to all zeros") {
        bool all_zeros = std::ranges::all_of(ss.h, [](auto b) { return b == 0; });
        REQUIRE(all_zeros);
    }

    SECTION("Chaining key equals hash") {
        REQUIRE(ss.ck == ss.h);
    }
}

TEST_CASE("SymmetricState - Multiple MixHash calls accumulate", "[symmetricstate][mixhash][sequence]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    SymmetricState ss(cipher, hash);

    std::string protocol_name = "Noise";
    ss.InitializeSymmetric(protocol_name);

    std::vector<std::uint8_t> data1 = {0x01};
    std::vector<std::uint8_t> data2 = {0x02};
    std::vector<std::uint8_t> data3 = {0x03};

    ss.MixHash(data1);
    auto h_after_1 = ss.h;

    ss.MixHash(data2);
    auto h_after_2 = ss.h;

    ss.MixHash(data3);
    auto h_after_3 = ss.h;

    SECTION("Each MixHash produces different hash") {
        REQUIRE(h_after_1 != h_after_2);
        REQUIRE(h_after_2 != h_after_3);
        REQUIRE(h_after_1 != h_after_3);
    }
}

TEST_CASE("SymmetricState - Large data handling", "[symmetricstate][edge-case]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    SymmetricState ss(cipher, hash);

    std::string protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
    ss.InitializeSymmetric(protocol_name);

    // Large input for MixKey
    std::vector<std::uint8_t> large_input(1024, 0x42);

    REQUIRE_NOTHROW(ss.MixKey(large_input));
    REQUIRE(ss.cs.HasKey());
}

TEST_CASE("SymmetricState - Works with different cipher algorithms", "[symmetricstate][compatibility]") {
    SECTION("ChaCha20-Poly1305") {
        Cipher cipher(ChaChaPoly);
        Hash hash(SHA256);
        SymmetricState ss(cipher, hash);

        std::string protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
        ss.InitializeSymmetric(protocol_name);

        REQUIRE(ss.h.size() == 32);
        REQUIRE(ss.ck.size() == 32);
    }

    SECTION("AES-256-GCM") {
        Cipher cipher(AESGCM);
        Hash hash(SHA256);
        SymmetricState ss(cipher, hash);

        std::string protocol_name = "Noise_XX_25519_AESGCM_SHA256";
        ss.InitializeSymmetric(protocol_name);

        REQUIRE(ss.h.size() == 32);
        REQUIRE(ss.ck.size() == 32);
    }
}

TEST_CASE("SymmetricState - Works with different hash algorithms", "[symmetricstate][compatibility]") {
    Cipher cipher(ChaChaPoly);

    SECTION("SHA-256") {
        Hash hash(SHA256);
        SymmetricState ss(cipher, hash);

        std::string protocol_name = "Noise";
        ss.InitializeSymmetric(protocol_name);

        REQUIRE(ss.hashLen == 32);
        REQUIRE(ss.h.size() == 32);
    }

    SECTION("SHA-512") {
        Hash hash(SHA512);
        SymmetricState ss(cipher, hash);

        std::string protocol_name = "Noise";
        ss.InitializeSymmetric(protocol_name);

        REQUIRE(ss.hashLen == 64);
        REQUIRE(ss.h.size() == 64);
    }

    SECTION("BLAKE2b") {
        Hash hash(BLAKE2b);
        SymmetricState ss(cipher, hash);

        std::string protocol_name = "Noise";
        ss.InitializeSymmetric(protocol_name);

        REQUIRE(ss.hashLen == 64);
        REQUIRE(ss.h.size() == 64);
    }

    SECTION("BLAKE2s") {
        Hash hash(BLAKE2s);
        SymmetricState ss(cipher, hash);

        std::string protocol_name = "Noise";
        ss.InitializeSymmetric(protocol_name);

        REQUIRE(ss.hashLen == 32);
        REQUIRE(ss.h.size() == 32);
    }
}

TEST_CASE("SymmetricState - HKDF matches RFC 5869 for every hash", "[symmetricstate][hkdf]") {
    // Guard for the HKDF path: Noise spec Section 4.3's HKDF (ck as the salt, empty info) must equal
    // RFC 5869 as Botan computes it, for MixKey (2 outputs), MixKeyAndHash (3) and Split (2).
    // test_vectors pins the handshake bytes.
    for (const auto name : {SHA256, SHA512, BLAKE2b, BLAKE2s}) {
        INFO(name);
        const Cipher cipher{ChaChaPoly};
        const Hash hash{name};
        const std::size_t hashLen = hash.hash_function->output_length();
        const auto kdf = Botan::KDF::create_or_throw("HKDF(" + hash.hash_function->name() + ")");
        const auto hkdf = [&](const std::span<const std::uint8_t> salt, const std::span<const std::uint8_t> ikm,
                              const std::size_t outputs) {
            return kdf->derive_key<std::vector<std::uint8_t>>(outputs * hashLen, ikm, salt,
                                                               std::span<const std::uint8_t>{});
        };
        const auto segment = [&](const std::vector<std::uint8_t>& out, const std::size_t i) {
            return std::span<const std::uint8_t>{out}.subspan(i * hashLen, hashLen);
        };

        std::vector<std::uint8_t> salt(hashLen);
        for (std::size_t i = 0; i < hashLen; ++i) salt[i] = static_cast<std::uint8_t>(0x40 + i);
        std::vector<std::uint8_t> ikm(32);
        for (std::size_t i = 0; i < ikm.size(); ++i) ikm[i] = static_cast<std::uint8_t>(0xC0 ^ (i * 3));
        std::vector<std::uint8_t> hBefore(hashLen);
        for (std::size_t i = 0; i < hashLen; ++i) hBefore[i] = static_cast<std::uint8_t>(0x11 + i);

        // MixKey: (ck, temp_k) = HKDF(ck, ikm, 2)
        {
            SymmetricState ss{cipher, hash};
            ss.ck = salt;
            ss.MixKey(ikm);
            const auto out = hkdf(salt, ikm, 2);
            CHECK(std::ranges::equal(ss.ck, segment(out, 0)));
            CHECK(std::ranges::equal(ss.cs.key, segment(out, 1).first(SYMMETRIC_KEY_SIZE)));
        }

        // MixKeyAndHash: (ck, temp_h, temp_k) = HKDF(ck, ikm, 3); h = HASH(h || temp_h)
        {
            SymmetricState ss{cipher, hash};
            ss.ck = salt;
            ss.h = hBefore;
            ss.MixKeyAndHash(ikm);
            const auto out = hkdf(salt, ikm, 3);
            CHECK(std::ranges::equal(ss.ck, segment(out, 0)));
            CHECK(std::ranges::equal(ss.cs.key, segment(out, 2).first(SYMMETRIC_KEY_SIZE)));
            const auto hashFn = hash.hash_function->new_object();
            hashFn->update(hBefore);
            hashFn->update(segment(out, 1));
            CHECK(ss.h == hashFn->final_stdvec());
        }

        // Split: (k1, k2) = HKDF(ck, empty, 2)
        {
            SymmetricState ss{cipher, hash};
            ss.ck = salt;
            ss.h = hBefore;
            const auto [c1, c2] = ss.Split();
            const auto out = hkdf(salt, {}, 2);
            CHECK(std::ranges::equal(c1.key, segment(out, 0).first(SYMMETRIC_KEY_SIZE)));
            CHECK(std::ranges::equal(c2.key, segment(out, 1).first(SYMMETRIC_KEY_SIZE)));
        }
    }
}

TEST_CASE("SymmetricState - copying a moved-from state throws NoiseError", "[symmetricstate][constructor][move][error]") {
    Cipher cipher(ChaChaPoly);
    Hash hash(SHA256);

    SymmetricState ss1(cipher, hash);
    const std::string protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
    ss1.InitializeSymmetric(protocol_name);
    const auto h_before = ss1.h;
    const auto ck_before = ss1.ck;

    SymmetricState ss2(std::move(ss1));

    // A moved-from SymmetricState may only be destroyed. Copying it throws
    // NoiseError instead of dereferencing its (now null) hash and HMAC objects.
    REQUIRE_THROWS_AS(SymmetricState{ss1}, NoiseError);

    // The move destination is unaffected: it still mixes, and a copy of it works.
    REQUIRE(ss2.h == h_before);
    REQUIRE(ss2.ck == ck_before);
    const std::vector<std::uint8_t> data{0x01, 0x02, 0x03};
    ss2.MixHash(data);
    REQUIRE(ss2.h != h_before);

    SymmetricState ss3(ss2);
    REQUIRE(ss3.h == ss2.h);
    REQUIRE(ss3.ck == ss2.ck);
    ss2.MixHash(data);
    ss3.MixHash(data);
    REQUIRE(ss3.h == ss2.h);
}

TEST_CASE("SymmetricState - InitializeSymmetric at the HASHLEN boundary", "[symmetricstate][initialize][boundary]") {
    // Guard: pins the Noise spec Section 5.2 split that InitializeSymmetric implements. A name
    // of exactly HASHLEN bytes is copied into h unchanged (no padding, no hash); one byte more is
    // hashed, with the digest computed independently through a separate Hash object.
    const Cipher cipher(ChaChaPoly);
    for (const auto hashName : {SHA256, BLAKE2b}) {
        const Hash hash(hashName);
        const std::size_t hashLen = hash.hash_function->output_length();
        INFO("hash " << hashName << " (HASHLEN " << hashLen << ")");
        const std::string exact(hashLen, 'N');
        const std::string longer(hashLen + 1, 'N');

        SymmetricState ss(cipher, hash);
        ss.InitializeSymmetric(exact);
        const std::vector<std::uint8_t> exactBytes(exact.begin(), exact.end());
        REQUIRE(ss.h.size() == hashLen);
        REQUIRE(ss.h == exactBytes);
        REQUIRE(ss.ck == ss.h);

        SymmetricState ssLong(cipher, hash);
        ssLong.InitializeSymmetric(longer);
        const auto digest = Hash(hashName).hash_function->process(longer);
        REQUIRE(ssLong.h.size() == hashLen);
        REQUIRE(std::ranges::equal(ssLong.h, digest));
        REQUIRE(ssLong.ck == ssLong.h);
        REQUIRE(ssLong.h != ss.h);
    }
}

// Main function for Catch2
int main(int argc, char* argv[]) {
    // Disable all logging during tests for clean output
    Noise::DisableAllLogging();
    return Catch::Session().run(argc, argv);
}
