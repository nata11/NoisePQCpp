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
// Protocol Module Tests using Catch2 v3
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>

import noise;

using namespace Noise;

TEST_CASE("Protocol - Constructor with individual parameters", "[protocol][constructor]") {
    SECTION("XX pattern with 25519, ChaChaPoly, SHA256") {
        Protocol proto(XX, X25519, ChaChaPoly, SHA256);
        REQUIRE(proto.pattern.String() == "XX");
        REQUIRE(proto.dh.String() == "25519");
        REQUIRE(proto.cipher.String() == "ChaChaPoly");
        REQUIRE(proto.hash.String() == "SHA256");
        REQUIRE(proto.String() == "Noise_XX_25519_ChaChaPoly_SHA256");
    }

    SECTION("NN pattern with 448, AESGCM, SHA512") {
        Protocol proto(NN, X448, AESGCM, SHA512);
        REQUIRE(proto.pattern.String() == "NN");
        REQUIRE(proto.dh.String() == "448");
        REQUIRE(proto.cipher.String() == "AESGCM");
        REQUIRE(proto.hash.String() == "SHA512");
        REQUIRE(proto.String() == "Noise_NN_448_AESGCM_SHA512");
    }

    SECTION("KK pattern with 25519, ChaChaPoly, BLAKE2b") {
        Protocol proto(KK, X25519, ChaChaPoly, BLAKE2b);
        REQUIRE(proto.pattern.String() == "KK");
        REQUIRE(proto.dh.String() == "25519");
        REQUIRE(proto.cipher.String() == "ChaChaPoly");
        REQUIRE(proto.hash.String() == "BLAKE2b");
        REQUIRE(proto.String() == "Noise_KK_25519_ChaChaPoly_BLAKE2b");
    }

    SECTION("NK pattern with 448, AESGCM, BLAKE2s") {
        Protocol proto(NK, X448, AESGCM, BLAKE2s);
        REQUIRE(proto.pattern.String() == "NK");
        REQUIRE(proto.dh.String() == "448");
        REQUIRE(proto.cipher.String() == "AESGCM");
        REQUIRE(proto.hash.String() == "BLAKE2s");
        REQUIRE(proto.String() == "Noise_NK_448_AESGCM_BLAKE2s");
    }
}

TEST_CASE("Protocol - Constructor with protocol string", "[protocol][constructor][string]") {
    SECTION("Noise_XX_25519_ChaChaPoly_SHA256") {
        Protocol proto("Noise_XX_25519_ChaChaPoly_SHA256");
        REQUIRE(proto.pattern.String() == "XX");
        REQUIRE(proto.dh.String() == "25519");
        REQUIRE(proto.cipher.String() == "ChaChaPoly");
        REQUIRE(proto.hash.String() == "SHA256");
        REQUIRE(proto.String() == "Noise_XX_25519_ChaChaPoly_SHA256");
    }

    SECTION("Noise_NN_448_AESGCM_SHA512") {
        Protocol proto("Noise_NN_448_AESGCM_SHA512");
        REQUIRE(proto.pattern.String() == "NN");
        REQUIRE(proto.dh.String() == "448");
        REQUIRE(proto.cipher.String() == "AESGCM");
        REQUIRE(proto.hash.String() == "SHA512");
        REQUIRE(proto.String() == "Noise_NN_448_AESGCM_SHA512");
    }

    SECTION("Noise_KK_25519_ChaChaPoly_BLAKE2b") {
        Protocol proto("Noise_KK_25519_ChaChaPoly_BLAKE2b");
        REQUIRE(proto.pattern.String() == "KK");
        REQUIRE(proto.dh.String() == "25519");
        REQUIRE(proto.cipher.String() == "ChaChaPoly");
        REQUIRE(proto.hash.String() == "BLAKE2b");
        REQUIRE(proto.String() == "Noise_KK_25519_ChaChaPoly_BLAKE2b");
    }

    SECTION("Noise_NK_448_AESGCM_BLAKE2s") {
        Protocol proto("Noise_NK_448_AESGCM_BLAKE2s");
        REQUIRE(proto.pattern.String() == "NK");
        REQUIRE(proto.dh.String() == "448");
        REQUIRE(proto.cipher.String() == "AESGCM");
        REQUIRE(proto.hash.String() == "BLAKE2s");
        REQUIRE(proto.String() == "Noise_NK_448_AESGCM_BLAKE2s");
    }
}

TEST_CASE("Protocol - String() method round-trip", "[protocol][string][roundtrip]") {
    SECTION("Noise_XX_25519_ChaChaPoly_SHA256") {
        std::string_view original = "Noise_XX_25519_ChaChaPoly_SHA256";
        Protocol proto(original);
        std::string result = proto.String();
        REQUIRE(result == original);
    }

    SECTION("Noise_KK_448_AESGCM_BLAKE2s") {
        std::string_view original = "Noise_KK_448_AESGCM_BLAKE2s";
        Protocol proto(original);
        std::string result = proto.String();
        REQUIRE(result == original);
    }

    SECTION("Noise_NN_25519_ChaChaPoly_BLAKE2b") {
        std::string_view original = "Noise_NN_25519_ChaChaPoly_BLAKE2b";
        Protocol proto(original);
        std::string result = proto.String();
        REQUIRE(result == original);
    }
}

TEST_CASE("Protocol - All pattern combinations", "[protocol][patterns]") {
    std::vector<std::pair<std::string_view, std::string_view>> test_patterns = {
        {"Noise_XX_25519_ChaChaPoly_SHA256", "XX"},
        {"Noise_NN_25519_ChaChaPoly_SHA256", "NN"},
        {"Noise_KK_25519_ChaChaPoly_SHA256", "KK"},
        {"Noise_NK_25519_ChaChaPoly_SHA256", "NK"}
    };

    for (const auto& [protocol_str, expected_pattern] : test_patterns) {
        INFO("Testing protocol: " << protocol_str);
        Protocol proto(protocol_str);
        REQUIRE(proto.pattern.String() == expected_pattern);
    }
}

TEST_CASE("Protocol - All DH algorithm combinations", "[protocol][dh]") {
    std::vector<std::pair<std::string_view, std::string_view>> test_dh = {
        {"Noise_XX_25519_ChaChaPoly_SHA256", "25519"},
        {"Noise_XX_448_ChaChaPoly_SHA256", "448"}
    };

    for (const auto& [protocol_str, expected_dh] : test_dh) {
        INFO("Testing protocol: " << protocol_str);
        Protocol proto(protocol_str);
        REQUIRE(proto.dh.String() == expected_dh);
    }
}

TEST_CASE("Protocol - All Cipher algorithm combinations", "[protocol][cipher]") {
    std::vector<std::pair<std::string_view, std::string_view>> test_cipher = {
        {"Noise_XX_25519_ChaChaPoly_SHA256", "ChaChaPoly"},
        {"Noise_XX_25519_AESGCM_SHA256", "AESGCM"}
    };

    for (const auto& [protocol_str, expected_cipher] : test_cipher) {
        INFO("Testing protocol: " << protocol_str);
        Protocol proto(protocol_str);
        REQUIRE(proto.cipher.String() == expected_cipher);
    }
}

TEST_CASE("Protocol - All Hash algorithm combinations", "[protocol][hash]") {
    std::vector<std::pair<std::string_view, std::string_view>> test_hash = {
        {"Noise_XX_25519_ChaChaPoly_SHA256", "SHA256"},
        {"Noise_XX_25519_ChaChaPoly_SHA512", "SHA512"},
        {"Noise_XX_25519_ChaChaPoly_BLAKE2b", "BLAKE2b"},
        {"Noise_XX_25519_ChaChaPoly_BLAKE2s", "BLAKE2s"}
    };

    for (const auto& [protocol_str, expected_hash] : test_hash) {
        INFO("Testing protocol: " << protocol_str);
        Protocol proto(protocol_str);
        REQUIRE(proto.hash.String() == expected_hash);
    }
}

TEST_CASE("Protocol - Invalid protocol strings throw errors", "[protocol][error][validation]") {
    std::vector<std::string_view> invalid_protocols = {
        "Invalid_XX_25519_ChaChaPoly_SHA256",          // Wrong prefix
        "Noise_XX_25519_ChaChaPoly",                   // Missing hash
        "Noise_XX_25519",                              // Missing cipher and hash
        "Noise_InvalidPattern_25519_ChaChaPoly_SHA256", // Invalid pattern
        "",                                             // Empty string
        "Noise",                                        // Just prefix
        "Noise_XX_InvalidDH_ChaChaPoly_SHA256"         // Invalid DH
    };

    for (const auto& invalid : invalid_protocols) {
        INFO("Testing invalid protocol: " << invalid);
        REQUIRE_THROWS(Protocol(invalid));
    }
}

TEST_CASE("Protocol - Pattern describe() method does not throw", "[protocol][pattern][describe]") {
    SECTION("XX pattern") {
        Protocol proto(XX, X25519, ChaChaPoly, SHA256);
        REQUIRE_NOTHROW(proto.pattern.describe(std::cout));
    }

    SECTION("NN pattern") {
        Protocol proto(NN, X25519, ChaChaPoly, SHA256);
        REQUIRE_NOTHROW(proto.pattern.describe(std::cout));
    }

    SECTION("KK pattern") {
        Protocol proto(KK, X25519, ChaChaPoly, SHA256);
        REQUIRE_NOTHROW(proto.pattern.describe(std::cout));
    }

    SECTION("NK pattern") {
        Protocol proto(NK, X25519, ChaChaPoly, SHA256);
        REQUIRE_NOTHROW(proto.pattern.describe(std::cout));
    }
}

TEST_CASE("Protocol - Comprehensive combination test", "[protocol][comprehensive]") {
    std::vector<std::tuple<std::string_view, std::string_view, std::string_view, std::string_view>> combinations = {
        {"XX", "25519", "ChaChaPoly", "SHA256"},
        {"XX", "448", "AESGCM", "SHA512"},
        {"NN", "25519", "ChaChaPoly", "BLAKE2b"},
        {"NN", "448", "AESGCM", "BLAKE2s"},
        {"KK", "25519", "AESGCM", "SHA256"},
        {"KK", "448", "ChaChaPoly", "SHA512"},
        {"NK", "25519", "AESGCM", "BLAKE2b"},
        {"NK", "448", "ChaChaPoly", "BLAKE2s"}
    };

    for (const auto& [pattern, dh, cipher, hash] : combinations) {
        std::string protocol_string = std::format("Noise_{}_{}_{}_{}",
            pattern, dh, cipher, hash);

        INFO("Testing protocol: " << protocol_string);

        // Test constructor
        Protocol proto(protocol_string);

        // Verify individual components
        REQUIRE(proto.pattern.String() == pattern);
        REQUIRE(proto.dh.String() == dh);
        REQUIRE(proto.cipher.String() == cipher);
        REQUIRE(proto.hash.String() == hash);
    }
}

TEST_CASE("Protocol - String() returns complete protocol name", "[protocol][string]") {
    SECTION("Components concatenate correctly") {
        Protocol proto(XX, X25519, ChaChaPoly, SHA256);
        std::string result = proto.String();

        REQUIRE(result.find("Noise_") == 0);
        REQUIRE(result.find("XX") != std::string::npos);
        REQUIRE(result.find("25519") != std::string::npos);
        REQUIRE(result.find("ChaChaPoly") != std::string::npos);
        REQUIRE(result.find("SHA256") != std::string::npos);
    }

    SECTION("Underscores separate components") {
        Protocol proto(KK, X448, AESGCM, BLAKE2s);
        std::string result = proto.String();

        // Count underscores (should be 4: Noise_KK_448_AESGCM_BLAKE2s)
        auto count = std::ranges::count(result, '_');
        REQUIRE(count == 4);
    }
}

TEST_CASE("Protocol - All supported combinations work correctly", "[protocol][supported]") {
    // Test all combinations of supported algorithms
    std::vector<HandshakePattern> patterns = {XX, NN, KK, NK};
    std::vector<std::string_view> dh_algos = {"25519", "448"};
    std::vector<std::string_view> ciphers = {ChaChaPoly, AESGCM};
    std::vector<std::string_view> hashes = {SHA256, SHA512, BLAKE2b, BLAKE2s};

    int success_count = 0;

    for (const auto& pattern : patterns) {
        for (const auto& dh : dh_algos) {
            for (const auto& cipher : ciphers) {
                for (const auto& hash : hashes) {
                    REQUIRE_NOTHROW([&]() {
                        Protocol proto(pattern, dh, cipher, hash);
                        // Verify protocol was created successfully
                        REQUIRE(!proto.String().empty());
                        success_count++;
                    }());
                }
            }
        }
    }

    // Verify we tested all combinations: 4 patterns * 2 DH * 2 ciphers * 4 hashes = 64
    REQUIRE(success_count == 64);
}

// ================================
// HFS Protocol Tests
// ================================

TEST_CASE("Protocol - HFS protocol string parsing", "[protocol][hfs][parsing]") {
    SECTION("Parse NNhfs with 25519+M768") {
        Protocol proto("Noise_NNhfs_25519+M768_ChaChaPoly_SHA256");
        REQUIRE(proto.IsHFS());
        REQUIRE(proto.pattern.String() == "NNhfs");
        REQUIRE(proto.dh.String() == "25519");
        REQUIRE(proto.kem.has_value());
        REQUIRE(proto.kem->String() == "M768");
        REQUIRE(proto.cipher.String() == "ChaChaPoly");
        REQUIRE(proto.hash.String() == "SHA256");
    }

    SECTION("Parse XXhfs with 448+M1024") {
        Protocol proto("Noise_XXhfs_448+M1024_AESGCM_BLAKE2b");
        REQUIRE(proto.IsHFS());
        REQUIRE(proto.pattern.String() == "XXhfs");
        REQUIRE(proto.dh.String() == "448");
        REQUIRE(proto.kem.has_value());
        REQUIRE(proto.kem->String() == "M1024");
    }

    SECTION("Parse IKhfs with 25519+M512") {
        Protocol proto("Noise_IKhfs_25519+M512_ChaChaPoly_SHA512");
        REQUIRE(proto.IsHFS());
        REQUIRE(proto.pattern.String() == "IKhfs");
        REQUIRE(proto.kem->String() == "M512");
    }

    SECTION("Non-HFS protocol IsHFS returns false") {
        Protocol proto("Noise_XX_25519_ChaChaPoly_SHA256");
        REQUIRE_FALSE(proto.IsHFS());
        REQUIRE_FALSE(proto.kem.has_value());
    }
}

TEST_CASE("Protocol - HFS protocol String() round-trip", "[protocol][hfs][string]") {
    SECTION("NNhfs round-trip") {
        std::string_view original = "Noise_NNhfs_25519+M768_ChaChaPoly_SHA256";
        Protocol proto(original);
        REQUIRE(proto.String() == original);
    }

    SECTION("XXhfs round-trip") {
        std::string_view original = "Noise_XXhfs_448+M1024_AESGCM_BLAKE2b";
        Protocol proto(original);
        REQUIRE(proto.String() == original);
    }

    SECTION("KKhfs round-trip") {
        std::string_view original = "Noise_KKhfs_25519+M512_ChaChaPoly_BLAKE2s";
        Protocol proto(original);
        REQUIRE(proto.String() == original);
    }
}

TEST_CASE("Protocol - HFS error handling", "[protocol][hfs][error]") {
    SECTION("DH+KEM without hfs suffix throws") {
        REQUIRE_THROWS(Protocol("Noise_XX_25519+M768_ChaChaPoly_SHA256"));
    }

    SECTION("hfs suffix without DH+KEM throws") {
        REQUIRE_THROWS(Protocol("Noise_XXhfs_25519_ChaChaPoly_SHA256"));
    }

    SECTION("Invalid KEM name throws") {
        REQUIRE_THROWS(Protocol("Noise_XXhfs_25519+InvalidKEM_ChaChaPoly_SHA256"));
    }
}

TEST_CASE("Protocol - HFS all DH+KEM combinations", "[protocol][hfs][combinations]") {
    std::vector<std::tuple<std::string_view, std::string_view, std::string_view>> dh_kem_combos = {
        {"25519", "M512", "25519+M512"},
        {"25519", "M768", "25519+M768"},
        {"25519", "M1024", "25519+M1024"},
        {"448", "M512", "448+M512"},
        {"448", "M768", "448+M768"},
        {"448", "M1024", "448+M1024"}
    };

    for (const auto& [dh, kem, combo] : dh_kem_combos) {
        std::string protocol_string = std::format("Noise_NNhfs_{}_ChaChaPoly_SHA256", combo);
        INFO("Testing: " << protocol_string);

        Protocol proto(protocol_string);
        REQUIRE(proto.IsHFS());
        REQUIRE(proto.dh.String() == dh);
        REQUIRE(proto.kem->String() == kem);
    }
}

TEST_CASE("Protocol - HFS deferred patterns", "[protocol][hfs][deferred]") {
    std::vector<std::string_view> deferred_hfs_patterns = {
        "Noise_NK1hfs_25519+M768_ChaChaPoly_SHA256",
        "Noise_XX1hfs_448+M1024_ChaChaPoly_BLAKE2b",
        "Noise_IK1hfs_25519+M512_AESGCM_SHA512"
    };

    for (const auto& pattern : deferred_hfs_patterns) {
        INFO("Testing: " << pattern);
        Protocol proto(pattern);
        REQUIRE(proto.IsHFS());
        REQUIRE(proto.kem.has_value());
    }
}

// ============================================================================
// Algorithm and pattern allowlists
// ============================================================================

TEST_CASE("Protocol - Non-Noise cipher names are rejected", "[protocol][error][allowlist][cipher]") {
    // Only the Noise names ChaChaPoly and AESGCM are accepted; nothing reaches Botan's
    // name parser (fuzzing found std::out_of_range from "ChaChaPoly/)").
    for (const std::string_view cipher : {"ChaChaPoly/)", "AES-256/GCM(8)", "AES-128/GCM",
                                          "ChaCha20Poly1305", ""}) {
        const std::string name = std::string("Noise_NN_25519_") + std::string(cipher) + "_SHA256";
        INFO("protocol: " << name);
        REQUIRE_THROWS_AS(Protocol{name}, ProtocolNotSupportedError);
    }
}

TEST_CASE("Protocol - Non-Noise hash names are rejected", "[protocol][error][allowlist][hash]") {
    for (const std::string_view hash : {"MD5", "SHA-3(256)", "SHA-256", "BLAKE2b(256)"}) {
        const std::string name = std::string("Noise_NN_25519_ChaChaPoly_") + std::string(hash);
        INFO("protocol: " << name);
        REQUIRE_THROWS_AS(Protocol{name}, ProtocolNotSupportedError);
    }
}

TEST_CASE("Protocol - Only registered HFS patterns parse", "[protocol][hfs][allowlist]") {
    SECTION("hfs names that are not in the registry are rejected") {
        // N has no ee (nothing to attach ekem1 to); NNpsk0 and pqXX are not HFS bases
        for (const std::string_view name : {"Noise_Nhfs_25519+M768_ChaChaPoly_SHA256",
                                            "Noise_NNpsk0hfs_25519+M768_ChaChaPoly_SHA256",
                                            "Noise_pqXXhfs_M768+M768_ChaChaPoly_SHA256"}) {
            INFO("protocol: " << name);
            REQUIRE_THROWS_AS(Protocol{name}, ProtocolNotSupportedError);
        }
    }

    SECTION("every registered hfs pattern parses and round-trips") {
        std::size_t count = 0;
        for (const auto& [patternName, pattern] : GetPatternRegistry()) {
            if (!patternName.ends_with("hfs")) continue;
            const std::string name = "Noise_" + patternName + "_25519+M768_ChaChaPoly_SHA256";
            INFO("protocol: " << name);
            const Protocol protocol{name};
            REQUIRE(protocol.IsHFS());
            REQUIRE(protocol.String() == name);
            ++count;
        }
        REQUIRE(count == 35);
    }
}

TEST_CASE("Protocol - Incompatible pattern and algorithms are rejected", "[protocol][error][allowlist][combination]") {
    SECTION("DH tokens with a KEM algorithm") {
        REQUIRE_THROWS_AS(Protocol{"Noise_XX_M768_ChaChaPoly_SHA256"}, ProtocolNotSupportedError);
    }
    SECTION("KEM tokens with a DH algorithm") {
        REQUIRE_THROWS_AS(Protocol{"Noise_pqXX_25519_ChaChaPoly_SHA256"}, ProtocolNotSupportedError);
    }
    SECTION("HFS secondary algorithm is not a KEM") {
        REQUIRE_THROWS_AS(Protocol{"Noise_XXhfs_25519+448_ChaChaPoly_SHA256"}, ProtocolNotSupportedError);
    }
    SECTION("HFS primary algorithm is not a DH") {
        REQUIRE_THROWS_AS(Protocol{"Noise_XXhfs_M768+M768_ChaChaPoly_SHA256"}, ProtocolNotSupportedError);
    }
    SECTION("A kem without e1 in the pattern (component constructor)") {
        REQUIRE_THROWS_AS(Protocol(XX, X25519, M768, ChaChaPoly, SHA256), ProtocolNotSupportedError);
    }
}

// Malformed DH+KEM forms are ProtocolNotSupportedError, and
// String() is the cached canonical name.
TEST_CASE("Protocol - malformed DH+KEM forms are ProtocolNotSupportedError", "[protocol][error][hfs][string]") {
    SECTION("a '+' without the hfs modifier, and hfs without a '+'") {
        // Before 1.1.0, both threw a plain NoiseError.
        REQUIRE_THROWS_AS(Protocol("Noise_XX_25519+M768_ChaChaPoly_SHA256"), ProtocolNotSupportedError);
        REQUIRE_THROWS_AS(Protocol("Noise_XXhfs_25519_ChaChaPoly_SHA256"), ProtocolNotSupportedError);
    }

    SECTION("String() returns the parsed name for every registry pattern, from a cached string") {
        // 25519_ChaChaPoly_SHA256 for the classical patterns, M768 for the KEM-only (pq) patterns
        // and 25519+M768 for the hfs patterns, so that every name is a valid combination.
        std::size_t checked = 0;
        for (const auto& [name, pattern] : GetPatternRegistry()) {
            INFO("pattern " << name);
            std::string algos = "25519";
            if (name.starts_with("pq")) {
                algos = "M768";
            }
            else if (name.ends_with("hfs")) {
                algos = "25519+M768";
            }
            const std::string full = "Noise_" + name + "_" + algos + "_ChaChaPoly_SHA256";
            const Protocol p(full);
            CHECK(p.String() == full);
            CHECK(&p.String() == &p.String());   // one cached string, no rebuild per call
            const std::string copy = p.String();  // the existing call form keeps compiling
            CHECK(copy == full);
            ++checked;
        }
        CHECK(checked == GetPatternRegistry().size());
        CHECK(checked >= 82);
    }
}

TEST_CASE("Algorithm enum constructors agree with the name constructors", "[protocol][enum][constructor][guard]") {
    // Cipher(CipherAlgo), Hash(HashAlgo) and Dh(KeyAlgo) store the enum directly,
    // validated against the Common tables; the name constructors resolve, then delegate. Both
    // routes must build the same algorithm, and an out-of-range value is ProtocolNotSupportedError.
    SECTION("every table entry builds the same algorithm from the enum and from the name") {
        for (const auto& [algo, name] : CipherAlgos) {
            CHECK(Cipher{algo}.String() == Cipher{name}.String());
            CHECK(Cipher{algo}.String() == name);
            CHECK(Cipher{algo}.GetAeadTagSize() == Cipher{name}.GetAeadTagSize());
        }
        for (const auto& [algo, name] : HashAlgos) {
            CHECK(Hash{algo}.String() == Hash{name}.String());
            CHECK(Hash{algo}.String() == name);
            CHECK(Hash{algo}.Size() == Hash{name}.Size());
        }
        for (const auto& [algo, name] : KeyAlgos) {
            CHECK(Dh{algo}.String() == Dh{name}.String());
            CHECK(Dh{algo}.String() == name);
            CHECK(Dh{algo}.Size() == Dh{name}.Size());
            CHECK(Dh{algo}.PublicKeySize() == Dh{name}.PublicKeySize());
            CHECK(Dh{algo}.IsKEM() == Dh{name}.IsKEM());
        }
    }
    SECTION("an out-of-range enum value is ProtocolNotSupportedError") {
        CHECK_THROWS_AS(Cipher{static_cast<CipherAlgo>(99)}, ProtocolNotSupportedError);
        CHECK_THROWS_AS(Hash{static_cast<HashAlgo>(99)}, ProtocolNotSupportedError);
        CHECK_THROWS_AS(Dh{static_cast<KeyAlgo>(99)}, ProtocolNotSupportedError);
    }
}

// Main function for Catch2
int main(int argc, char* argv[]) {
    // Disable all logging during tests for clean output
    Noise::DisableAllLogging();
    return Catch::Session().run(argc, argv);
}