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
// Hash Module Tests using Catch2 v3.11
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>

import noise;

using namespace Noise;

TEST_CASE("Hash - Default Constructor", "[hash][constructor]") {
    Hash hash;
    REQUIRE(hash.String() == SHA256);
}

TEST_CASE("Hash - Explicit Constructor with SHA-256 string", "[hash][constructor]") {
    Hash hash(SHA256);
    REQUIRE(hash.String() == SHA256);
}

TEST_CASE("Hash - Explicit Constructor with SHA-512 string", "[hash][constructor]") {
    Hash hash(SHA512);
    REQUIRE(hash.String() == SHA512);
}

TEST_CASE("Hash - Explicit Constructor with BLAKE2b string", "[hash][constructor]") {
    Hash hash(BLAKE2b);
    REQUIRE(hash.String() == BLAKE2b);
}

TEST_CASE("Hash - Explicit Constructor with BLAKE2s string", "[hash][constructor]") {
    Hash hash(BLAKE2s);
    REQUIRE(hash.String() == BLAKE2s);
}

TEST_CASE("Hash - Constructor from HashAlgo enum", "[hash][constructor][enum]") {
    SECTION("SHA-256 from enum") {
        Hash hash(HashAlgo::SHA256);
        REQUIRE(hash.String() == SHA256);
    }

    SECTION("SHA-512 from enum") {
        Hash hash(HashAlgo::SHA512);
        REQUIRE(hash.String() == SHA512);
    }

    SECTION("BLAKE2b from enum") {
        Hash hash(HashAlgo::BLAKE2b);
        REQUIRE(hash.String() == BLAKE2b);
    }

    SECTION("BLAKE2s from enum") {
        Hash hash(HashAlgo::BLAKE2s);
        REQUIRE(hash.String() == BLAKE2s);
    }
}

TEST_CASE("Hash - Copy Constructor", "[hash][constructor][copy]") {
    Hash hash1(SHA512);
    Hash hash2(hash1);

    REQUIRE(hash1.String() == hash2.String());
    REQUIRE(hash2.String() == SHA512);
}

TEST_CASE("Hash - Move Constructor", "[hash][constructor][move]") {
    Hash hash1(BLAKE2b);
    Hash hash2(std::move(hash1));

    REQUIRE(hash2.String() == BLAKE2b);
}

TEST_CASE("Hash - String method returns correct algorithm name", "[hash][utility]") {
    SECTION("SHA-256") {
        Hash hash(HashAlgo::SHA256);
        REQUIRE(hash.String() == "SHA256");
    }

    SECTION("SHA-512") {
        Hash hash(HashAlgo::SHA512);
        REQUIRE(hash.String() == "SHA512");
    }

    SECTION("BLAKE2b") {
        Hash hash(HashAlgo::BLAKE2b);
        REQUIRE(hash.String() == "BLAKE2b");
    }

    SECTION("BLAKE2s") {
        Hash hash(HashAlgo::BLAKE2s);
        REQUIRE(hash.String() == "BLAKE2s");
    }
}

TEST_CASE("Hash - Size method returns correct output length", "[hash][utility]") {
    SECTION("SHA-256 output is 32 bytes") {
        Hash hash(HashAlgo::SHA256);
        REQUIRE(hash.Size() == 32);
    }

    SECTION("SHA-512 output is 64 bytes") {
        Hash hash(HashAlgo::SHA512);
        REQUIRE(hash.Size() == 64);
    }

    SECTION("BLAKE2b output is 64 bytes") {
        Hash hash(HashAlgo::BLAKE2b);
        REQUIRE(hash.Size() == 64);
    }

    SECTION("BLAKE2s output is 32 bytes") {
        Hash hash(HashAlgo::BLAKE2s);
        REQUIRE(hash.Size() == 32);
    }
}

TEST_CASE("Hash - hash_function is initialized", "[hash][initialization]") {
    Hash hash(HashAlgo::SHA256);
    REQUIRE(hash.hash_function != nullptr);
}

TEST_CASE("Hash - Basic hashing with SHA-256", "[hash][hashing][sha256]") {
    Hash hash(HashAlgo::SHA256);

    std::vector<std::uint8_t> data = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f  // "Hello"
    };

    auto digest = hash.hash_function->process(data);

    SECTION("Digest has correct length") {
        REQUIRE(digest.size() == 32);
    }

    SECTION("Digest is not all zeros") {
        bool has_nonzero = std::ranges::any_of(digest, [](auto byte) { return byte != 0; });
        REQUIRE(has_nonzero);
    }
}

TEST_CASE("Hash - Basic hashing with SHA-512", "[hash][hashing][sha512]") {
    Hash hash(HashAlgo::SHA512);

    std::vector<std::uint8_t> data = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f  // "Hello"
    };

    auto digest = hash.hash_function->process(data);

    SECTION("Digest has correct length") {
        REQUIRE(digest.size() == 64);
    }

    SECTION("Digest is not all zeros") {
        bool has_nonzero = std::ranges::any_of(digest, [](auto byte) { return byte != 0; });
        REQUIRE(has_nonzero);
    }
}

TEST_CASE("Hash - Basic hashing with BLAKE2b", "[hash][hashing][blake2b]") {
    Hash hash(HashAlgo::BLAKE2b);

    std::vector<std::uint8_t> data = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f  // "Hello"
    };

    auto digest = hash.hash_function->process(data);

    SECTION("Digest has correct length") {
        REQUIRE(digest.size() == 64);
    }

    SECTION("Digest is not all zeros") {
        bool has_nonzero = std::ranges::any_of(digest, [](auto byte) { return byte != 0; });
        REQUIRE(has_nonzero);
    }
}

TEST_CASE("Hash - Basic hashing with BLAKE2s", "[hash][hashing][blake2s]") {
    Hash hash(HashAlgo::BLAKE2s);

    std::vector<std::uint8_t> data = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f  // "Hello"
    };

    auto digest = hash.hash_function->process(data);

    SECTION("Digest has correct length") {
        REQUIRE(digest.size() == 32);
    }

    SECTION("Digest is not all zeros") {
        bool has_nonzero = std::ranges::any_of(digest, [](auto byte) { return byte != 0; });
        REQUIRE(has_nonzero);
    }
}

TEST_CASE("Hash - Same input produces same output (determinism)", "[hash][determinism]") {
    Hash hash(HashAlgo::SHA256);

    std::vector<std::uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};

    auto digest1 = hash.hash_function->process(data);
    auto digest2 = hash.hash_function->process(data);

    REQUIRE(digest1 == digest2);
}

TEST_CASE("Hash - Different inputs produce different outputs", "[hash][collision]") {
    Hash hash(HashAlgo::SHA256);

    std::vector<std::uint8_t> data1 = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> data2 = {0x04, 0x05, 0x06};

    auto digest1 = hash.hash_function->process(data1);
    auto digest2 = hash.hash_function->process(data2);

    REQUIRE(digest1 != digest2);
}

TEST_CASE("Hash - Empty input produces valid hash", "[hash][edge-case]") {
    Hash hash(HashAlgo::SHA256);

    std::vector<std::uint8_t> empty_data;
    auto digest = hash.hash_function->process(empty_data);

    SECTION("Digest has correct length") {
        REQUIRE(digest.size() == 32);
    }

    SECTION("Digest is not all zeros") {
        bool has_nonzero = std::ranges::any_of(digest, [](auto byte) { return byte != 0; });
        REQUIRE(has_nonzero);
    }
}

TEST_CASE("Hash - Large input produces valid hash", "[hash][edge-case]") {
    Hash hash(HashAlgo::SHA256);

    // Create a large input (1MB)
    std::vector<std::uint8_t> large_data(1024 * 1024);
    for (size_t i = 0; i < large_data.size(); ++i) {
        large_data[i] = static_cast<std::uint8_t>(i % 256);
    }

    auto digest = hash.hash_function->process(large_data);

    SECTION("Digest has correct length") {
        REQUIRE(digest.size() == 32);
    }

    SECTION("Digest is not all zeros") {
        bool has_nonzero = std::ranges::any_of(digest, [](auto byte) { return byte != 0; });
        REQUIRE(has_nonzero);
    }
}

TEST_CASE("Hash - Single byte change produces different hash", "[hash][sensitivity]") {
    Hash hash(HashAlgo::SHA256);

    std::vector<std::uint8_t> data1 = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<std::uint8_t> data2 = {0x01, 0x02, 0x03, 0x04, 0x06}; // Last byte different

    auto digest1 = hash.hash_function->process(data1);
    auto digest2 = hash.hash_function->process(data2);

    REQUIRE(digest1 != digest2);
}

TEST_CASE("Hash - Different hash algorithms produce different outputs for same input", "[hash][algorithm-difference]") {
    std::vector<std::uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};

    Hash sha256(HashAlgo::SHA256);
    Hash sha512(HashAlgo::SHA512);
    Hash blake2b(HashAlgo::BLAKE2b);
    Hash blake2s(HashAlgo::BLAKE2s);

    auto digest_sha256 = sha256.hash_function->process(data);
    auto digest_sha512 = sha512.hash_function->process(data);
    auto digest_blake2b = blake2b.hash_function->process(data);
    auto digest_blake2s = blake2s.hash_function->process(data);

    SECTION("SHA-256 and SHA-512 produce different results") {
        REQUIRE(digest_sha256 != digest_sha512);
    }

    SECTION("SHA-256 and BLAKE2b produce different results") {
        REQUIRE(digest_sha256 != digest_blake2b);
    }

    SECTION("SHA-256 and BLAKE2s produce different results") {
        REQUIRE(digest_sha256 != digest_blake2s);
    }

    SECTION("All outputs have correct lengths") {
        REQUIRE(digest_sha256.size() == 32);
        REQUIRE(digest_sha512.size() == 64);
        REQUIRE(digest_blake2b.size() == 64);
        REQUIRE(digest_blake2s.size() == 32);
    }
}

TEST_CASE("Hash - Incremental hashing with update", "[hash][incremental]") {
    Hash hash(HashAlgo::SHA256);

    std::vector<std::uint8_t> data1 = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> data2 = {0x04, 0x05, 0x06};
    std::vector<std::uint8_t> combined = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

    SECTION("Incremental hashing matches single-pass hashing") {
        // Incremental hashing
        hash.hash_function->update(data1);
        hash.hash_function->update(data2);
        auto digest_incremental = hash.hash_function->final();

        // Single-pass hashing
        Hash hash2(HashAlgo::SHA256);
        auto digest_single = hash2.hash_function->process(combined);

        REQUIRE(digest_incremental == digest_single);
    }
}

TEST_CASE("Hash - Known test vector for SHA-256", "[hash][test-vector][sha256]") {
    Hash hash(HashAlgo::SHA256);

    // Test vector: SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    std::vector<std::uint8_t> data = {0x61, 0x62, 0x63}; // "abc"
    auto digest = hash.hash_function->process(data);

    std::vector<std::uint8_t> expected = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };

    // Convert secure_vector to regular vector for comparison
    std::vector<std::uint8_t> digest_vec(digest.begin(), digest.end());
    REQUIRE(digest_vec == expected);
}

TEST_CASE("Hash - Known test vector for empty string SHA-256", "[hash][test-vector][sha256]") {
    Hash hash(HashAlgo::SHA256);

    // Test vector: SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    std::vector<std::uint8_t> data;
    auto digest = hash.hash_function->process(data);

    std::vector<std::uint8_t> expected = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    // Convert secure_vector to regular vector for comparison
    std::vector<std::uint8_t> digest_vec(digest.begin(), digest.end());
    REQUIRE(digest_vec == expected);
}

TEST_CASE("Hash - Multiple hashes with same Hash object", "[hash][reuse]") {
    Hash hash(HashAlgo::SHA256);

    std::vector<std::uint8_t> data1 = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> data2 = {0x04, 0x05, 0x06};

    auto digest1 = hash.hash_function->process(data1);
    auto digest2 = hash.hash_function->process(data2);

    REQUIRE(digest1 != digest2);
    REQUIRE(digest1.size() == 32);
    REQUIRE(digest2.size() == 32);
}

TEST_CASE("Hash - All zeros input", "[hash][edge-case]") {
    Hash hash(HashAlgo::SHA256);

    std::vector<std::uint8_t> zeros(64, 0);
    auto digest = hash.hash_function->process(zeros);

    REQUIRE(digest.size() == 32);
    // Hash of zeros should not be all zeros
    bool has_nonzero = std::ranges::any_of(digest, [](auto byte) { return byte != 0; });
    REQUIRE(has_nonzero);
}

TEST_CASE("Hash - All ones input", "[hash][edge-case]") {
    Hash hash(HashAlgo::SHA256);

    std::vector<std::uint8_t> ones(64, 0xFF);
    auto digest = hash.hash_function->process(ones);

    REQUIRE(digest.size() == 32);
    bool has_nonzero = std::ranges::any_of(digest, [](auto byte) { return byte != 0; });
    REQUIRE(has_nonzero);
}

TEST_CASE("Hash - Copy constructor creates independent instance", "[hash][independence]") {
    Hash hash1(HashAlgo::SHA256);
    std::vector<std::uint8_t> data = {0x01, 0x02, 0x03};

    // Use hash1
    auto digest1 = hash1.hash_function->process(data);

    // Copy hash1
    Hash hash2(hash1);

    // Use hash2
    auto digest2 = hash2.hash_function->process(data);

    // Both should produce the same result
    REQUIRE(digest1 == digest2);
}

// Main function for Catch2
int main(int argc, char* argv[]) {
    // Disable all logging during tests for clean output
    Noise::DisableAllLogging();
    return Catch::Session().run(argc, argv);
}
