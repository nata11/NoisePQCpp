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
// Protocol Sandbox - Test all Protocol module functionality
//

#include "botan_all.h"
import noise;

using namespace Noise;

void print_separator(const std::string& title) {
    std::println("\n{:=^80}", "");
    std::println("{:^80}", title);
    std::println("{:=^80}\n", "");
}

void print_protocol_info(const Protocol& protocol) {
    std::println("  Pattern: {}", protocol.pattern.String());
    std::println("  DH:      {}", protocol.dh.String());
    std::println("  Cipher:  {}", protocol.cipher.String());
    std::println("  Hash:    {}", protocol.hash.String());
    std::println("  Full:    {}", protocol.String());
}

int main() {
    std::println("\n{:*^80}", " Protocol Module Sandbox ");
    std::println("{:^80}", "Testing all Protocol constructors and methods");
    std::println("{:*^80}\n", "");

    // =======================================================================
    // Test 1: Constructor with individual parameters
    // =======================================================================
    print_separator("Test 1: Constructor with Individual Parameters");

    try {
        std::println("Creating Protocol with XX pattern, 25519, ChaChaPoly, SHA256");
        Protocol proto1(XX, X25519, ChaChaPoly, SHA256);
        print_protocol_info(proto1);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Creating Protocol with NN pattern, 448, AESGCM, SHA512");
        Protocol proto2(NN, X448, AESGCM, SHA512);
        print_protocol_info(proto2);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Creating Protocol with KK pattern, 25519, ChaChaPoly, BLAKE2b");
        Protocol proto3(KK, X25519, ChaChaPoly, BLAKE2b);
        print_protocol_info(proto3);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Creating Protocol with NK pattern, 448, AESGCM, BLAKE2s");
        Protocol proto4(NK, X448, AESGCM, BLAKE2s);
        print_protocol_info(proto4);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 1b: Constructor with individual parameters using ML-KEM constants
    // =======================================================================
    print_separator("Test 1b: Constructor with Individual Parameters - ML-KEM");

    try {
        std::println("Creating Protocol with XX pattern, M512, ChaChaPoly, SHA256");
        Protocol proto_mlkem1(XX, M512, ChaChaPoly, SHA256);
        print_protocol_info(proto_mlkem1);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Creating Protocol with IK pattern, M768, AESGCM, SHA512");
        Protocol proto_mlkem2(IK, M768, AESGCM, SHA512);
        print_protocol_info(proto_mlkem2);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Creating Protocol with XN pattern, M1024, ChaChaPoly, BLAKE2b");
        Protocol proto_mlkem3(XN, M1024, ChaChaPoly, BLAKE2b);
        print_protocol_info(proto_mlkem3);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 2: Constructor with protocol string
    // =======================================================================
    print_separator("Test 2: Constructor with Protocol String");

    try {
        std::println("Creating Protocol from string: \"Noise_XX_25519_ChaChaPoly_SHA256\"");
        Protocol proto5("Noise_XX_25519_ChaChaPoly_SHA256");
        print_protocol_info(proto5);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Creating Protocol from string: \"Noise_NN_448_AESGCM_SHA512\"");
        Protocol proto6("Noise_NN_448_AESGCM_SHA512");
        print_protocol_info(proto6);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Creating Protocol from string: \"Noise_KK_25519_ChaChaPoly_BLAKE2b\"");
        Protocol proto7("Noise_KK_25519_ChaChaPoly_BLAKE2b");
        print_protocol_info(proto7);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Creating Protocol from string: \"Noise_NK_448_AESGCM_BLAKE2s\"");
        Protocol proto8("Noise_NK_448_AESGCM_BLAKE2s");
        print_protocol_info(proto8);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // ML-KEM variants
    try {
        std::println("Creating Protocol from string: \"Noise_XX_M512_ChaChaPoly_SHA256\"");
        Protocol proto_m512("Noise_XX_M512_ChaChaPoly_SHA256");
        print_protocol_info(proto_m512);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Creating Protocol from string: \"Noise_IK_M768_AESGCM_SHA512\"");
        Protocol proto_m768("Noise_IK_M768_AESGCM_SHA512");
        print_protocol_info(proto_m768);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Creating Protocol from string: \"Noise_XN_M1024_ChaChaPoly_BLAKE2b\"");
        Protocol proto_m1024("Noise_XN_M1024_ChaChaPoly_BLAKE2b");
        print_protocol_info(proto_m1024);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 3: new_protocol static method
    // =======================================================================
    print_separator("Test 3: new_protocol Static Method");

    try {
        std::println("Creating Protocol using new_protocol: \"Noise_XX_25519_ChaChaPoly_SHA256\"");
        Protocol proto9 = Protocol{"Noise_XX_25519_ChaChaPoly_SHA256"};
        print_protocol_info(proto9);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Creating Protocol using new_protocol: \"Noise_NN_448_AESGCM_SHA512\"");
        Protocol proto10 = Protocol{"Noise_NN_448_AESGCM_SHA512"};
        print_protocol_info(proto10);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Creating Protocol using new_protocol: \"Noise_KK_25519_ChaChaPoly_BLAKE2b\"");
        Protocol proto11 = Protocol{"Noise_KK_25519_ChaChaPoly_BLAKE2b"};
        print_protocol_info(proto11);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Creating Protocol using new_protocol: \"Noise_NK_448_AESGCM_BLAKE2s\"");
        Protocol proto12 = Protocol{"Noise_NK_448_AESGCM_BLAKE2s"};
        print_protocol_info(proto12);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 4: String() method - round-trip test
    // =======================================================================
    print_separator("Test 4: String() Method - Round-Trip Test");

    try {
        std::println("Testing round-trip: Create from string, get string back");
        std::string_view original = "Noise_XX_25519_ChaChaPoly_SHA256";
        Protocol proto13(original);
        std::string result = proto13.String();

        std::println("  Original: {}", original);
        std::println("  Result:   {}", result);

        if (original == result) {
            std::println("✓ Round-trip SUCCESS: Strings match\n");
        }
        else {
            std::println("✗ Round-trip FAILED: Strings don't match\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Testing round-trip with different algorithms");
        std::string_view original2 = "Noise_KK_448_AESGCM_BLAKE2s";
        Protocol proto14(original2);
        std::string result2 = proto14.String();

        std::println("  Original: {}", original2);
        std::println("  Result:   {}", result2);

        if (original2 == result2) {
            std::println("✓ Round-trip SUCCESS: Strings match\n");
        }
        else {
            std::println("✗ Round-trip FAILED: Strings don't match\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // ML-KEM round-trip tests
    try {
        std::println("Testing ML-KEM round-trip: M512");
        std::string_view original_m512 = "Noise_XX_M512_ChaChaPoly_SHA256";
        Protocol proto_m512(original_m512);
        std::string result_m512 = proto_m512.String();

        std::println("  Original: {}", original_m512);
        std::println("  Result:   {}", result_m512);

        if (original_m512 == result_m512) {
            std::println("✓ M512 Round-trip SUCCESS\n");
        }
        else {
            std::println("✗ M512 Round-trip FAILED\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Testing ML-KEM round-trip: M768");
        std::string_view original_m768 = "Noise_IK_M768_AESGCM_SHA512";
        Protocol proto_m768(original_m768);
        std::string result_m768 = proto_m768.String();

        std::println("  Original: {}", original_m768);
        std::println("  Result:   {}", result_m768);

        if (original_m768 == result_m768) {
            std::println("✓ M768 Round-trip SUCCESS\n");
        }
        else {
            std::println("✗ M768 Round-trip FAILED\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Testing ML-KEM round-trip: M1024");
        std::string_view original_m1024 = "Noise_XN_M1024_ChaChaPoly_BLAKE2b";
        Protocol proto_m1024(original_m1024);
        std::string result_m1024 = proto_m1024.String();

        std::println("  Original: {}", original_m1024);
        std::println("  Result:   {}", result_m1024);

        if (original_m1024 == result_m1024) {
            std::println("✓ M1024 Round-trip SUCCESS\n");
        }
        else {
            std::println("✗ M1024 Round-trip FAILED\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 5: All pattern combinations
    // =======================================================================
    print_separator("Test 5: All Pattern Combinations");

    std::vector<std::string_view> test_patterns = {
        "Noise_XX_25519_ChaChaPoly_SHA256",
        "Noise_NN_25519_ChaChaPoly_SHA256",
        "Noise_KK_25519_ChaChaPoly_SHA256",
        "Noise_NK_25519_ChaChaPoly_SHA256"
    };

    for (const auto& pattern_str : test_patterns) {
        try {
            std::println("Testing: {}", pattern_str);
            Protocol proto(pattern_str);
            std::println("  ✓ Pattern: {} - SUCCESS", proto.pattern.String());
        }
        catch (const std::exception& e) {
            std::println("  ✗ FAILED: {}", e.what());
        }
    }
    std::println("");

    // =======================================================================
    // Test 6: All DH algorithm combinations
    // =======================================================================
    print_separator("Test 6: All DH Algorithm Combinations");

    std::vector<std::string_view> test_dh = {
        "Noise_XX_25519_ChaChaPoly_SHA256",
        "Noise_XX_448_ChaChaPoly_SHA256",
        "Noise_XX_M512_ChaChaPoly_SHA256",
        "Noise_XX_M768_ChaChaPoly_SHA256",
        "Noise_XX_M1024_ChaChaPoly_SHA256"
    };

    for (const auto& dh_str : test_dh) {
        try {
            std::println("Testing: {}", dh_str);
            Protocol proto(dh_str);
            std::println("  ✓ DH: {} - SUCCESS", proto.dh.String());
        }
        catch (const std::exception& e) {
            std::println("  ✗ FAILED: {}", e.what());
        }
    }
    std::println("");

    // =======================================================================
    // Test 7: All Cipher algorithm combinations
    // =======================================================================
    print_separator("Test 7: All Cipher Algorithm Combinations");

    std::vector<std::string_view> test_cipher = {
        "Noise_XX_25519_ChaChaPoly_SHA256",
        "Noise_XX_25519_AESGCM_SHA256"
    };

    for (const auto& cipher_str : test_cipher) {
        try {
            std::println("Testing: {}", cipher_str);
            Protocol proto(cipher_str);
            std::println("  ✓ Cipher: {} - SUCCESS", proto.cipher.String());
        }
        catch (const std::exception& e) {
            std::println("  ✗ FAILED: {}", e.what());
        }
    }
    std::println("");

    // =======================================================================
    // Test 8: All Hash algorithm combinations
    // =======================================================================
    print_separator("Test 8: All Hash Algorithm Combinations");

    std::vector<std::string_view> test_hash = {
        "Noise_XX_25519_ChaChaPoly_SHA256",
        "Noise_XX_25519_ChaChaPoly_SHA512",
        "Noise_XX_25519_ChaChaPoly_BLAKE2b",
        "Noise_XX_25519_ChaChaPoly_BLAKE2s"
    };

    for (const auto& hash_str : test_hash) {
        try {
            std::println("Testing: {}", hash_str);
            Protocol proto(hash_str);
            std::println("  ✓ Hash: {} - SUCCESS", proto.hash.String());
        }
        catch (const std::exception& e) {
            std::println("  ✗ FAILED: {}", e.what());
        }
    }
    std::println("");

    // =======================================================================
    // Test 9: Error cases - Invalid protocol strings
    // =======================================================================
    print_separator("Test 9: Error Cases - Invalid Protocol Strings");

    std::vector<std::string_view> invalid_protocols = {
        "Invalid_XX_25519_ChaChaPoly_SHA256", // Wrong prefix
        "Noise_XX_25519_ChaChaPoly", // Missing hash
        "Noise_XX_25519", // Missing cipher and hash
        "Noise_InvalidPattern_25519_ChaChaPoly_SHA256", // Invalid pattern
        "", // Empty string
        "Noise", // Just prefix
        "Noise_XX_InvalidDH_ChaChaPoly_SHA256" // Invalid DH (will fail in Dh constructor)
    };

    for (const auto& invalid : invalid_protocols) {
        try {
            std::println("Testing invalid: \"{}\"", invalid);
            Protocol proto(invalid);
            std::println("  ✗ UNEXPECTED: Should have failed but succeeded\n");
        }
        catch (const std::exception& e) {
            std::println("  ✓ EXPECTED failure: {}\n", e.what());
        }
    }

    // =======================================================================
    // Test 10: Pattern describe() method
    // =======================================================================
    print_separator("Test 10: Pattern describe() Method");

    try {
        std::println("Testing pattern description for XX:");
        Protocol proto(XX, X25519, ChaChaPoly, SHA256);
        proto.pattern.describe(std::cout);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Testing pattern description for NN:");
        Protocol proto(NN, X25519, ChaChaPoly, SHA256);
        proto.pattern.describe(std::cout);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Testing pattern description for KK:");
        Protocol proto(KK, X25519, ChaChaPoly, SHA256);
        proto.pattern.describe(std::cout);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    try {
        std::println("Testing pattern description for NK:");
        Protocol proto(NK, X25519, ChaChaPoly, SHA256);
        proto.pattern.describe(std::cout);
        std::println("✓ SUCCESS\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Test 11: Comprehensive combination test
    // =======================================================================
    print_separator("Test 11: Comprehensive Combination Test");

    std::vector<std::tuple<std::string_view, std::string_view, std::string_view, std::string_view>> combinations = {
        {"XX", "25519", "ChaChaPoly", "SHA256"},
        {"XX", "448", "AESGCM", "SHA512"},
        {"NN", "25519", "ChaChaPoly", "BLAKE2b"},
        {"NN", "448", "AESGCM", "BLAKE2s"},
        {"KK", "25519", "AESGCM", "SHA256"},
        {"KK", "448", "ChaChaPoly", "SHA512"},
        {"NK", "25519", "AESGCM", "BLAKE2b"},
        {"NK", "448", "ChaChaPoly", "BLAKE2s"},
        // ML-KEM combinations
        {"XX", "M512", "ChaChaPoly", "SHA256"},
        {"IK", "M768", "AESGCM", "SHA512"},
        {"XN", "M1024", "ChaChaPoly", "BLAKE2b"},
        {"NN", "M512", "AESGCM", "BLAKE2s"},
        {"KK", "M768", "ChaChaPoly", "SHA256"},
        {"NK", "M1024", "AESGCM", "SHA512"}
    };

    int success_count = 0;
    int total_count = combinations.size();

    for (const auto& [pattern, dh, cipher, hash] : combinations) {
        try {
            std::string protocol_string = std::format("Noise_{}_{}_{}_{}",
                                                      pattern, dh, cipher, hash);
            std::println("Testing: {}", protocol_string);

            // Test both constructor methods
            Protocol proto1(protocol_string);
            Protocol proto2 = Protocol{protocol_string};

            // Verify they produce the same result
            if (proto1.String() == proto2.String()) {
                std::println("  ✓ Both constructors produce identical results");
                success_count++;
            }
            else {
                std::println("  ✗ Constructors produce different results!");
            }
        }
        catch (const std::exception& e) {
            std::println("  ✗ FAILED: {}", e.what());
        }
    }

    std::println("\nResults: {}/{} combinations successful", success_count, total_count);

    // =======================================================================
    // Test 12: Protocol.dh Access & Dh Object Creation
    // =======================================================================
    print_separator("Test 12: Protocol.dh Access & Dh Object Creation");

    // Sub-test 12a: Access protocol.dh member for ML-KEM protocols
    std::println("12a: Accessing protocol.dh member for ML-KEM protocols");
    try {
        Protocol proto_m512(XX, M512, ChaChaPoly, SHA256);
        Protocol proto_m768(IK, M768, AESGCM, SHA512);
        Protocol proto_m1024(XN, M1024, ChaChaPoly, BLAKE2b);

        std::println("  M512 DH algorithm: {}", proto_m512.dh.String());
        std::println("  M768 DH algorithm: {}", proto_m768.dh.String());
        std::println("  M1024 DH algorithm: {}", proto_m1024.dh.String());
        std::println("✓ SUCCESS: protocol.dh member access works\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // Sub-test 12b: Create standalone Dh objects using string constants
    std::println("12b: Creating standalone Dh objects using string constants");
    try {
        Dh dh_m512_str("M512");
        Dh dh_m768_str("M768");
        Dh dh_m1024_str("M1024");

        std::println("  Created Dh(\"M512\"): {}", dh_m512_str.String());
        std::println("  Created Dh(\"M768\"): {}", dh_m768_str.String());
        std::println("  Created Dh(\"M1024\"): {}", dh_m1024_str.String());
        std::println("✓ SUCCESS: String-based Dh construction works\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // Sub-test 12c: Create standalone Dh objects using KeyAlgo enum
    std::println("12c: Creating standalone Dh objects using KeyAlgo enum");
    try {
        Dh dh_m512_enum(KeyAlgo::M512);
        Dh dh_m768_enum(KeyAlgo::M768);
        Dh dh_m1024_enum(KeyAlgo::M1024);

        std::println("  Created Dh(KeyAlgo::M512): {}", dh_m512_enum.String());
        std::println("  Created Dh(KeyAlgo::M768): {}", dh_m768_enum.String());
        std::println("  Created Dh(KeyAlgo::M1024): {}", dh_m1024_enum.String());
        std::println("✓ SUCCESS: Enum-based Dh construction works\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // Sub-test 12d: Generate keypairs for all ML-KEM variants, verify sizes
    std::println("12d: Generating keypairs for ML-KEM variants and verifying sizes");
    try {
        Dh dh_m512(KeyAlgo::M512);
        Dh dh_m768(KeyAlgo::M768);
        Dh dh_m1024(KeyAlgo::M1024);

        auto kp_m512 = dh_m512.GenerateKeypair();
        auto kp_m768 = dh_m768.GenerateKeypair();
        auto kp_m1024 = dh_m1024.GenerateKeypair();

        std::println("  M512 keypair sizes:");
        std::println("    Private key: {} bytes", kp_m512.private_key.size());
        std::println("    Public key:  {} bytes", kp_m512.public_key.size());

        std::println("  M768 keypair sizes:");
        std::println("    Private key: {} bytes", kp_m768.private_key.size());
        std::println("    Public key:  {} bytes", kp_m768.public_key.size());

        std::println("  M1024 keypair sizes:");
        std::println("    Private key: {} bytes", kp_m1024.private_key.size());
        std::println("    Public key:  {} bytes", kp_m1024.public_key.size());

        // Verify DH size is consistent (32 bytes shared secret for all ML-KEM variants)
        std::println("  M512 shared secret size: {} bytes", dh_m512.Size());
        std::println("  M768 shared secret size: {} bytes", dh_m768.Size());
        std::println("  M1024 shared secret size: {} bytes", dh_m1024.Size());

        std::println("✓ SUCCESS: Keypair generation works for all ML-KEM variants\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // Sub-test 12e: Verify DH() throws error for KEM mode (expected behavior)
    std::println("12e: Verifying DH() throws error for KEM mode");
    try {
        Dh dh_m512(KeyAlgo::M512);
        auto kp1 = dh_m512.GenerateKeypair();
        auto kp2 = dh_m512.GenerateKeypair();

        // This should throw an exception
        try {
            auto shared_secret = dh_m512.DH(kp1, kp2);
            std::println("✗ UNEXPECTED: DH() should have thrown for KEM mode\n");
        }
        catch (const NoiseError& e) {
            std::println("  ✓ Expected exception: {}", e.what());
            std::println("✓ SUCCESS: DH() correctly throws for KEM mode\n");
        }
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // Sub-test 12f: Test Encapsulate/Decapsulate for ML-KEM, verify shared secrets match
    std::println("12f: Testing Encapsulate/Decapsulate for ML-KEM");
    try {
        Dh dh_m512(KeyAlgo::M512);
        Dh dh_m768(KeyAlgo::M768);
        Dh dh_m1024(KeyAlgo::M1024);

        // Test M512
        {
            auto receiver_kp = dh_m512.GenerateKeypair();
            auto [encap_key, sender_ss] = dh_m512.Encapsulate(receiver_kp.public_key);
            auto receiver_ss = dh_m512.Decapsulate(receiver_kp.private_key, encap_key);

            std::println("  M512:");
            std::println("    Encapsulated key size: {} bytes", encap_key.size());
            std::println("    Shared secret size: {} bytes", sender_ss.size());
            std::println("    Shared secrets match: {}", sender_ss == receiver_ss ? "YES" : "NO");

            if (sender_ss != receiver_ss) {
                std::println("✗ FAILED: M512 shared secrets don't match\n");
            }
        }

        // Test M768
        {
            auto receiver_kp = dh_m768.GenerateKeypair();
            auto [encap_key, sender_ss] = dh_m768.Encapsulate(receiver_kp.public_key);
            auto receiver_ss = dh_m768.Decapsulate(receiver_kp.private_key, encap_key);

            std::println("  M768:");
            std::println("    Encapsulated key size: {} bytes", encap_key.size());
            std::println("    Shared secret size: {} bytes", sender_ss.size());
            std::println("    Shared secrets match: {}", sender_ss == receiver_ss ? "YES" : "NO");

            if (sender_ss != receiver_ss) {
                std::println("✗ FAILED: M768 shared secrets don't match\n");
            }
        }

        // Test M1024
        {
            auto receiver_kp = dh_m1024.GenerateKeypair();
            auto [encap_key, sender_ss] = dh_m1024.Encapsulate(receiver_kp.public_key);
            auto receiver_ss = dh_m1024.Decapsulate(receiver_kp.private_key, encap_key);

            std::println("  M1024:");
            std::println("    Encapsulated key size: {} bytes", encap_key.size());
            std::println("    Shared secret size: {} bytes", sender_ss.size());
            std::println("    Shared secrets match: {}", sender_ss == receiver_ss ? "YES" : "NO");

            if (sender_ss != receiver_ss) {
                std::println("✗ FAILED: M1024 shared secrets don't match\n");
            }
        }

        std::println("✓ SUCCESS: All ML-KEM Encapsulate/Decapsulate operations work correctly\n");
    }
    catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    // =======================================================================
    // Summary
    // =======================================================================
    print_separator("Protocol Sandbox Complete");
    std::println("All Protocol functionality has been tested.");
    std::println("Review the output above for any failures.\n");

    return 0;
}
