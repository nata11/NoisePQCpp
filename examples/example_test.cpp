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
// Noise Protocol Framework - Complete API Example
// Demonstrates protocol construction, handshake execution, and transport
//

import std;
import noise;

using namespace Noise;

// Helper function to print separator
void print_separator(std::string_view title = "") {
    if (title.empty()) {
        std::println("{}", std::string(80, '='));
    }
    else {
        std::println("\n{}", std::string(80, '='));
        std::println("  {}", title);
        std::println("{}", std::string(80, '='));
    }
}

// Helper function to print subsection
void print_subsection(std::string_view title) {
    std::println("\n{}", std::string(80, '-'));
    std::println("  {}", title);
    std::println("{}", std::string(80, '-'));
}

// Helper to print byte vector as hex
void print_bytes(std::string_view label, std::span<const std::uint8_t> data) {
    std::print("  {}: ", label);
    for (auto byte : data) {
        std::print("{:02x}", byte);
    }
    std::println(" ({} bytes)", data.size());
}

int main() {
    EnableAllLogging(); // Only works in debug builds
    print_separator("NOISE PROTOCOL FRAMEWORK - API EXAMPLE");
    std::println("This example demonstrates the complete Noise API:");
    std::println("  1. Protocol construction (from string and manual)");
    std::println("  2. Keypair generation");
    std::println("  3. Handshake state creation and configuration");
    std::println("  4. Full XX handshake execution (3 messages)");
    std::println("  5. Handshake status verification");
    std::println("  6. Post-handshake encrypted transport");
    print_separator();

    try {
        // ====================================================================
        // SECTION 1: Protocol Construction
        // ====================================================================
        print_subsection("SECTION 1: Protocol Construction");

        std::println("\n1.1 Creating protocol from string:");
        std::println("    Input: \"Noise_XX_25519_AESGCM_BLAKE2s\"");

        Protocol protocol1("Noise_XX_25519_AESGCM_BLAKE2s");

        std::println("    ✓ Protocol created successfully");
        std::println("      Pattern: {}", protocol1.pattern.String());
        std::println("      DH:      {}", protocol1.dh.String());
        std::println("      Cipher:  {}", protocol1.cipher.String());
        std::println("      Hash:    {}", protocol1.hash.String());
        std::println("      Full:    {}", protocol1.String());

        std::println("\n1.2 Creating protocol manually:");
        std::println("    Using enums: XX, X25519, AESGCM, BLAKE2s");

        Protocol protocol2(XX, X25519, AESGCM, BLAKE2s);

        std::println("    ✓ Protocol created successfully");
        std::println("      Full:    {}", protocol2.String());

        std::println("\n1.3 Verifying both methods produce identical protocols:");
        bool same = protocol1.String() == protocol2.String();
        std::println("    {} Protocols match: {}", same ? "✓" : "✗",
                     same ? "PASS" : "FAIL");

        // Use protocol1 for the rest of the example
        Protocol& protocol = protocol1;

        // ====================================================================
        // SECTION 2: Keypair Generation
        // ====================================================================
        print_subsection("SECTION 2: Keypair Generation");

        std::println("\n2.1 Generating Alice's static keypair:");
        std::println("    Algorithm: {}", protocol.dh.String());

        Dh dhAlice(protocol.dh.String());
        auto aliceStatic = dhAlice.GenerateKeypair();

        std::println("    ✓ Alice's keypair generated");
        print_bytes("      Private key", aliceStatic.private_key);
        print_bytes("      Public key", aliceStatic.public_key);

        std::println("\n2.2 Generating Bob's static keypair:");
        std::println("    Algorithm: {}", protocol.dh.String());

        Dh dhBob(protocol.dh.String());
        auto bobStatic = dhBob.GenerateKeypair();

        std::println("    ✓ Bob's keypair generated");
        print_bytes("      Private key", bobStatic.private_key);
        print_bytes("      Public key", bobStatic.public_key);

        // ====================================================================
        // SECTION 3: Handshake State Creation
        // ====================================================================
        print_subsection("SECTION 3: Handshake State Creation");

        std::println("\n3.1 Creating Alice's handshake configuration:");
        std::println("    Protocol:    {}", protocol.String());
        std::println("    Role:        Initiator");
        std::println("    Static key:  Set");

        HandshakeConfig aliceCfg{
            .protocol = protocol,
            .isInitiator = true,
            .localStatic = aliceStatic
        };

        std::println("\n3.2 Creating Bob's handshake configuration:");
        std::println("    Protocol:    {}", protocol.String());
        std::println("    Role:        Responder");
        std::println("    Static key:  Set");

        HandshakeConfig bobCfg{
            .protocol = protocol,
            .isInitiator = false,
            .localStatic = bobStatic
        };

        std::println("\n3.3 Initializing handshake states:");

        HandshakeState aliceHs(aliceCfg);
        std::println("    ✓ Alice's HandshakeState created");

        HandshakeState bobHs(bobCfg);
        std::println("    ✓ Bob's HandshakeState created");

        std::println("\n3.4 Accessing embedded states (for demonstration):");
        std::println("    Note: Most users will not need to access these during handshake");

        auto& aliceSs = aliceHs.GetSymmetricState();
        std::println("    ✓ Alice's SymmetricState accessible");

        auto& aliceCs = aliceSs.cs;
        std::println("    ✓ Alice's CipherState accessible via 'cs' public member");
        std::println("      Has key: {}", aliceCs.HasKey() ? "Yes (encrypted mode)" : "No (plaintext mode)");

        // ====================================================================
        // SECTION 4: Handshake Execution
        // ====================================================================
        print_subsection("SECTION 4: Handshake Execution (XX Pattern)");

        std::println("\nXX Pattern structure:");
        std::println("  -> e");
        std::println("  <- e, ee, s, es");
        std::println("  -> s, se");

        // Message 1: Alice -> Bob
        std::println("\n4.1 Message 1: Alice (Initiator) -> Bob");
        std::println("    Tokens: e");

        std::vector<std::uint8_t> alicePlaintext1 = {
            'a', 'l', 'i', 'c', 'e', ' ', 'e', ' ',
            'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't'
        };
        std::println("    Payload: \"{}\"", std::string_view(
                         reinterpret_cast<const char*>(alicePlaintext1.data()),
                         alicePlaintext1.size()));

        auto aliceMsg1 = aliceHs.WriteMessage(alicePlaintext1);
        std::println("    ✓ Alice wrote message");
        print_bytes("      Message", aliceMsg1);
        std::println("      Handshake complete: {}", aliceHs.GetStatus().IsComplete() ? "Yes" : "No");

        auto bobRecv1 = bobHs.ReadMessage(aliceMsg1);
        std::println("    ✓ Bob read message");
        std::println("      Payload: \"{}\"", std::string_view(
                         reinterpret_cast<const char*>(bobRecv1.data()),
                         bobRecv1.size()));
        std::println("      Payload matches: {}", bobRecv1 == alicePlaintext1 ? "Yes ✓" : "No ✗");
        std::println("      Handshake complete: {}", bobHs.GetStatus().IsComplete() ? "Yes" : "No");

        // Message 2: Bob -> Alice
        std::vector<std::uint8_t> bobPlaintext2 = {
            'b', 'o', 'b', ' ', '2', ' ', 'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't'
        };
        std::println("\n4.2 Message 2: Bob (Responder) -> Alice");
        std::println("    Tokens: e, ee, s, es");
        std::println("    Payload: \"{}\"", std::string_view(
                         reinterpret_cast<const char*>(bobPlaintext2.data()),
                         bobPlaintext2.size()));

        auto bobMsg2 = bobHs.WriteMessage(bobPlaintext2);
        std::println("    ✓ Bob wrote message");
        print_bytes("      Message", bobMsg2);
        std::println("      Handshake complete: {}", bobHs.GetStatus().IsComplete() ? "Yes" : "No");

        auto aliceRecv2 = aliceHs.ReadMessage(bobMsg2);
        std::println("    ✓ Alice read message");
        std::println("      Payload: \"{}\"", std::string_view(
                         reinterpret_cast<const char*>(aliceRecv2.data()),
                         aliceRecv2.size()));
        std::println("      Payload matches: {}", aliceRecv2 == bobPlaintext2 ? "Yes ✓" : "No ✗");
        std::println("      Handshake complete: {}", aliceHs.GetStatus().IsComplete() ? "Yes" : "No");

        // Message 3: Alice -> Bob
        std::vector<std::uint8_t> alicePlaintext3 = {
            'a', 'l', 'i', 'c', 'e', ' ', '3', ' ',
            'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't'
        };
        std::println("\n4.3 Message 3: Alice (Initiator) -> Bob");
        std::println("    Tokens: s, se");
        std::println("    Payload: \"{}\"", std::string_view(
                         reinterpret_cast<const char*>(alicePlaintext3.data()),
                         alicePlaintext3.size()));

        auto aliceMsg3 = aliceHs.WriteMessage(alicePlaintext3);
        std::println("    ✓ Alice wrote message");
        print_bytes("      Message", aliceMsg3);
        std::println("      Handshake complete: {} ✓", aliceHs.GetStatus().IsComplete() ? "Yes" : "No");

        auto bobRecv3 = bobHs.ReadMessage(aliceMsg3);
        std::println("    ✓ Bob read message");
        std::println("      Payload: \"{}\"", std::string_view(
                 reinterpret_cast<const char*>(bobRecv3.data()),
                 bobRecv3.size()));
        std::println("      Payload matches: {}", bobRecv3 == alicePlaintext3 ? "Yes ✓" : "No ✗");

        std::println("      Payload: ({} bytes)", bobRecv3.size());
        std::println("      Handshake complete: {} ✓", bobHs.GetStatus().IsComplete() ? "Yes" : "No");

        // ====================================================================
        // SECTION 5: Handshake Status Verification
        // ====================================================================
        print_subsection("SECTION 5: Handshake Status Verification");

        std::println("\n5.1 Retrieving handshake status:");

        auto aliceStatus = aliceHs.GetStatus();
        std::println("    ✓ Alice's status retrieved");

        auto bobStatus = bobHs.GetStatus();
        std::println("    ✓ Bob's status retrieved");

        std::println("\n5.2 Verifying handshake hash:");
        print_bytes("    Alice's hash", aliceStatus.handshakeHash);
        print_bytes("    Bob's hash", bobStatus.handshakeHash);
        bool hashMatch = aliceStatus.handshakeHash == bobStatus.handshakeHash;
        std::println("    {} Handshake hashes match: {}", hashMatch ? "✓" : "✗", hashMatch ? "PASS" : "FAIL");

        std::println("\n5.3 Verifying ephemeral keys:");
        std::println("    Note: Ephemeral keys are PublicKey (std::vector<std::uint8_t>)");
        print_bytes("    Alice's local ephemeral", aliceStatus.localEphemeral);
        print_bytes("    Bob's remote ephemeral", bobStatus.remoteEphemeral);
        bool ephemMatch1 = aliceStatus.localEphemeral == bobStatus.remoteEphemeral;
        std::println("    {} Alice's ephemeral == Bob's remote: {}", ephemMatch1 ? "✓" : "✗",
                     ephemMatch1 ? "PASS" : "FAIL");

        print_bytes("    Bob's local ephemeral", bobStatus.localEphemeral);
        print_bytes("    Alice's remote ephemeral", aliceStatus.remoteEphemeral);
        bool ephemMatch2 = bobStatus.localEphemeral == aliceStatus.remoteEphemeral;
        std::println("    {} Bob's ephemeral == Alice's remote: {}", ephemMatch2 ? "✓" : "✗",
                     ephemMatch2 ? "PASS" : "FAIL");

        std::println("\n5.4 Verifying static keys:");
        print_bytes("    Alice's remote static", aliceStatus.remoteStatic);
        print_bytes("    Bob's original static (public)", bobStatic.public_key);
        bool staticMatch1 = aliceStatus.remoteStatic == bobStatic.public_key;
        std::println("    {} Alice learned Bob's static key: {}", staticMatch1 ? "✓" : "✗",
                     staticMatch1 ? "PASS" : "FAIL");

        print_bytes("    Bob's remote static", bobStatus.remoteStatic);
        print_bytes("    Alice's original static (public)", aliceStatic.public_key);
        bool staticMatch2 = bobStatus.remoteStatic == aliceStatic.public_key;
        std::println("    {} Bob learned Alice's static key: {}", staticMatch2 ? "✓" : "✗",
                     staticMatch2 ? "PASS" : "FAIL");

        // ====================================================================
        // SECTION 6: Post-Handshake Transport
        // ====================================================================
        print_subsection("SECTION 6: Post-Handshake Encrypted Transport");

        std::println("\n6.1 Extracting CipherState objects:");
        std::println("    Note: CipherStates are stored in std::optional<std::pair>");

        if (!aliceStatus.cipherStates.has_value() || !bobStatus.cipherStates.has_value()) {
            throw std::runtime_error("Cipher states not available");
        }

        auto& aliceTx = aliceStatus.cipherStates->first;
        auto& aliceRx = aliceStatus.cipherStates->second;
        std::println("    ✓ Alice: Tx = first, Rx = second");
        std::println("      Tx has key: {}", aliceTx.HasKey() ? "Yes" : "No");
        std::println("      Rx has key: {}", aliceRx.HasKey() ? "Yes" : "No");

        auto& bobRx = bobStatus.cipherStates->first; // Reversed!
        auto& bobTx = bobStatus.cipherStates->second; // Reversed!
        std::println("    ✓ Bob:   Rx = first, Tx = second (reversed!)");
        std::println("      Tx has key: {}", bobTx.HasKey() ? "Yes" : "No");
        std::println("      Rx has key: {}", bobRx.HasKey() ? "Yes" : "No");

        // Alice -> Bob transport
        std::println("\n6.2 Transport message: Alice -> Bob");

        std::vector<std::uint8_t> alicePlaintext = {
            'a', 'l', 'i', 'c', 'e', ' ', 't', 'r', 'a', 'n', 's', 'p', 'o', 'r', 't', ' ',
            'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't'
        };
        std::println("    Plaintext: \"{}\"", std::string_view(
                         reinterpret_cast<const char*>(alicePlaintext.data()),
                         alicePlaintext.size()));

        auto aliceMsg4 = aliceTx.EncryptWithAd({}, alicePlaintext);
        std::println("    ✓ Alice encrypted");
        print_bytes("      Ciphertext", aliceMsg4);
        std::println("      Overhead: {} bytes", aliceMsg4.size() - alicePlaintext.size());
        //std::println("Failing here");
        auto bobRecv4 = bobRx.DecryptWithAd({}, aliceMsg4);
        std::println("    ✓ Bob decrypted");
        std::println("      Plaintext: \"{}\"", std::string_view(
                         reinterpret_cast<const char*>(bobRecv4.data()),
                         bobRecv4.size()));
        bool transportMatch1 = bobRecv4 == alicePlaintext;
        std::println("      {} Message matches: {}", transportMatch1 ? "✓" : "✗", transportMatch1 ? "PASS" : "FAIL");

        // Bob -> Alice transport
        std::println("\n6.3 Transport message: Bob -> Alice");

        std::vector<std::uint8_t> bobPlaintext = {
            'b', 'o', 'b', ' ', 't', 'r', 'a', 'n', 's', 'p', 'o', 'r', 't', ' ',
            'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't'
        };
        std::println("    Plaintext: \"{}\"", std::string_view(
                         reinterpret_cast<const char*>(bobPlaintext.data()),
                         bobPlaintext.size()));

        auto bobMsg5 = bobTx.EncryptWithAd({}, bobPlaintext);
        std::println("    ✓ Bob encrypted");
        print_bytes("      Ciphertext", bobMsg5);
        std::println("      Overhead: {} bytes", bobMsg5.size() - bobPlaintext.size());

        auto aliceRecv5 = aliceRx.DecryptWithAd({}, bobMsg5);
        std::println("    ✓ Alice decrypted");
        std::println("      Plaintext: \"{}\"", std::string_view(
                         reinterpret_cast<const char*>(aliceRecv5.data()),
                         aliceRecv5.size()));
        bool transportMatch2 = aliceRecv5 == bobPlaintext;
        std::println("      {} Message matches: {}", transportMatch2 ? "✓" : "✗", transportMatch2 ? "PASS" : "FAIL");

        // ====================================================================
        // FINAL SUMMARY
        // ====================================================================
        print_separator("EXAMPLE COMPLETE");
        std::println("\n✓✓✓ All operations completed successfully! ✓✓✓\n");
        std::println("Summary:");
        std::println("  ✓ Protocol construction (string and manual)");
        std::println("  ✓ Keypair generation for Alice and Bob");
        std::println("  ✓ Handshake state initialization");
        std::println("  ✓ XX handshake execution (3 messages)");
        std::println("  ✓ Handshake hash verification");
        std::println("  ✓ Ephemeral key verification");
        std::println("  ✓ Static key verification");
        std::println("  ✓ Bidirectional encrypted transport");
        print_separator();

        return 0;
    }
    catch (const std::exception& e) {
        std::println("\n✗✗✗ ERROR: {} ✗✗✗", e.what());
        return 1;
    }
}
