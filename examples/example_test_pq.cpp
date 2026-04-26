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
// PQNoise Protocol Framework - Complete API Example
// Demonstrates protocol construction, handshake execution, and transport
// using Post-Quantum KEM (ML-KEM-768) with pqXX pattern
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
    print_separator("PQNOISE PROTOCOL FRAMEWORK - API EXAMPLE");
    std::println("This example demonstrates the complete PQNoise API:");
    std::println("  1. Protocol construction (from string and manual)");
    std::println("  2. Keypair generation (ML-KEM-768)");
    std::println("  3. Handshake state creation and configuration");
    std::println("  4. Full pqXX handshake execution (4 messages)");
    std::println("  5. Handshake status verification");
    std::println("  6. Post-handshake encrypted transport");
    print_separator();

    try {
        // ====================================================================
        // SECTION 1: Protocol Construction
        // ====================================================================
        print_subsection("SECTION 1: Protocol Construction");

        std::println("\n1.1 Creating protocol from string:");
        std::println("    Input: \"Noise_pqXX_M768_AESGCM_BLAKE2s\"");

        Protocol protocol1("Noise_pqXX_M768_AESGCM_BLAKE2s");

        std::println("    ✓ Protocol created successfully");
        std::println("      Pattern: {}", protocol1.pattern.String());
        std::println("      DH/KEM: {}", protocol1.dh.String());
        std::println("      Cipher: {}", protocol1.cipher.String());
        std::println("      Hash:   {}", protocol1.hash.String());
        std::println("      Full:   {}", protocol1.String());

        std::println("\n1.2 Creating protocol manually:");
        std::println("    Using enums: pqXX, M768, AESGCM, BLAKE2s");

        Protocol protocol2(pqXX, M768, AESGCM, BLAKE2s);

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
        std::println("    Algorithm: {} (ML-KEM-768)", protocol.dh.String());

        Dh dhAlice(protocol.dh.String());
        auto aliceStatic = dhAlice.GenerateKeypair();

        std::println("    ✓ Alice's keypair generated");
        std::println("      Private key: ({} bytes)", aliceStatic.private_key.size());
        std::println("      Public key:  ({} bytes)", aliceStatic.public_key.size());

        std::println("\n2.2 Generating Bob's static keypair:");
        std::println("    Algorithm: {} (ML-KEM-768)", protocol.dh.String());

        Dh dhBob(protocol.dh.String());
        auto bobStatic = dhBob.GenerateKeypair();

        std::println("    ✓ Bob's keypair generated");
        std::println("      Private key: ({} bytes)", bobStatic.private_key.size());
        std::println("      Public key:  ({} bytes)", bobStatic.public_key.size());

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
        print_subsection("SECTION 4: Handshake Execution (pqXX Pattern)");

        std::println("\npqXX Pattern structure:");
        std::println("  -> e");
        std::println("  <- ekem, s");
        std::println("  -> skem, s");
        std::println("  <- skem");

        // Message 1: Alice -> Bob
        std::println("\n4.1 Message 1: Alice (Initiator) -> Bob");
        std::println("    Tokens: e");

        std::vector<std::uint8_t> alicePlaintext1 = {
            'a', 'l', 'i', 'c', 'e', ' ', 'p', 'q', ' ',
            'e', ' ', 'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't'
        };
        std::println("    Payload: \"{}\"", std::string_view(
                         reinterpret_cast<const char*>(alicePlaintext1.data()),
                         alicePlaintext1.size()));

        auto aliceMsg1 = aliceHs.WriteMessage(alicePlaintext1);
        std::println("    ✓ Alice wrote message");
        std::println("      Message size: {} bytes", aliceMsg1.size());
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
            'b', 'o', 'b', ' ', 'p', 'q', ' ',
            'e', 'k', 'e', 'm', ' ', 's', ' ',
            'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't'
        };
        std::println("\n4.2 Message 2: Bob (Responder) -> Alice");
        std::println("    Tokens: ekem, s");
        std::println("    Payload: \"{}\"", std::string_view(
                         reinterpret_cast<const char*>(bobPlaintext2.data()),
                         bobPlaintext2.size()));

        auto bobMsg2 = bobHs.WriteMessage(bobPlaintext2);
        std::println("    ✓ Bob wrote message");
        std::println("      Message size: {} bytes", bobMsg2.size());
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
            'a', 'l', 'i', 'c', 'e', ' ', 'p', 'q', ' ',
            's', 'k', 'e', 'm', ' ', 's', ' ',
            'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't'
        };
        std::println("\n4.3 Message 3: Alice (Initiator) -> Bob");
        std::println("    Tokens: skem, s");
        std::println("    Payload: \"{}\"", std::string_view(
                         reinterpret_cast<const char*>(alicePlaintext3.data()),
                         alicePlaintext3.size()));

        auto aliceMsg3 = aliceHs.WriteMessage(alicePlaintext3);
        std::println("    ✓ Alice wrote message");
        std::println("      Message size: {} bytes", aliceMsg3.size());
        std::println("      Handshake complete: {}", aliceHs.GetStatus().IsComplete() ? "Yes" : "No");

        auto bobRecv3 = bobHs.ReadMessage(aliceMsg3);
        std::println("    ✓ Bob read message");
        std::println("      Payload: \"{}\"", std::string_view(
                         reinterpret_cast<const char*>(bobRecv3.data()),
                         bobRecv3.size()));
        std::println("      Payload matches: {}", bobRecv3 == alicePlaintext3 ? "Yes ✓" : "No ✗");
        std::println("      Handshake complete: {}", bobHs.GetStatus().IsComplete() ? "Yes" : "No");

        // Message 4: Bob -> Alice (final message in pqXX)
        std::vector<std::uint8_t> bobPlaintext4 = {
            'b', 'o', 'b', ' ', 'p', 'q', ' ',
            's', 'k', 'e', 'm', ' ',
            'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't'
        };
        std::println("\n4.4 Message 4: Bob (Responder) -> Alice");
        std::println("    Tokens: skem");
        std::println("    Payload: \"{}\"", std::string_view(
                         reinterpret_cast<const char*>(bobPlaintext4.data()),
                         bobPlaintext4.size()));

        auto bobMsg4 = bobHs.WriteMessage(bobPlaintext4);
        std::println("    ✓ Bob wrote message");
        std::println("      Message size: {} bytes", bobMsg4.size());
        std::println("      Handshake complete: {} ✓", bobHs.GetStatus().IsComplete() ? "Yes" : "No");

        auto aliceRecv4 = aliceHs.ReadMessage(bobMsg4);
        std::println("    ✓ Alice read message");
        std::println("      Payload: \"{}\"", std::string_view(
                         reinterpret_cast<const char*>(aliceRecv4.data()),
                         aliceRecv4.size()));
        std::println("      Payload matches: {}", aliceRecv4 == bobPlaintext4 ? "Yes ✓" : "No ✗");
        std::println("      Handshake complete: {} ✓", aliceHs.GetStatus().IsComplete() ? "Yes" : "No");

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
        std::println("    Note: In pqXX, only the initiator (Alice) generates an ephemeral key.");
        std::println("          Bob does not generate 'e' - he uses ekem/skem tokens instead.");

        print_bytes("    Alice's local ephemeral", aliceStatus.localEphemeral);
        std::println("    Alice's remote ephemeral: (empty - Bob has no ephemeral in pqXX)");
        std::println("    Bob's local ephemeral: (empty - Bob has no ephemeral in pqXX)");
        print_bytes("    Bob's remote ephemeral (Alice's e)", bobStatus.remoteEphemeral);

        bool ephemMatch = aliceStatus.localEphemeral == bobStatus.remoteEphemeral;
        std::println("    {} Alice's ephemeral == Bob's remote: {}", ephemMatch ? "✓" : "✗",
                     ephemMatch ? "PASS" : "FAIL");

        std::println("\n5.4 Verifying static keys:");
        std::println("      Alice's remote static size: {} bytes", aliceStatus.remoteStatic.size());
        std::println("      Bob's original static (public) size: {} bytes", bobStatic.public_key.size());
        bool staticMatch1 = aliceStatus.remoteStatic == bobStatic.public_key;
        std::println("    {} Alice learned Bob's static key: {}", staticMatch1 ? "✓" : "✗",
                     staticMatch1 ? "PASS" : "FAIL");

        std::println("      Bob's remote static size: {} bytes", bobStatus.remoteStatic.size());
        std::println("      Alice's original static (public) size: {} bytes", aliceStatic.public_key.size());
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
            'a', 'l', 'i', 'c', 'e', ' ', 'p', 'q', ' ',
            't', 'r', 'a', 'n', 's', 'p', 'o', 'r', 't', ' ',
            'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't'
        };
        std::println("    Plaintext: \"{}\"", std::string_view(
                         reinterpret_cast<const char*>(alicePlaintext.data()),
                         alicePlaintext.size()));

        auto aliceMsg5 = aliceTx.EncryptWithAd({}, alicePlaintext);
        std::println("    ✓ Alice encrypted");
        std::println("      Ciphertext size: {} bytes", aliceMsg5.size());
        std::println("      Overhead: {} bytes", aliceMsg5.size() - alicePlaintext.size());

        auto bobRecv5 = bobRx.DecryptWithAd({}, aliceMsg5);
        std::println("    ✓ Bob decrypted");
        std::println("      Plaintext: \"{}\"", std::string_view(
                         reinterpret_cast<const char*>(bobRecv5.data()),
                         bobRecv5.size()));
        bool transportMatch1 = bobRecv5 == alicePlaintext;
        std::println("      {} Message matches: {}", transportMatch1 ? "✓" : "✗", transportMatch1 ? "PASS" : "FAIL");

        // Bob -> Alice transport
        std::println("\n6.3 Transport message: Bob -> Alice");

        std::vector<std::uint8_t> bobPlaintext = {
            'b', 'o', 'b', ' ', 'p', 'q', ' ',
            't', 'r', 'a', 'n', 's', 'p', 'o', 'r', 't', ' ',
            'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't'
        };
        std::println("    Plaintext: \"{}\"", std::string_view(
                         reinterpret_cast<const char*>(bobPlaintext.data()),
                         bobPlaintext.size()));

        auto bobMsg5 = bobTx.EncryptWithAd({}, bobPlaintext);
        std::println("    ✓ Bob encrypted");
        std::println("      Ciphertext size: {} bytes", bobMsg5.size());
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
        std::println("\n✓✓✓ All PQNoise operations completed successfully! ✓✓✓\n");
        std::println("Summary:");
        std::println("  ✓ Protocol construction (string and manual) with ML-KEM-768");
        std::println("  ✓ Keypair generation for Alice and Bob (KEM keys)");
        std::println("  ✓ Handshake state initialization");
        std::println("  ✓ pqXX handshake execution (4 messages)");
        std::println("  ✓ Handshake hash verification");
        std::println("  ✓ Ephemeral key verification (initiator-only in pqXX)");
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
