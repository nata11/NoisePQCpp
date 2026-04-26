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

#include "botan_all.h"
import noise;

using namespace Noise;

int main () {
    std::println("\n{:*^80}", " HandshakeState Module Sandbox ");
    std::println("{:^80}", "Testing HandshakeState construction");
    std::println("{:*^80}\n", "");

    // =======================================================================
    // Test 1: HandshakeState Construction
    // =======================================================================
    try {
        std::println("Creating HandshakeState with XX pattern, X25519, ChaChaPoly, SHA256");

        //Define protocol
        Protocol protocol(XX, X25519, ChaChaPoly, SHA256);
        //Alice's configs
        KeyPair aliceStatic = protocol.dh.GenerateKeypair();
        HandshakeConfig aliceCfg{
            .protocol = protocol,
            .isInitiator = true,
            .localStatic = aliceStatic,
            .maxMessageSize = 65535
        };

        //Bob's configs
        KeyPair bobStatic = protocol.dh.GenerateKeypair();
        HandshakeConfig bobCfg{
            .protocol = protocol,
            .isInitiator = false,
            .localStatic = bobStatic,
            .maxMessageSize = 65535
        };

        //Both sides create HandshakeState
        HandshakeState aliceHS(aliceCfg);
        HandshakeState bobHS(bobCfg);


        std::println("✓ SUCCESS\n");
    } catch (const std::exception& e) {
        std::println("✗ FAILED: {}\n", e.what());
    }

    return 0;
}