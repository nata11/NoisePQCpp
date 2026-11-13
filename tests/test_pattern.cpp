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
// Pattern Validation Tests using Catch2 v3
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>

import noise;

using namespace Noise;

int main(int argc, char* argv[]) {
    // Disable all logging during tests for clean output
    Noise::DisableAllLogging();
    return Catch::Session().run(argc, argv);
}

TEST_CASE("Built-in Pattern Validity", "[pattern][validity]") {
    // Test all patterns in the registry for validity
    for (const auto& registry = GetPatternRegistry();
        const auto& [name, pattern] : registry) {
        DYNAMIC_SECTION(name) {
            auto result = HandshakePattern::IsValid(pattern);
            REQUIRE(result.has_value());
        }
    }
}

TEST_CASE("Pattern - isOneWay matches the message count", "[pattern][oneway]") {
    // Every registered pattern: the flag agrees with the message count (Noise spec Section 7.4)
    for (const auto& [name, pattern] : GetPatternRegistry()) {
        INFO(name);
        CHECK(pattern.isOneWay == (pattern.messages.size() == 1));
    }

    // IsValid rejects a flag that disagrees with the message count, in both directions
    HandshakePattern twoWayFlaggedOneWay = NN;
    twoWayFlaggedOneWay.isOneWay = true;
    const auto nnResult = HandshakePattern::IsValid(twoWayFlaggedOneWay);
    REQUIRE_FALSE(nnResult.has_value());
    CHECK(nnResult.error() == "isOneWay does not match the message count");

    HandshakePattern oneWayUnflagged = N;
    oneWayUnflagged.isOneWay = false;
    const auto nResult = HandshakePattern::IsValid(oneWayUnflagged);
    REQUIRE_FALSE(nResult.has_value());
    CHECK(nResult.error() == "isOneWay does not match the message count");
}
