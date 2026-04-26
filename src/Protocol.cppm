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

export module noise:protocol;

import :cipher;
import :hash;
import :dh;
import :pattern;
import :common;
import :errors;

export namespace Noise
{
    /**
     * Combines a handshake pattern with concrete algorithm choices to form a
     * complete Noise protocol configuration (Noise spec Section 8).
     *
     * Supports three protocol string formats:
     * - Classical: `Noise_XX_25519_ChaChaPoly_SHA256`
     * - Post-quantum: `Noise_pqXX_M768_ChaChaPoly_SHA256`
     * - HFS hybrid: `Noise_XXhfs_25519+M768_ChaChaPoly_SHA256`
     *
     * Can be constructed either from individual components or by parsing a
     * Noise protocol name string.
     */
    class Protocol {
    public:
        const HandshakePattern pattern;     ///< The handshake pattern definition.
        const Dh dh;                        ///< Primary DH or KEM algorithm.
        const std::optional<Dh> kem;        ///< Secondary KEM for HFS patterns (std::nullopt if not HFS).
        const Cipher cipher;                ///< AEAD cipher algorithm.
        const Hash hash;                    ///< Hash function algorithm.

        /** Construct a classical or PQ protocol (non-HFS). */
        Protocol(HandshakePattern pattern,
                 const std::string_view dh_name,
                 const std::string_view cipher_name,
                 const std::string_view hash_name
        )
            : pattern{std::move(pattern)},
              dh{dh_name},
              kem{std::nullopt},
              cipher{cipher_name},
              hash{hash_name} {}

        /** Construct an HFS protocol with a secondary KEM algorithm. */
        Protocol(HandshakePattern pattern,
                 const std::string_view dh_name,
                 const std::string_view kem_name,
                 const std::string_view cipher_name,
                 const std::string_view hash_name
        )
            : pattern{std::move(pattern)},
              dh{dh_name},
              kem{Dh{kem_name}},
              cipher{cipher_name},
              hash{hash_name} {}

        /**
         * Construct from a Noise protocol name string.
         *
         * Parses the string format: `Noise_<pattern>_<dh>[+<kem>]_<cipher>_<hash>`
         * and looks up the pattern in the registry.
         *
         * @param pr_string Full protocol name, e.g., "Noise_XX_25519_ChaChaPoly_SHA256".
         * @throws ProtocolNotSupportedError If the pattern or algorithm is unknown.
         */
        explicit Protocol(const std::string_view& pr_string)
            : Protocol{
                [&pr_string]() -> Protocol {
                    auto result = ParseProtocolString(pr_string);
                    if (result.kem_name.has_value()) {
                        return {result.pattern, result.dh_name, *result.kem_name,
                                result.cipher_name, result.hash_name};
                    }
                    return {result.pattern, result.dh_name,
                            result.cipher_name, result.hash_name};
                }()
            } {}

        /** @return True if this protocol uses Hybrid Forward Secrecy (has a secondary KEM). */
        [[nodiscard]] bool IsHFS() const {
            return kem.has_value();
        }

        /** @return The canonical Noise protocol name string. */
        [[nodiscard]] std::string String() const {
            constexpr std::string_view uscore = "_";
            std::stringstream ss;
            const auto x1 = pattern.String();
            const auto x2 = dh.String();
            const auto x3 = cipher.String();
            const auto x4 = hash.String();
            ss << protocolPrefix << uscore << x1 << uscore << x2;
            if (kem.has_value()) {
                ss << "+" << kem->String();
            }
            ss << uscore << x3 << uscore << x4;
            return ss.str();
        }

    private:
        /** Intermediate result from parsing a protocol name string. */
        struct ParseResult {
            HandshakePattern pattern;
            std::string_view dh_name;
            std::optional<std::string_view> kem_name;
            std::string_view cipher_name;
            std::string_view hash_name;
        };

        /** Parses `Noise_<pattern>_<dh>[+<kem>]_<cipher>_<hash>` into components. */
        static ParseResult ParseProtocolString(const std::string_view& pr_string) {
            std::vector<std::string_view> parts;
            std::size_t pos = 0;

            while (pos != std::string_view::npos) {
                const std::size_t next_pos = pr_string.find('_', pos);
                parts.push_back(pr_string.substr(pos, next_pos - pos));
                pos = next_pos == std::string_view::npos ? next_pos : next_pos + 1;
            }

            if (parts.size() != 5 || parts[0] != protocolPrefix) {
                throw ProtocolNotSupportedError();
            }

            // Check for "hfs" suffix in pattern name
            std::string pattern_name{parts[1]};
            const bool isHFS = pattern_name.ends_with("hfs");

            // Parse DH/KEM part - may contain "+" for HFS (e.g., "25519+M768")
            std::string_view dh_part = parts[2];
            std::optional<std::string_view> kem_part = std::nullopt;

            if (const auto plus_pos = dh_part.find('+'); plus_pos != std::string_view::npos) {
                if (!isHFS) {
                    throw NoiseError("DH+KEM format requires 'hfs' pattern modifier");
                }
                kem_part = dh_part.substr(plus_pos + 1);
                dh_part = dh_part.substr(0, plus_pos);
            } else if (isHFS) {
                throw NoiseError("HFS patterns require DH+KEM format (e.g., 25519+M768)");
            }

            // Get the pattern registry
            const auto& pattern_registry = GetPatternRegistry();

            HandshakePattern final_pattern;
            if (isHFS) {
                // Extract base pattern name (remove "hfs" suffix)
                std::string base_pattern_name = pattern_name.substr(0, pattern_name.size() - 3);
                if (!pattern_registry.contains(base_pattern_name)) {
                    throw ProtocolNotSupportedError();
                }
                // Apply HFS modifier to transform the base pattern
                final_pattern = ApplyHFSModifier(pattern_registry.at(base_pattern_name));
            } else {
                if (!pattern_registry.contains(pattern_name)) {
                    throw ProtocolNotSupportedError();
                }
                final_pattern = pattern_registry.at(pattern_name);
            }

            return ParseResult{
                .pattern = final_pattern,
                .dh_name = dh_part,
                .kem_name = kem_part,
                .cipher_name = parts[3],
                .hash_name = parts[4]
            };
        }
    };
}
