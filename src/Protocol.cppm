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

        /**
         * Construct a classical or PQ protocol (non-HFS).
         * @throws ProtocolNotSupportedError If a name is unknown, or the pattern's tokens do
         *         not match the algorithm (DH tokens need a DH, KEM tokens need a KEM, and
         *         e1/ekem1 need the HFS constructor).
         * @throws NoiseError If a Botan algorithm cannot be constructed.
         */
        Protocol(HandshakePattern hp,
                 const std::string_view dh_name,
                 const std::string_view cipher_name,
                 const std::string_view hash_name
        )
            : pattern{std::move(hp)},
              dh{dh_name},
              kem{std::nullopt},
              cipher{cipher_name},
              hash{hash_name},
              m_name{BuildName()} {
            CheckCombination();
        }

        /**
         * Construct an HFS protocol with a secondary KEM algorithm.
         * @throws ProtocolNotSupportedError If a name is unknown, or the combination is
         *         incompatible: the pattern must carry e1/ekem1, dh must be a DH and kem a KEM.
         * @throws NoiseError If a Botan algorithm cannot be constructed.
         */
        Protocol(HandshakePattern hp,
                 const std::string_view dh_name,
                 const std::string_view kem_name,
                 const std::string_view cipher_name,
                 const std::string_view hash_name
        )
            : pattern{std::move(hp)},
              dh{dh_name},
              kem{Dh{kem_name}},
              cipher{cipher_name},
              hash{hash_name},
              m_name{BuildName()} {
            CheckCombination();
        }

        /**
         * Construct from a Noise protocol name string.
         *
         * Parses the string format: `Noise_<pattern>_<dh>[+<kem>]_<cipher>_<hash>`
         * and looks up the pattern in the registry.
         *
         * @param pr_string Full protocol name, e.g., "Noise_XX_25519_ChaChaPoly_SHA256".
         * @throws ProtocolNotSupportedError If the string is malformed (including a `+` without
         *         the `hfs` modifier, or `hfs` without a `+`), the pattern or an algorithm is
         *         unknown, or the combination is incompatible.
         */
        explicit Protocol(const std::string_view& pr_string)
            : Protocol{ParseProtocolString(pr_string), ParseTag{}} {}

        /** @return True if this protocol uses Hybrid Forward Secrecy (has a secondary KEM). */
        [[nodiscard]] bool IsHFS() const {
            return kem.has_value();
        }

        /** @return The canonical Noise protocol name, built once at construction. */
        [[nodiscard]] const std::string& String() const {
            return m_name;
        }

    private:
        struct ParseTag {};

        /** Intermediate result from parsing a protocol name string. */
        struct ParseResult {
            HandshakePattern pattern;
            std::string_view dh_name;
            std::optional<std::string_view> kem_name;
            std::string_view cipher_name;
            std::string_view hash_name;
        };

        /** Builds the members in place from a parse result (the pattern is moved, nothing is copied twice). */
        Protocol(ParseResult&& r, ParseTag)
            : pattern{std::move(r.pattern)},
              dh{r.dh_name},
              kem{r.kem_name ? std::optional<Dh>{Dh{*r.kem_name}} : std::nullopt},
              cipher{r.cipher_name},
              hash{r.hash_name},
              m_name{BuildName()} {
            CheckCombination();
        }

        /** The one name builder: `Noise_<pattern>_<dh>[+<kem>]_<cipher>_<hash>`. */
        [[nodiscard]] std::string BuildName() const {
            std::string name;
            name.reserve(64);
            name.append(protocolPrefix).append("_").append(pattern.String()).append("_").append(dh.String());
            if (kem.has_value()) {
                name.append("+").append(kem->String());
            }
            name.append("_").append(cipher.String()).append("_").append(hash.String());
            return name;
        }

        const std::string m_name;   ///< Canonical protocol name (String()).

        /**
         * Rejects pattern/algorithm combinations that would otherwise fail one or two
         * messages into the handshake (Noise spec Section 8; PQNoise; Noise Protocol HFS
         * spec extension).
         *
         * - ekem/skem present => dh is a KEM;
         * - ee/es/se/ss present => dh is a DH;
         * - e1/ekem1 present <=> kem is set;
         * - kem set => kem is a KEM and dh is a DH.
         */
        void CheckCombination() const {
            bool hasDhToken = false, hasKemToken = false, hasHfsToken = false;
            for (const auto& message : pattern.messages) {
                for (const auto token : message.tokens) {
                    switch (token) {
                    case Token::Token_ee:
                    case Token::Token_es:
                    case Token::Token_se:
                    case Token::Token_ss:
                        hasDhToken = true;
                        break;
                    case Token::Token_ekem:
                    case Token::Token_skem:
                        hasKemToken = true;
                        break;
                    case Token::Token_e1:
                    case Token::Token_ekem1:
                        hasHfsToken = true;
                        break;
                    default:
                        break;
                    }
                }
            }

            const bool ok =
                (!hasKemToken || dh.IsKEM()) &&
                (!hasDhToken || !dh.IsKEM()) &&
                (hasHfsToken == kem.has_value()) &&
                (!kem.has_value() || (kem->IsKEM() && !dh.IsKEM()));

            if (!ok) {
                throw ProtocolNotSupportedError{};
            }
        }

        /** Parses `Noise_<pattern>_<dh>[+<kem>]_<cipher>_<hash>` into components; the pattern is
         *  copied once from the registry and handed over by move. */
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
                    throw ProtocolNotSupportedError{};   // DH+KEM format requires the hfs modifier
                }
                kem_part = dh_part.substr(plus_pos + 1);
                dh_part = dh_part.substr(0, plus_pos);
            } else if (isHFS) {
                throw ProtocolNotSupportedError{};   // hfs patterns require the DH+KEM format
            }

            // Get the pattern registry
            const auto& pattern_registry = GetPatternRegistry();

            // Classical, PQ and HFS names alike are looked up in full: the 35 HFS patterns are
            // registered (built with ApplyHFSModifier at registry creation), so no pattern is
            // synthesized at parse time and an unregistered hfs name is rejected.
            const auto found = pattern_registry.find(pattern_name);
            if (found == pattern_registry.end()) {
                throw ProtocolNotSupportedError();
            }

            return ParseResult{
                .pattern = found->second,
                .dh_name = dh_part,
                .kem_name = kem_part,
                .cipher_name = parts[3],
                .hash_name = parts[4]
            };
        }
    };
}
