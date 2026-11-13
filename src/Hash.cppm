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

module;

#include "botan_all.h"

export module noise:hash;

import :common;
import :errors;

export namespace Noise
{
    /**
     * Hash function wrapper supporting SHA-256, SHA-512, BLAKE2b, and BLAKE2s
     * (Noise spec Section 4.3).
     *
     * Wraps Botan's hash function interface and maps short Noise names
     * ("SHA256", "BLAKE2b") to Botan's internal names ("SHA-256", "BLAKE2b").
     */
    class Hash {
    public:
        std::unique_ptr<Botan::HashFunction> hash_function;  ///< Botan hash function instance.

        /** Default constructor: SHA-256. */
        Hash() : Hash{HashAlgo::SHA256} {}

        /**
         * Construct from a HashAlgo enum value. The value is checked against HashAlgos before
         * any Botan call.
         * @param algo One of the four Noise hashes.
         * @throws ProtocolNotSupportedError If algo is not an entry of HashAlgos, or the
         *         constructed function's output length is neither 32 nor 64 bytes (HASHLEN,
         *         Noise spec Section 4.3; unreachable with the four entries).
         * @throws NoiseError If Botan cannot construct the hash function.
         */
        explicit Hash(const HashAlgo algo) : m_algo{Validate(algo)} {
            CreateFunction();
        }

        /**
         * Construct from a Noise hash name: exactly "SHA256", "SHA512", "BLAKE2b" or "BLAKE2s"
         * (case-sensitive). The name is resolved through HashAlgos before any Botan call; no
         * other string reaches Botan's algorithm parser.
         * @param algo_name Noise hash name.
         * @throws ProtocolNotSupportedError If the name is not one of the four Noise names, or
         *         the constructed function's output length is neither 32 nor 64 bytes (HASHLEN,
         *         Noise spec Section 4.3; unreachable with the four names).
         * @throws NoiseError If Botan cannot construct the hash function.
         */
        explicit Hash(const std::string_view algo_name) : Hash{Resolve(algo_name)} {}

        // Copy constructor: same algorithm, fresh Botan object (no string compares)
        Hash(const Hash& other)
            : m_algo(other.m_algo) {
            CreateFunction();
        }

        // Move constructor
        Hash(Hash&& other) noexcept
            : hash_function(std::move(other.hash_function)),
              m_algo(other.m_algo) {}

        Hash& operator=(const Hash&) = delete;

        Hash& operator=(Hash&&) = delete;

        /** @return The Noise hash name ("SHA256", "SHA512", "BLAKE2b" or "BLAKE2s"). */
        [[nodiscard]] std::string_view String() const {
            return GetHashAlgorithmName(m_algo);
        }

        [[nodiscard]] std::size_t Size() const {
            return hash_function->output_length();
        }

    private:
        const HashAlgo m_algo;

        /** Resolves a Noise hash name or throws ProtocolNotSupportedError. */
        static HashAlgo Resolve(const std::string_view algo_name) {
            const auto algo = ParseHashAlgo(algo_name);
            if (!algo) {
                throw ProtocolNotSupportedError{};
            }
            return *algo;
        }

        /** Returns algo if HashAlgos lists it, else throws ProtocolNotSupportedError. */
        static HashAlgo Validate(const HashAlgo algo) {
            if (!std::ranges::any_of(HashAlgos, [algo](const auto& entry) { return entry.first == algo; })) {
                throw ProtocolNotSupportedError{};
            }
            return algo;
        }

        /** Botan's algorithm name for a Noise hash. */
        static constexpr std::string_view BotanName(const HashAlgo algo) {
            switch (algo) {
            case HashAlgo::SHA256: return "SHA-256";
            case HashAlgo::SHA512: return "SHA-512";
            case HashAlgo::BLAKE2b: return "BLAKE2b";
            case HashAlgo::BLAKE2s: return "BLAKE2s";
            }
            return "";
        }

        /** Builds the Botan hash for m_algo; Botan failures become NoiseError; checks HASHLEN. */
        void CreateFunction() {
            try {
                hash_function = Botan::HashFunction::create_or_throw(BotanName(m_algo));
            }
            catch (const Botan::Exception& e) {
                // Botan types never escape the library (NoiseError model)
                throw NoiseError(std::string("noisepqc++/Hash: ") + e.what());
            }

            // Noise spec Section 4.3: HASHLEN is 32 or 64. Defensive: unreachable with the
            // four Noise names.
            const auto len = hash_function->output_length();
            if (len != 32 && len != 64) [[unlikely]] {
                throw ProtocolNotSupportedError{};
            }
        }
    };
}
