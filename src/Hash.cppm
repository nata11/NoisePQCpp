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
        Hash() : Hash{SHA256} {}

        /**
         * Construct from a hash name string ("SHA256", "SHA512", "BLAKE2b", "BLAKE2s").
         * @param algo_name Short hash algorithm name.
         */
        explicit Hash(const std::string_view algo_name) : m_algoName{algo_name} {
            // Map short hash names to full Botan names
            std::string_view botan_name = algo_name;
            if (algo_name == "SHA256") {
                botan_name = "SHA-256";
            }
            else if (algo_name == "SHA512") {
                botan_name = "SHA-512";
            }

            hash_function = Botan::HashFunction::create_or_throw(botan_name);
        }

        explicit Hash(const HashAlgo algo) : Hash{GetHashAlgorithmName(algo)} {}

        // Copy constructor
        Hash(const Hash& other)
            : m_algoName(other.m_algoName) {
            // Map short hash names to full Botan names
            std::string_view botan_name = m_algoName;
            if (m_algoName == "SHA256") {
                botan_name = "SHA-256";
            }
            else if (m_algoName == "SHA512") {
                botan_name = "SHA-512";
            }

            hash_function = Botan::HashFunction::create_or_throw(botan_name);
        }

        // Move constructor
        Hash(Hash&& other) noexcept
            : hash_function(std::move(other.hash_function)),
              m_algoName(other.m_algoName) {}

        Hash& operator=(const Hash&) = delete;

        Hash& operator=(Hash&&) = delete;

        [[nodiscard]] std::string_view String() const {
            return m_algoName;
        }

        [[nodiscard]] std::size_t Size() const {
            return hash_function->output_length();
        }

    private:
        const std::string m_algoName;
    };
}
