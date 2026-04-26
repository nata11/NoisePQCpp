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

export module noise:cipher;

import :common;
import :errors;

export namespace Noise
{
    /**
     * AEAD cipher wrapper supporting ChaCha20-Poly1305 and AES-256-GCM
     * (Noise spec Section 4.2).
     *
     * Provides authenticated encryption with associated data (AEAD) using
     * Botan as the cryptographic backend. Handles the Noise-specific 96-bit
     * nonce format: 4 zero bytes followed by an 8-byte counter, encoded in
     * little-endian for ChaCha20-Poly1305 (RFC 7539) or big-endian for
     * AES-256-GCM (NIST SP 800-38D).
     */
    class Cipher {
    public:
        /** Default constructor: ChaCha20-Poly1305. */
        Cipher() : Cipher{ChaChaPoly} {}

        /** Construct from a CipherAlgo enum value. */
        explicit Cipher(const CipherAlgo algo) : Cipher{GetCipherAlgorithmName(algo)} {}

        /**
         * Construct from a cipher name string ("ChaChaPoly" or "AESGCM").
         * @param cipher_name Short cipher name mapped to Botan's full algorithm name.
         */
        explicit Cipher(const std::string_view cipher_name) : m_cipherName{cipher_name} {
            // Map short cipher names to full Botan names
            std::string_view botan_name = cipher_name;
            if (cipher_name == "ChaChaPoly") {
                botan_name = "ChaCha20Poly1305";
            }
            else if (cipher_name == "AESGCM") {
                botan_name = "AES-256/GCM";
            }

            m_enc = Botan::AEAD_Mode::create_or_throw(botan_name, Botan::Cipher_Dir::Encryption);
            m_dec = Botan::AEAD_Mode::create_or_throw(botan_name, Botan::Cipher_Dir::Decryption);
            SetNonceEncoder();
        }

        // Copy constructor
        Cipher(const Cipher& other)
            : m_cipherName(other.m_cipherName) {
            // Map short cipher names to full Botan names
            std::string_view botan_name = m_cipherName;
            if (m_cipherName == "ChaChaPoly") {
                botan_name = "ChaCha20Poly1305";
            }
            else if (m_cipherName == "AESGCM") {
                botan_name = "AES-256/GCM";
            }

            m_enc = Botan::AEAD_Mode::create_or_throw(botan_name, Botan::Cipher_Dir::Encryption);
            m_dec = Botan::AEAD_Mode::create_or_throw(botan_name, Botan::Cipher_Dir::Decryption);
            m_nonceEncoder = other.m_nonceEncoder;
        }

        // Move constructor
        Cipher(Cipher&& other) noexcept
            : m_enc(std::move(other.m_enc)),
              m_dec(std::move(other.m_dec)),
              m_cipherName(other.m_cipherName),
              m_nonceEncoder(std::move(other.m_nonceEncoder)) {}

        Cipher& operator=(const Cipher&) = delete;

        Cipher& operator=(Cipher&&) = delete;

        /**
         * Encrypts plaintext with AEAD and appends ciphertext (including tag) to dst.
         *
         * @param[in,out] dst Buffer to append ciphertext to.
         * @param[in] k 32-byte encryption key.
         * @param[in] n 64-bit nonce counter (encoded to 96-bit Noise nonce format).
         * @param[in] ad Associated data for AEAD authentication.
         * @param[in] plaintext Data to encrypt.
         */
        void Encrypt(std::vector<std::uint8_t>& dst,
                     const std::span<const std::uint8_t> k,
                     const std::uint64_t n,
                     const std::span<const std::uint8_t> ad,
                     const std::span<const std::uint8_t> plaintext) const {
            const std::size_t offset = dst.size();

            // Resize dst and copy plaintext to destination at offset
            dst.resize(offset + plaintext.size());
            std::ranges::copy(plaintext, dst.begin() + static_cast<std::ptrdiff_t>(offset));

            // Set up cipher and encrypt in-place starting at offset
            m_enc->set_key(k);
            m_enc->set_associated_data(ad);
            const auto nonce = m_nonceEncoder(n);
            m_enc->start(nonce);

            // finish() encrypts in-place and appends the AEAD tag
            m_enc->finish(dst, offset);
        }

        /**
         * Decrypts AEAD ciphertext (with tag verification) and appends plaintext to dst.
         *
         * @param[in,out] dst Buffer to append decrypted plaintext to.
         * @param[in] k 32-byte decryption key.
         * @param[in] n 64-bit nonce counter.
         * @param[in] ad Associated data for AEAD verification.
         * @param[in] ciphertext Data to decrypt (includes AEAD tag).
         * @throws Botan::Invalid_Authentication_Tag If the AEAD tag verification fails.
         */
        void Decrypt(std::vector<std::uint8_t>& dst,
                     const std::span<const std::uint8_t> k,
                     const std::uint64_t n,
                     const std::span<const std::uint8_t> ad,
                     const std::span<const std::uint8_t> ciphertext) const {
            const std::size_t offset = dst.size();

            // Resize dst and copy ciphertext to destination at offset
            dst.resize(offset + ciphertext.size());
            std::ranges::copy(ciphertext, dst.begin() + static_cast<std::ptrdiff_t>(offset));

            // Set up cipher and decrypt in-place starting at offset
            m_dec->set_key(k);
            m_dec->set_associated_data(ad);
            const auto nonce = m_nonceEncoder(n);
            m_dec->start(nonce);

            // finish() decrypts in-place, verifies tag, and shrinks buffer to remove tag
            m_dec->finish(dst, offset);
        }

        [[nodiscard]] std::string_view String() const {
            return m_cipherName;
        }

        [[nodiscard]] auto GetAeadTagSize() const {
            return m_enc->tag_size();
        }

        void Reset() const {
            m_enc->clear();
            m_dec->clear();
        }

    private:
        std::unique_ptr<Botan::AEAD_Mode> m_enc, m_dec;
        const std::string m_cipherName;
        std::function<std::array<std::uint8_t, 12>(uint64_t)> m_nonceEncoder;

        /**
         * Configures the 96-bit Noise nonce encoder.
         *
         * Format: 4 zero bytes + 8-byte counter.
         * AES-GCM uses big-endian byte order (NIST SP 800-38D).
         * ChaCha20-Poly1305 uses little-endian byte order (RFC 7539 Section 2.3).
         */
        void SetNonceEncoder() {
            const bool big_endian = (m_cipherName == AESGCM);
            m_nonceEncoder = [big_endian](const std::uint64_t nonce) -> std::array<std::uint8_t, 12> {
                // Bit-cast the 64-bit counter to raw bytes
                const auto bytes = std::bit_cast<std::array<std::uint8_t, 8>>(nonce);

                // Noise-style 96-bit nonce prefix: 4 zero bytes + 8-byte counter
                std::array<std::uint8_t, 12> encoded{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

                if (big_endian) {
                    // AES-GCM: big-endian (MSB first)
                    std::copy(bytes.rbegin(), bytes.rend(), encoded.begin() + 4);
                }
                else {
                    // ChaCha20-Poly1305: little-endian (LSB first)
                    std::copy(bytes.begin(), bytes.end(), encoded.begin() + 4);
                }

                return encoded;
            };
        }
    };
}
