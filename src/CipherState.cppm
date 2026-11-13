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


export module noise:cipherstate;

import :common;
import :cipher;
import :errors;

export namespace Noise
{
    class SymmetricState; // Forward declaration

    /**
     * Tracks an AEAD encryption key and nonce for one direction of communication
     * (Noise spec Section 5.1).
     *
     * When no key is set (all-zero key), encrypt/decrypt operations pass data through
     * as plaintext — this is the Noise spec convention for the early handshake phase
     * before any DH/KEM operation has established keying material. Once a key is set
     * via InitializeKey(), all subsequent operations use authenticated encryption.
     *
     * After the handshake completes, Split() produces two CipherState objects:
     * one for each direction of the transport channel.
     */
    class CipherState {
    public:
        Cipher cipher;                                          ///< AEAD cipher instance.
        std::array<std::uint8_t, SYMMETRIC_KEY_SIZE> key{};     ///< 32-byte symmetric key (zero = no key).
        std::uint64_t nonce{0};                                 ///< 64-bit nonce counter.
        std::size_t aeadOverhead{0};                            ///< AEAD tag size in bytes (16).
        std::uint32_t maxMessageSize{0};                        ///< Maximum message (ciphertext) size in bytes; 0 = unchecked.
        /**
         * Tracks the plaintext→encrypted state transition.
         * Set to true after the first non-zero key is loaded, ensuring the
         * handshake can detect when encryption becomes active.
         */
        bool hadKeyBefore{false};

        CipherState(Cipher aead, const std::uint32_t maxSize)
            : cipher{std::move(aead)}, maxMessageSize{maxSize} {
            aeadOverhead = cipher.GetAeadTagSize();
        }

        // Copy constructor
        CipherState(const CipherState&) = default;

        // Move constructor
        CipherState(CipherState&& other) noexcept = default;

        /**
         * Destructor. Scrubs the key with Botan::secure_scrub_memory. A moved-from CipherState
         * still holds its copy of the key (std::array moves copy), so it is scrubbed here too.
         */
        ~CipherState() {
            Botan::secure_scrub_memory(key);
        }

        CipherState& operator=(const CipherState&) = delete;
        CipherState& operator=(CipherState&&) = delete;

        /**
         * Replaces the key with REKEY(k) = ENCRYPT(k, 2^64-1, zerolen, zeros) truncated to
         * 32 bytes (Noise spec Section 4.2, the default REKEY). The nonce is unchanged. Does
         * nothing when no key is set. The temporary ciphertext is scrubbed on every path.
         *
         * @throws NoiseError If the cipher backend fails; the key is unchanged.
         */
        void Rekey() {
            if (!HasKey()) return;

            // Cipher::Encrypt, not EncryptWithAd: REKEY uses the reserved nonce 2^64-1, which
            // EncryptWithAd rightly rejects with NonceExhaustedError.
            std::vector<std::uint8_t> tmp;
            tmp.reserve(SYMMETRIC_KEY_SIZE + aeadOverhead);   // never reallocates
            const struct ScrubOnExit {
                std::vector<std::uint8_t>& bytes;
                ~ScrubOnExit() {
                    bytes.resize(bytes.capacity());   // cover anything written past size()
                    Botan::secure_scrub_memory(bytes);
                }
            } scrub{tmp};

            constexpr std::array<std::uint8_t, SYMMETRIC_KEY_SIZE> zeros{};
            cipher.Encrypt(tmp, key, MAX_NONCE, {}, zeros);
            std::ranges::copy_n(tmp.cbegin(), SYMMETRIC_KEY_SIZE, key.begin());
        }

        /** Securely scrubs the key and resets the cipher state. */
        void Reset() {
            Botan::secure_scrub_memory(key);
            cipher.Reset();
        }

        /** @return True if a non-zero key has been set (encryption is active). */
        [[nodiscard]] bool HasKey() const {
            const bool hasKey = std::ranges::any_of(key, [](const std::uint8_t num) -> bool { return num != 0; });
            return hasKey;
        }

        void SetNonce(const std::uint64_t n) {
            nonce = n;
        }

        /**
         * Sets the symmetric key and resets the nonce to zero (Noise spec Section 5.1).
         * @param newKey Exactly 32 bytes of key material.
         */
        void InitializeKey(const std::span<const std::uint8_t> newKey) {
            if (newKey.size() != SYMMETRIC_KEY_SIZE) {
                ThrowNoiseError("Key size must be 32 bytes");
            }

            const bool wasEmpty = !HasKey();
            std::ranges::copy(newKey, key.begin());
            nonce = 0;
            const bool isNowSet = HasKey();

            // Track state transition from plaintext to encrypted
            if (wasEmpty && isNowSet && !hadKeyBefore) {
                hadKeyBefore = true;
            }
        }

        /** Encrypts plaintext with associated data, returning the ciphertext. */
        [[nodiscard]] std::vector<std::uint8_t> EncryptWithAd(
            const std::span<const std::uint8_t> ad,
            const std::span<const std::uint8_t> plaintext) {
            std::vector<std::uint8_t> result;
            EncryptWithAd(result, ad, plaintext);
            return result;
        }

        /** Decrypts ciphertext with associated data, returning the plaintext. */
        [[nodiscard]] std::vector<std::uint8_t> DecryptWithAd(
            const std::span<const std::uint8_t> ad,
            const std::span<const std::uint8_t> ciphertext) {
            std::vector<std::uint8_t> result;
            DecryptWithAd(result, ad, ciphertext);
            return result;
        }

        // Grant SymmetricState access to private members
        friend class SymmetricState;

    private:

        /**
         * Appends encrypted data to dst. If no key is set, passes plaintext through unchanged.
         * @throws NonceExhaustedError If nonce == MAX_NONCE (the reserved value).
         * @throws MessageSizeError If the resulting message would exceed maxMessageSize (when > 0).
         * On any failure the nonce is unchanged.
         */
        void EncryptWithAd(std::vector<std::uint8_t>& dst,
                          const std::span<const std::uint8_t> ad,
                          const std::span<const std::uint8_t> plaintext) {
            // Noise spec Section 5.1: 2^64-1 is reserved; using it is an error
            if (nonce == MAX_NONCE) [[unlikely]] throw NonceExhaustedError{};

            const bool hasKey = HasKey();

            // Noise spec Section 3: the message (ciphertext) is bounded by maxMessageSize
            if (maxMessageSize > 0 &&
                plaintext.size() + (hasKey ? aeadOverhead : 0) > maxMessageSize) [[unlikely]] {
                throw MessageSizeError{};
            }

            if (!hasKey) [[unlikely]] {
                dst.insert(dst.end(), plaintext.begin(), plaintext.end());
                return;
            }

            // Encrypt directly into dst buffer (no intermediate allocation)
            cipher.Encrypt(dst, key, nonce, ad, plaintext);
            nonce++;
        }

        /**
         * Appends decrypted data to dst. If no key is set, passes ciphertext through unchanged.
         * @throws NonceExhaustedError If nonce == MAX_NONCE (the reserved value).
         * @throws MessageSizeError If ciphertext exceeds maxMessageSize (when > 0).
         * @throws DecryptionError If the ciphertext is shorter than the tag or the tag does not verify.
         * On any failure the nonce is unchanged.
         */
        void DecryptWithAd(std::vector<std::uint8_t>& dst,
                          const std::span<const std::uint8_t> ad,
                          const std::span<const std::uint8_t> ciphertext) {
            // Noise spec Section 5.1: 2^64-1 is reserved; using it is an error
            if (nonce == MAX_NONCE) [[unlikely]] throw NonceExhaustedError{};

            // Noise spec Section 3: the message (ciphertext) is bounded by maxMessageSize
            if (maxMessageSize > 0 && ciphertext.size() > maxMessageSize) [[unlikely]] {
                throw MessageSizeError{};
            }

            if (!HasKey()) [[unlikely]] {
                dst.insert(dst.end(), ciphertext.begin(), ciphertext.end());
                return;
            }

            // Decrypt directly into dst buffer (no intermediate allocation)
            cipher.Decrypt(dst, key, nonce, ad, ciphertext);
            nonce++;
        }
    };
}
