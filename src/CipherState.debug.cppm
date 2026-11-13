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


export module noise:cipherstate.debug;

import :common;
import :cipher;
import :errors;

export namespace Noise
{
    class SymmetricState; // Forward declaration

    class CipherState {
    public:
        Cipher cipher;
        std::array<std::uint8_t, SYMMETRIC_KEY_SIZE> key{}; // 32 byte key (zero-initialized)
        std::uint64_t nonce{0}; // 8 byte integer nonce
        std::size_t aeadOverhead{0};
        std::uint32_t maxMessageSize{0}; // Maximum message (ciphertext) size in bytes; 0 = unchecked
        bool hadKeyBefore{false}; // Track state transition from plaintext to encrypted

        CipherState(Cipher aead, const std::uint32_t maxSize)
            : cipher{std::move(aead)}, maxMessageSize{maxSize} {
            aeadOverhead = cipher.GetAeadTagSize();
        }

        // Copy constructor
        CipherState(const CipherState&) = default;

        // Move constructor
        CipherState(CipherState&& other) noexcept = default;

        // Destructor: scrubs the key (a moved-from source still holds a copy and scrubs it too)
        ~CipherState() {
            Botan::secure_scrub_memory(key);
        }

        CipherState& operator=(const CipherState&) = delete;
        CipherState& operator=(CipherState&&) = delete;

        // Noise spec Section 4.2 REKEY: ENCRYPT(k, 2^64-1, zerolen, zeros) truncated to 32 bytes.
        // The nonce is unchanged; the temporary ciphertext is scrubbed on every path.
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

        void Reset() {
            Botan::secure_scrub_memory(key);
            cipher.Reset();
        }

        [[nodiscard]] bool HasKey() const {
            const bool hasKey = std::ranges::any_of(key, [](const std::uint8_t num) -> bool { return num != 0; });
            return hasKey;
        }

        void SetNonce(const std::uint64_t n) {
            nonce = n;
        }

        void InitializeKey(const std::span<const std::uint8_t> newKey) {
            if (newKey.size() != SYMMETRIC_KEY_SIZE) {
                ThrowNoiseError("Key size must be 32 bytes");
            }

            const bool wasEmpty = !HasKey();
            std::ranges::copy(newKey, key.begin());
            nonce = 0;
            const bool isNowSet = HasKey();

            // Log state transition
            if (g_EnableSymmetricLogging) {
                if (wasEmpty && isNowSet && !hadKeyBefore) {
                    std::println("{}[CIPHER] {}State transition: PLAINTEXT -> ENCRYPTED mode{}",
                        Color::Cyan, Color::White, Color::Reset);
                    hadKeyBefore = true;
                } else if (wasEmpty && !isNowSet) {
                    std::println("{}[CIPHER] {}Key initialized (still in plaintext mode){}",
                        Color::Cyan, Color::White, Color::Reset);
                } else if (isNowSet) {
                    std::println("{}[CIPHER] {}Key re-initialized (nonce reset to 0){}",
                        Color::Cyan, Color::White, Color::Reset);
                }
            }
        }

        // User-friendly return-value overload for EncryptWithAd
        [[nodiscard]] std::vector<std::uint8_t> EncryptWithAd(
            const std::span<const std::uint8_t> ad,
            const std::span<const std::uint8_t> plaintext) {
            std::vector<std::uint8_t> result;
            EncryptWithAd(result, ad, plaintext);
            return result;
        }

        // User-friendly return-value overload for DecryptWithAd
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

        // Appends encrypted data to dst buffer
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
                // Append plaintext directly to dst
                if (g_EnableSymmetricLogging) {
                    std::println("{}[CIPHER] {}EncryptWithAd: Plaintext passthrough (no key) - appending {} bytes (nonce: {}, ad: {} bytes){}",
                        Color::Cyan, Color::White, plaintext.size(), nonce, ad.size(), Color::Reset);
                }
                dst.insert(dst.end(), plaintext.begin(), plaintext.end());
                return;
            }

            if (g_EnableSymmetricLogging) {
                std::println("{}[CIPHER] {}EncryptWithAd: Encrypting {} bytes with nonce {} (ad: {} bytes, dst size before: {}){}",
                    Color::Cyan, Color::White, plaintext.size(), nonce, ad.size(), dst.size(), Color::Reset);
            }

            const std::size_t dstSizeBefore = dst.size();

            // Encrypt directly into dst buffer (no intermediate allocation)
            cipher.Encrypt(dst, key, nonce, ad, plaintext);
            nonce++;

            if (g_EnableSymmetricLogging) {
                const std::size_t bytesAdded = dst.size() - dstSizeBefore;
                std::println("{}[CIPHER] {}  Result: {} bytes appended to dst (overhead: {} bytes, new nonce: {}, dst size after: {}){}",
                    Color::Cyan, Color::White, bytesAdded, bytesAdded - plaintext.size(), nonce, dst.size(), Color::Reset);
            }
        }

        // Appends decrypted data to dst buffer
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
                // Append ciphertext (as plaintext) directly to dst
                if (g_EnableSymmetricLogging) {
                    std::println("{}[CIPHER] {}DecryptWithAd: Plaintext passthrough (no key) - appending {} bytes (nonce: {}, ad: {} bytes){}",
                        Color::Cyan, Color::White, ciphertext.size(), nonce, ad.size(), Color::Reset);
                }
                dst.insert(dst.end(), ciphertext.begin(), ciphertext.end());
                return;
            }

            if (g_EnableSymmetricLogging) {
                std::println("{}[CIPHER] {}DecryptWithAd: Decrypting {} bytes with nonce {} (ad: {} bytes, dst size before: {}){}",
                    Color::Cyan, Color::White, ciphertext.size(), nonce, ad.size(), dst.size(), Color::Reset);
            }

            const std::size_t dstSizeBefore = dst.size();

            // Decrypt directly into dst buffer (no intermediate allocation)
            cipher.Decrypt(dst, key, nonce, ad, ciphertext);
            nonce++;

            if (g_EnableSymmetricLogging) {
                const std::size_t bytesAdded = dst.size() - dstSizeBefore;
                std::println("{}[CIPHER] {}  Result: {} bytes appended to dst (removed {} bytes overhead, new nonce: {}, dst size after: {}){}",
                    Color::Cyan, Color::White, bytesAdded, ciphertext.size() - bytesAdded, nonce, dst.size(), Color::Reset);
            }
        }
    };
}
