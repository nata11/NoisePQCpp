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

export module noise:symmetricstate.debug;
import std;
import :common;
import :cipher;
import :hash;
import :cipherstate.debug;
import :errors;

export namespace Noise
{
    // Zero-copy HKDF result - holds buffer and provides span views
    struct HkdfResult {
        Botan::secure_vector<std::uint8_t> buffer;
        std::array<std::span<const std::uint8_t>, 3> outputs;
        std::size_t count;

        [[nodiscard]] std::span<const std::uint8_t> operator[](const std::size_t i) const {
            return outputs[i];
        }
    };

    class SymmetricState {
    public:
        CipherState cs;
        std::vector<std::uint8_t> ck;
        std::vector<std::uint8_t> h;
        std::size_t hashLen{0};

        SymmetricState(const Cipher& cipher, const Hash& hash)
            : cs{cipher, NOISE_MAX_MESSAGE_SIZE},
              hashLen{hash.hash_function->output_length()},
              cipher{cipher},
              hash{hash} {}

        // Copy constructor
        SymmetricState(const SymmetricState&) = default;

        // Move constructor
        SymmetricState(SymmetricState&& other) noexcept
            : cs{std::move(other.cs)},
              ck{std::move(other.ck)},
              h{std::move(other.h)},
              hashLen{other.hashLen},
              cipher{other.cipher},
              hash{other.hash} {}

        SymmetricState& operator=(const SymmetricState&) = delete;

        SymmetricState& operator=(SymmetricState&&) = delete;

        void InitializeSymmetric(std::span<const std::uint8_t> protocolName) {
            h = std::vector<std::uint8_t>(hashLen, 0);
            if (protocolName.size() <= hashLen) {
                std::ranges::copy(protocolName, h.begin());
            }
            else {
                const auto hash_result = hash.hash_function->process(protocolName);
                std::ranges::copy(hash_result, h.begin());
            }
            ck = h;
            // Initialize cipher state with zero-filled key (32 bytes)
            std::array<std::uint8_t, 32> zero_key{};
            cs.InitializeKey(zero_key);
        }

        void MixKey(const std::span<const std::uint8_t> input_km) {
            auto result = HkdfExpand(ck, input_km, hash.hash_function->name(), hashLen, 2);

            // result[0] = new_ck, result[1] = temp_k (spans into contiguous buffer)
            ck.assign(result[0].begin(), result[0].end());

            // Truncate temp_k to 32 bytes if HASHLEN=64
            if (hashLen != 32 && hashLen != 64) [[unlikely]]
                ThrowNoiseError("Noise expects HASHLEN 32 or 64");

            const auto temp_k = result[1].subspan(0, SYMMETRIC_KEY_SIZE);
            cs.InitializeKey(temp_k);
        }

        void MixHash(const std::span<const std::uint8_t> data) {
            hash.hash_function->update(h);
            hash.hash_function->update(data);
            hash.hash_function->final(h);
        }

        void MixKeyAndHash(const std::span<const std::uint8_t> input_km) {
            // (ck, temp_h, temp_k) = HKDF(ck, ikm, 3)
            auto result = HkdfExpand(ck, input_km, hash.hash_function->name(), hashLen, 3);

            // result[0] = new_ck, result[1] = temp_h, result[2] = temp_k (spans into contiguous buffer)
            // h = HASH(h || temp_h)
            MixHash(result[1]);

            // Truncate temp_k to 32 bytes if HASHLEN=64
            if (hashLen != 32 && hashLen != 64) [[unlikely]]
                ThrowNoiseError("Noise expects HASHLEN 32 or 64");

            ck.assign(result[0].begin(), result[0].end());
            const auto temp_k = result[2].subspan(0, SYMMETRIC_KEY_SIZE);
            cs.InitializeKey(temp_k);
        }

        // Encrypts plaintext and appends to dst, then mixes ciphertext into hash
        void EncryptAndHash(std::vector<std::uint8_t>& dst,
                            const std::span<const std::uint8_t> plaintext) {
            if (g_EnableSymmetricLogging) {
                std::println("{}[SYMMETRIC] {}EncryptAndHash: Processing {} bytes (dst size before: {}){}",
                             Color::Cyan, Color::White, plaintext.size(), dst.size(), Color::Reset);
            }

            // Save the offset where new ciphertext will start
            const std::size_t ciphertextOff = dst.size();

            // Encrypt and append to dst
            cs.EncryptWithAd(dst, h, plaintext);

            // Mix ONLY the newly added ciphertext portion into hash
            //const std::span<const std::uint8_t> newCiphertext(dst.begin() + ciphertextOff, dst.end());
            // Mix ONLY the newly added ciphertext portion into hash
            const auto start = std::next(dst.begin(), static_cast<std::ptrdiff_t>(ciphertextOff));
            const std::span<const std::uint8_t> newCiphertext(start, dst.end());

            if (g_EnableSymmetricLogging) {
                std::println(
                    "{}[SYMMETRIC] {}  Mixing new ciphertext ({} bytes) into handshake hash (dst size after: {}){}",
                    Color::Cyan, Color::White, newCiphertext.size(), dst.size(), Color::Reset);
            }

            MixHash(newCiphertext);
        }

        // Mixes ciphertext into hash, then decrypts and appends to dst (matching Go's signature)
        void DecryptAndHash(std::vector<std::uint8_t>& dst,
                            const std::span<const std::uint8_t> ciphertext) {
            if (g_EnableSymmetricLogging) {
                std::println("{}[SYMMETRIC] {}DecryptAndHash: Processing {} bytes (dst size before: {}){}",
                             Color::Cyan, Color::White, ciphertext.size(), dst.size(), Color::Reset);
            }

            // CRITICAL: Save a copy of h BEFORE mixing (for AD)
            std::vector<std::uint8_t> hPrev(h.begin(), h.end());

            if (g_EnableSymmetricLogging) {
                std::println("{}[SYMMETRIC] {}  Mixing ciphertext ({} bytes) into handshake hash BEFORE decryption{}",
                             Color::Cyan, Color::White, ciphertext.size(), Color::Reset);
            }

            // Mix ciphertext BEFORE decryption
            MixHash(ciphertext);

            // Decrypt using saved h as AD, append to dst
            cs.DecryptWithAd(dst, hPrev, ciphertext);

            if (g_EnableSymmetricLogging) {
                std::println("{}[SYMMETRIC] {}  Decryption complete (dst size after: {}){}",
                             Color::Cyan, Color::White, dst.size(), Color::Reset);
            }
        }

        [[nodiscard]] auto GetHandshakeHash() const {
            return h;
        }

        [[nodiscard]] std::pair<CipherState, CipherState> Split() const {
            auto result = HkdfExpand(ck, {}, hash.hash_function->name(), hashLen, 2);

            // Truncate to 32 bytes if HASHLEN=64
            if (hashLen != 32 && hashLen != 64) [[unlikely]]
                ThrowNoiseError("Noise expects HASHLEN 32 or 64");

            const auto k1 = result[0].subspan(0, SYMMETRIC_KEY_SIZE);
            const auto k2 = result[1].subspan(0, SYMMETRIC_KEY_SIZE);

            CipherState c1{cs}, c2{cs};
            c1.InitializeKey(k1);
            c2.InitializeKey(k2);
            return {c1, c2};
        }

    private:
        const Cipher& cipher;
        const Hash& hash;

        static HkdfResult HkdfExpand(const std::span<const std::uint8_t> salt_ck,
                                      const std::span<const std::uint8_t> input_km,
                                      const std::string& hash_name,
                                      const std::size_t hash_len,
                                      const std::size_t num_outputs) {
            const auto kdf = Botan::KDF::create_or_throw("HKDF(" + hash_name + ")");
            const std::size_t total = hash_len * num_outputs;

            HkdfResult result;
            result.buffer = kdf->derive_key(total, input_km, salt_ck, {});
            result.count = num_outputs;

            // Create spans (views) into the contiguous buffer - zero copy
            for (std::size_t i = 0; i < num_outputs; ++i) {
                const auto start = result.buffer.data() + (i * hash_len);
                result.outputs[i] = std::span<const std::uint8_t>(start, hash_len);
            }

            return result;
        }
    };
}
