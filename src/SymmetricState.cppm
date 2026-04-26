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

export module noise:symmetricstate;
import std;
import :common;
import :cipher;
import :hash;
import :cipherstate;
import :errors;

export namespace Noise
{
    /**
     * Zero-copy HKDF result container.
     *
     * Holds a single contiguous secure buffer with span views into each
     * HKDF output segment, avoiding separate allocations per output.
     */
    struct HkdfResult {
        Botan::secure_vector<std::uint8_t> buffer;  ///< Contiguous HKDF output buffer.
        std::array<std::span<const std::uint8_t>, 3> outputs;  ///< Span views into buffer segments.
        std::size_t count;  ///< Number of valid outputs (2 or 3).

        /** @return Span view of the i-th HKDF output. */
        [[nodiscard]] std::span<const std::uint8_t> operator[](const std::size_t i) const {
            return outputs[i];
        }
    };

    /**
     * Manages the handshake's chaining key and hash state (Noise spec Section 5.2).
     *
     * Encapsulates the symmetric cryptographic operations that underlie the Noise
     * handshake: MixKey, MixHash, MixKeyAndHash, EncryptAndHash, DecryptAndHash,
     * and Split. This class is algorithm-agnostic — it treats DH and KEM outputs
     * uniformly as input keying material for HKDF.
     *
     * @see Noise spec Section 5.2 (The SymmetricState object)
     */
    class SymmetricState {
    public:
        CipherState cs;                 ///< Embedded CipherState for encrypt/decrypt operations.
        std::vector<std::uint8_t> ck;   ///< Chaining key (HASHLEN bytes).
        std::vector<std::uint8_t> h;    ///< Handshake hash (HASHLEN bytes).
        std::size_t hashLen{0};         ///< Hash output length (32 for SHA-256/BLAKE2s, 64 for SHA-512/BLAKE2b).

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

        /**
         * Initializes h and ck from the protocol name (Noise spec Section 5.2).
         *
         * If the protocol name fits within HASHLEN bytes, h is set to the name
         * zero-padded to HASHLEN. Otherwise, h = HASH(protocol_name). The chaining
         * key ck is initialized to h, and the CipherState is initialized with an
         * empty (all-zero) key.
         *
         * @param protocolName The ASCII-encoded Noise protocol name string.
         */
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

        /**
         * Mixes input keying material into the chaining key (Noise spec Section 5.2 MixKey).
         *
         * Derives (ck, temp_k) = HKDF(ck, input_km, 2). Updates the chaining key
         * and initializes the CipherState with temp_k (truncated to 32 bytes if
         * HASHLEN is 64).
         *
         * @param input_km DH shared secret or KEM shared secret bytes.
         */
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

        /** Sets h = HASH(h || data), binding data into the handshake transcript (Noise spec Section 5.2). */
        void MixHash(const std::span<const std::uint8_t> data) {
            hash.hash_function->update(h);
            hash.hash_function->update(data);
            hash.hash_function->final(h);
        }

        /**
         * Derives (ck, temp_h, temp_k) = HKDF(ck, input_km, 3), then MixHash(temp_h)
         * and initializes CipherState with temp_k (Noise spec Section 5.2 MixKeyAndHash).
         *
         * Used by PSK tokens and skem tokens to bind keying material into both
         * the chaining key and the handshake hash simultaneously.
         *
         * @param input_km Input keying material (PSK or KEM shared secret).
         */
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

        /**
         * Encrypts plaintext and appends ciphertext to dst, then mixes ciphertext into h
         * (Noise spec Section 5.2 EncryptAndHash).
         *
         * Tracks the ciphertext offset so that only the newly appended bytes are mixed
         * into the hash, not the entire dst buffer.
         *
         * @param[in,out] dst Buffer to append ciphertext to.
         * @param[in] plaintext Data to encrypt (passed as AD=h to CipherState).
         */
        void EncryptAndHash(std::vector<std::uint8_t>& dst,
                            const std::span<const std::uint8_t> plaintext) {
            // Save the offset where new ciphertext will start
            const std::size_t ciphertextOff = dst.size();

            // Encrypt and append to dst
            cs.EncryptWithAd(dst, h, plaintext);

            // Mix ONLY the newly added ciphertext portion into hash
            const auto start = std::next(dst.begin(), static_cast<std::ptrdiff_t>(ciphertextOff));
            const std::span<const std::uint8_t> newCiphertext(start, dst.end());

            MixHash(newCiphertext);
        }

        /**
         * Mixes ciphertext into h, then decrypts and appends plaintext to dst
         * (Noise spec Section 5.2 DecryptAndHash).
         *
         * The ordering is critical for correctness: MixHash(ciphertext) must happen
         * BEFORE decryption to maintain transcript consistency with the sender's
         * EncryptAndHash. However, decryption needs the hash state from BEFORE mixing
         * as the AEAD associated data. Therefore we save a copy of h, mix, then
         * decrypt using the saved copy.
         *
         * @param[in,out] dst Buffer to append decrypted plaintext to.
         * @param[in] ciphertext AEAD ciphertext (with tag) to decrypt.
         */
        void DecryptAndHash(std::vector<std::uint8_t>& dst,
                            const std::span<const std::uint8_t> ciphertext) {

            // Save h BEFORE mixing — needed as AD for decryption, while the
            // transcript must reflect the post-mix state for consistency with the sender.
            std::vector<std::uint8_t> hPrev(h.begin(), h.end());

            // Mix ciphertext into transcript BEFORE decryption (Noise spec ordering).
            MixHash(ciphertext);

            // Decrypt using the pre-mix h as AD, matching the sender's EncryptAndHash.
            cs.DecryptWithAd(dst, hPrev, ciphertext);
        }

        /** @return The current handshake hash h (for channel binding after completion). */
        [[nodiscard]] auto GetHandshakeHash() const {
            return h;
        }

        /**
         * Derives two transport CipherStates from the chaining key (Noise spec Section 5.2 Split).
         *
         * Computes (k1, k2) = HKDF(ck, empty, 2). Returns (cs1, cs2) where cs1
         * encrypts initiator→responder traffic and cs2 encrypts responder→initiator.
         * Keys are truncated to 32 bytes if HASHLEN is 64.
         *
         * @return Pair of transport CipherStates (cs1, cs2).
         */
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

        /**
         * Performs HKDF key derivation with zero-copy output via span views (RFC 5869).
         *
         * @param salt_ck The chaining key used as HKDF salt.
         * @param input_km Input keying material (DH/KEM shared secret, or empty for Split).
         * @param hash_name Botan hash algorithm name (e.g., "SHA-256").
         * @param hash_len Output length per segment (HASHLEN).
         * @param num_outputs Number of output segments (2 or 3).
         * @return HkdfResult with span views into a contiguous secure buffer.
         */
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
