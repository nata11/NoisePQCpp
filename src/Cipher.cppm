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
        // Defined before the constructors so that their static_asserts can evaluate it.
        /**
         * Encodes the 96-bit Noise nonce (Noise spec Section 5.1): 4 zero bytes, then the 64-bit
         * counter in little-endian order for ChaCha20-Poly1305 (RFC 7539 Section 2.3) or big-endian
         * order for AES-GCM (NIST SP 800-38D). The bytes are produced by shifting, so the layout
         * is the same on every host regardless of its byte order.
         */
        static constexpr std::array<std::uint8_t, 12> EncodeNonce(const std::uint64_t n, const bool bigEndian) noexcept {
            std::array<std::uint8_t, 12> encoded{};
            for (std::size_t i = 0; i < 8; ++i) {
                encoded[bigEndian ? 11 - i : 4 + i] = static_cast<std::uint8_t>(n >> (8 * i));
            }
            return encoded;
        }

    public:
        /** Default constructor: ChaCha20-Poly1305. */
        Cipher() : Cipher{CipherAlgo::ChaChaPoly} {}

        /**
         * Construct from a CipherAlgo enum value. The value is checked against CipherAlgos
         * before any Botan call.
         * @param algo One of the two Noise ciphers.
         * @throws ProtocolNotSupportedError If algo is not an entry of CipherAlgos.
         * @throws NoiseError If Botan cannot construct the AEAD.
         */
        explicit Cipher(const CipherAlgo algo) : m_algo{Validate(algo)} {
            CreateModes();
            // m_tag is reserved on first use: a Cipher that never encrypts allocates nothing for it.

            // The 96-bit nonce layout is pinned at compile time: 4 zero bytes, then the counter
            // little-endian (ChaChaPoly) or big-endian (AESGCM), independent of the host's byte order.
            static_assert(EncodeNonce(0x0102030405060708, false)
                          == std::array<std::uint8_t, 12>{0, 0, 0, 0, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01});
            static_assert(EncodeNonce(0x0102030405060708, true)
                          == std::array<std::uint8_t, 12>{0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});
        }

        /**
         * Construct from a Noise cipher name: exactly "ChaChaPoly" or "AESGCM" (case-sensitive).
         * The name is resolved through CipherAlgos before any Botan call; no other string
         * reaches Botan's algorithm parser.
         * @param cipher_name Noise cipher name.
         * @throws ProtocolNotSupportedError If the name is not one of the two Noise names.
         * @throws NoiseError If Botan cannot construct the AEAD.
         */
        explicit Cipher(const std::string_view cipher_name) : Cipher{Resolve(cipher_name)} {}

        // Copy constructor: same algorithm, fresh (unkeyed) Botan objects, so both directions start
        // unkeyed and the cache empty; the source's cache is not copied.
        Cipher(const Cipher& other)
            : m_algo(other.m_algo) {
            CreateModes();
        }

        // Move constructor: takes the Botan objects, the tag scratch and the key cache (key and
        // both direction flags); the source's cached key is scrubbed and its flags cleared.
        Cipher(Cipher&& other) noexcept
            : m_enc(std::move(other.m_enc)),
              m_dec(std::move(other.m_dec)),
              m_algo(other.m_algo),
              m_tag(std::move(other.m_tag)),
              m_loadedKey(other.m_loadedKey),
              m_encKeyed(other.m_encKeyed),
              m_decKeyed(other.m_decKeyed) {
            Botan::secure_scrub_memory(other.m_loadedKey);
            other.m_encKeyed = false;
            other.m_decKeyed = false;
        }

        Cipher& operator=(const Cipher&) = delete;

        Cipher& operator=(Cipher&&) = delete;

        /** Scrubs the cached key; Botan scrubs its own key schedules. */
        ~Cipher() {
            Botan::secure_scrub_memory(m_loadedKey);
        }

        /**
         * Encrypts plaintext with AEAD and appends ciphertext (including tag) to dst.
         *
         * The body is encrypted in place in dst (one resize to the final length, no
         * whole-buffer copy); only the tag goes through Botan's finish, via the member
         * secure_vector. Both Noise AEADs have update_granularity() == 1, so in-place
         * processing is legal at any length.
         *
         * @param[in,out] dst Buffer to append ciphertext to.
         * @param[in] k 32-byte encryption key.
         * @param[in] n 64-bit nonce counter (encoded to 96-bit Noise nonce format).
         * @param[in] ad Associated data for AEAD authentication.
         * @param[in] plaintext Data to encrypt.
         * @throws NoiseError If k is not SYMMETRIC_KEY_SIZE bytes (dst untouched), or if the
         *         cipher backend fails. On a backend failure the scratch region dst[offset, end)
         *         (the plaintext copy) is scrubbed and dst is restored to its entry size.
         */
        void Encrypt(std::vector<std::uint8_t>& dst,
                     const std::span<const std::uint8_t> k,
                     const std::uint64_t n,
                     const std::span<const std::uint8_t> ad,
                     const std::span<const std::uint8_t> plaintext) const {
            RequireKeySize(k, "Encrypt");

            const std::size_t offset = dst.size();
            const std::size_t bodySize = plaintext.size();
            const std::size_t tagSize = m_enc->tag_size();

            // One resize to the final length, then the plaintext goes to its final place
            dst.resize(offset + bodySize + tagSize);
            const auto body = std::span{dst}.subspan(offset, bodySize);
            std::ranges::copy(plaintext, body.begin());

            try {
                LoadKey(k, *m_enc, m_encKeyed);
                ReserveTag(tagSize);
                m_enc->set_associated_data(ad);
                const auto nonce = EncodeNonce(n, m_algo == CipherAlgo::AESGCM);
                m_enc->start(nonce);

                // Encrypt the body in place; finish only the tag (secure_vector overload, no copy)
                if (bodySize > 0 && m_enc->process(body) != bodySize) [[unlikely]] {
                    throw NoiseError("noisepqc++/Cipher/Encrypt: AEAD processed an unexpected length");
                }
                m_tag.clear();
                m_enc->finish(m_tag);
                if (m_tag.size() != tagSize) [[unlikely]] {
                    throw NoiseError("noisepqc++/Cipher/Encrypt: AEAD produced an unexpected tag length");
                }
                std::ranges::copy(m_tag, std::span{dst}.subspan(offset + bodySize).begin());
            }
            catch (const Botan::Exception& e) {
                // Botan types never escape the library (NoiseError model)
                ForgetKeying();   // a half-keyed object is never trusted
                ScrubAndRestore(dst, offset);
                throw NoiseError(std::string("noisepqc++/Cipher/Encrypt: ") + e.what());
            }
            catch (...) {
                ForgetKeying();
                ScrubAndRestore(dst, offset);
                throw;
            }
        }

        /**
         * Decrypts AEAD ciphertext (with tag verification) and appends plaintext to dst.
         *
         * The body is decrypted in place in dst and the tag is verified through the member
         * secure_vector, so no whole-buffer copy is made. Until the tag verifies, dst[offset,
         * end) holds unauthenticated plaintext; on a tag failure that region is scrubbed and
         * dst is restored to its entry size before DecryptionError is thrown.
         *
         * @param[in,out] dst Buffer to append decrypted plaintext to.
         * @param[in] k 32-byte decryption key.
         * @param[in] n 64-bit nonce counter.
         * @param[in] ad Associated data for AEAD verification.
         * @param[in] ciphertext Data to decrypt (includes AEAD tag).
         * @throws DecryptionError If the ciphertext is shorter than the AEAD tag, or the tag
         *         does not verify. dst is restored to its entry size and the scratch region
         *         is scrubbed.
         * @throws NoiseError If k is not SYMMETRIC_KEY_SIZE bytes (dst untouched), or if the
         *         cipher backend fails for any other reason; same restore-and-scrub.
         */
        void Decrypt(std::vector<std::uint8_t>& dst,
                     const std::span<const std::uint8_t> k,
                     const std::uint64_t n,
                     const std::span<const std::uint8_t> ad,
                     const std::span<const std::uint8_t> ciphertext) const {
            RequireKeySize(k, "Decrypt");

            const std::size_t tagSize = m_dec->tag_size();

            // A ciphertext without a complete tag cannot authenticate; reject it before
            // touching dst or the cipher object.
            if (ciphertext.size() < tagSize) [[unlikely]] {
                throw DecryptionError{};
            }

            const std::size_t offset = dst.size();
            const std::size_t bodySize = ciphertext.size() - tagSize;

            // The body goes to its final place; the tag stays in the caller's buffer
            dst.resize(offset + bodySize);
            const auto body = std::span{dst}.subspan(offset, bodySize);
            std::ranges::copy(ciphertext.first(bodySize), body.begin());

            try {
                LoadKey(k, *m_dec, m_decKeyed);
                ReserveTag(tagSize);
                m_dec->set_associated_data(ad);
                const auto nonce = EncodeNonce(n, m_algo == CipherAlgo::AESGCM);
                m_dec->start(nonce);

                // Decrypt the body in place, then verify the tag alone (finish leaves m_tag empty)
                if (bodySize > 0 && m_dec->process(body) != bodySize) [[unlikely]] {
                    throw NoiseError("noisepqc++/Cipher/Decrypt: AEAD processed an unexpected length");
                }
                const auto tag = ciphertext.last(tagSize);
                m_tag.assign(tag.begin(), tag.end());
                m_dec->finish(m_tag);
            }
            catch (const Botan::Invalid_Authentication_Tag&) {
                ScrubAndRestore(dst, offset);
                throw DecryptionError{};
            }
            catch (const Botan::Exception& e) {
                // Botan types never escape the library (NoiseError model)
                ForgetKeying();   // a half-keyed object is never trusted
                ScrubAndRestore(dst, offset);
                throw NoiseError(std::string("noisepqc++/Cipher/Decrypt: ") + e.what());
            }
            catch (...) {
                ForgetKeying();
                ScrubAndRestore(dst, offset);
                throw;
            }
        }

        /** @return The Noise cipher name ("ChaChaPoly" or "AESGCM"). */
        [[nodiscard]] std::string_view String() const {
            return GetCipherAlgorithmName(m_algo);
        }

        [[nodiscard]] auto GetAeadTagSize() const {
            return m_enc->tag_size();
        }

        /** Clears both AEAD directions and scrubs the cached key, so the next call re-keys. */
        void Reset() const {
            m_enc->clear();
            m_dec->clear();
            Botan::secure_scrub_memory(m_loadedKey);
            ForgetKeying();
        }

    private:
        std::unique_ptr<Botan::AEAD_Mode> m_enc, m_dec;
        const CipherAlgo m_algo;
        /// Tag scratch for finish(): reserved to the tag size on first use, then never reallocated.
        mutable Botan::secure_vector<std::uint8_t> m_tag;
        /// The key last given to Encrypt/Decrypt. m_encKeyed / m_decKeyed say which
        /// direction has been keyed with it; a new key clears both. Encrypt/Decrypt are const and a
        /// Cipher is single-thread, hence mutable.
        mutable std::array<std::uint8_t, SYMMETRIC_KEY_SIZE> m_loadedKey{};
        mutable bool m_encKeyed{false};
        mutable bool m_decKeyed{false};

        /** @throws NoiseError If k is not a 32-byte Noise symmetric key (a caller error). */
        static void RequireKeySize(const std::span<const std::uint8_t> k, const std::string_view where) {
            if (k.size() != SYMMETRIC_KEY_SIZE) [[unlikely]] {
                throw NoiseError(std::string("noisepqc++/Cipher/") + std::string(where) + ": key size");
            }
        }

        /**
         * Keys one AEAD direction with k unless it already holds k. A key that differs from the
         * cached one (constant-time compare) is recorded and both direction flags are cleared;
         * then the direction in use is keyed if its flag is clear. A transport CipherState uses one
         * direction with one key for a whole session, so the AES key expansion and GHASH
         * precompute (or the ChaCha key load) run once per key instead of once per message; a
         * handshake, whose key changes at almost every call, keys exactly the direction it uses,
         * as before. A flag is set only after set_key returns, so a throwing set_key leaves that
         * direction marked unkeyed.
         */
        void LoadKey(const std::span<const std::uint8_t> k, Botan::AEAD_Mode& mode, bool& keyed) const {
            if (!Botan::constant_time_compare(k, m_loadedKey)) {
                ForgetKeying();
                std::ranges::copy(k, m_loadedKey.begin());
            }
            if (!keyed) {
                mode.set_key(k);
                keyed = true;
            }
        }

        /** Marks both directions unkeyed (the cached key bytes are left to the caller to scrub). */
        void ForgetKeying() const noexcept {
            m_encKeyed = false;
            m_decKeyed = false;
        }

        /** Reserves the tag scratch on first use (one allocation per Cipher that encrypts or decrypts). */
        void ReserveTag(const std::size_t tagSize) const {
            if (m_tag.capacity() < tagSize) [[unlikely]] {
                m_tag.reserve(tagSize);
            }
        }

        /**
         * Failure path shared by Encrypt and Decrypt: scrub dst[offset, end) (the plaintext
         * copy, or unauthenticated plaintext) and the tag scratch, then restore dst to its
         * entry size.
         */
        void ScrubAndRestore(std::vector<std::uint8_t>& dst, const std::size_t offset) const {
            Botan::secure_scrub_memory(std::span{dst}.subspan(offset));
            dst.resize(offset);
            Botan::secure_scrub_memory(m_tag);
            m_tag.clear();
        }

        /** Resolves a Noise cipher name or throws ProtocolNotSupportedError. */
        static CipherAlgo Resolve(const std::string_view cipher_name) {
            const auto algo = ParseCipherAlgo(cipher_name);
            if (!algo) {
                throw ProtocolNotSupportedError{};
            }
            return *algo;
        }

        /** Returns algo if CipherAlgos lists it, else throws ProtocolNotSupportedError. */
        static CipherAlgo Validate(const CipherAlgo algo) {
            if (!std::ranges::any_of(CipherAlgos, [algo](const auto& entry) { return entry.first == algo; })) {
                throw ProtocolNotSupportedError{};
            }
            return algo;
        }

        /** Botan's algorithm name for a Noise cipher. */
        static constexpr std::string_view BotanName(const CipherAlgo algo) {
            switch (algo) {
            case CipherAlgo::AESGCM: return "AES-256/GCM";
            case CipherAlgo::ChaChaPoly: return "ChaCha20Poly1305";
            }
            return "";
        }

        /** Builds the two Botan AEAD objects for m_algo; Botan failures become NoiseError. */
        void CreateModes() {
            try {
                const auto name = BotanName(m_algo);
                m_enc = Botan::AEAD_Mode::create_or_throw(name, Botan::Cipher_Dir::Encryption);
                m_dec = Botan::AEAD_Mode::create_or_throw(name, Botan::Cipher_Dir::Decryption);
            }
            catch (const Botan::Exception& e) {
                // Botan types never escape the library (NoiseError model)
                throw NoiseError(std::string("noisepqc++/Cipher: ") + e.what());
            }
        }

    };
}
