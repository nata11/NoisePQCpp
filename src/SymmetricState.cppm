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
    class HandshakeState; // Forward declaration (friend, for ScrubHkdfState)

    /**
     * Manages the handshake's chaining key and hash state (Noise spec Section 5.2).
     *
     * Encapsulates the symmetric cryptographic operations that underlie the Noise
     * handshake: MixKey, MixHash, MixKeyAndHash, EncryptAndHash, DecryptAndHash,
     * and Split. This class is algorithm-agnostic — it treats DH and KEM outputs
     * uniformly as input keying material for HKDF, which it computes itself as Noise spec
     * Section 4.3 writes it, with one HMAC object owned by the state.
     *
     * A moved-from SymmetricState may only be destroyed: its hash and HMAC objects have been
     * taken, and copying it throws NoiseError.
     *
     * @see Noise spec Section 5.2 (The SymmetricState object)
     */
    class SymmetricState {
    public:
        CipherState cs;                 ///< Embedded CipherState for encrypt/decrypt operations.
        std::vector<std::uint8_t> ck;   ///< Chaining key (HASHLEN bytes).
        std::vector<std::uint8_t> h;    ///< Handshake hash (HASHLEN bytes).
        std::size_t hashLen{0};         ///< Hash output length (32 for SHA-256/BLAKE2s, 64 for SHA-512/BLAKE2b).

        /**
         * @param cipher Builds the embedded CipherState (not retained).
         * @param hash Its Botan hash is cloned; this state owns the clone, so the Protocol's
         *        Hash is never mutated by a handshake and one Protocol can serve many threads.
         */
        SymmetricState(const Cipher& cipher, const Hash& hash)
            : cs{cipher, NOISE_MAX_MESSAGE_SIZE},
              hashLen{hash.hash_function->output_length()},
              m_hash{hash.hash_function->new_object()},
              m_hmac{CreateHmac(*m_hash)} {
            ReserveHkdfBuffers();
        }

        /** Copy constructor. The copy owns a fresh hash clone and a fresh, unkeyed HMAC (every MixHash ends in final() and every derivation re-keys, so there is no in-flight state).
         *  @throws NoiseError If other has been moved from. */
        SymmetricState(const SymmetricState& other)
            : cs{other.cs},
              ck{other.ck},
              h{other.h},
              hashLen{other.hashLen},
              m_hash{LiveHash(other).new_object()},
              m_hmac{other.m_hmac->new_object()} {
            ReserveHkdfBuffers();
        }

        // Move constructor
        SymmetricState(SymmetricState&& other) noexcept
            : cs{std::move(other.cs)},
              ck{std::move(other.ck)},
              h{std::move(other.h)},
              hashLen{other.hashLen},
              m_hash{std::move(other.m_hash)},
              m_hmac{std::move(other.m_hmac)},
              m_hkdfOut{std::move(other.m_hkdfOut)},
              m_tempKey{std::move(other.m_tempKey)} {}

        /** Destructor. Scrubs the chaining key; h is public transcript data and is left alone. */
        ~SymmetricState() {
            Botan::secure_scrub_memory(ck);
        }

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
         * @param protocolName The Noise protocol name (ASCII text, Noise spec Section 8).
         */
        void InitializeSymmetric(const std::string_view protocolName) {
            h.assign(hashLen, 0);
            if (protocolName.size() <= hashLen) {
                std::ranges::transform(protocolName, h.begin(),
                                       [](const char c) { return static_cast<std::uint8_t>(c); });
            }
            else {
                m_hash->update(protocolName);  // in place, as MixHash does: no temporary from process()
                m_hash->final(h);
            }
            ck = h;
            std::array<std::uint8_t, SYMMETRIC_KEY_SIZE> zero_key{};
            cs.InitializeKey(zero_key);  // k = empty: an all-zero key means "no key" (HasKey())
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
            Hkdf(input_km, 2);

            // out1 = new ck, out2 = temp_k (truncated to 32 bytes when HASHLEN is 64)
            const std::span<const std::uint8_t> out{m_hkdfOut};
            const auto newCk = out.first(hashLen);
            ck.assign(newCk.begin(), newCk.end());
            cs.InitializeKey(out.subspan(hashLen, hashLen).first(SYMMETRIC_KEY_SIZE));

            ScrubHkdfBuffers();
        }

        /** Sets h = HASH(h || data), binding data into the handshake transcript (Noise spec Section 5.2). */
        void MixHash(const std::span<const std::uint8_t> data) {
            m_hash->update(h);
            m_hash->update(data);
            m_hash->final(h);
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
            Hkdf(input_km, 3);

            // out1 = new ck, out2 = temp_h, out3 = temp_k (truncated to 32 bytes when HASHLEN is 64)
            const std::span<const std::uint8_t> out{m_hkdfOut};
            MixHash(out.subspan(hashLen, hashLen));   // h = HASH(h || temp_h)

            const auto newCk = out.first(hashLen);
            ck.assign(newCk.begin(), newCk.end());
            cs.InitializeKey(out.subspan(2 * hashLen, hashLen).first(SYMMETRIC_KEY_SIZE));

            ScrubHkdfBuffers();
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
            const auto newCiphertext = std::span{dst}.subspan(ciphertextOff);

            MixHash(newCiphertext);
        }

        /**
         * Decrypts ciphertext with the current h as associated data, appends the plaintext to
         * dst, then mixes the ciphertext into h (Noise spec Section 5.2 DecryptAndHash:
         * `plaintext = DecryptWithAd(h, ciphertext); MixHash(ciphertext)`).
         *
         * This is the sender's EncryptAndHash in mirror image: both use the pre-mix h as AD
         * and both mix the same ciphertext afterwards, so the transcripts agree. No copy of h
         * is needed because dst and ciphertext never alias in this library (every caller
         * passes a fresh vector and a span into the received message); the earlier
         * copy-then-mix-then-decrypt form produced the same bytes, which the vectors pin.
         *
         * @param[in,out] dst Buffer to append decrypted plaintext to.
         * @param[in] ciphertext AEAD ciphertext (with tag) to decrypt.
         */
        void DecryptAndHash(std::vector<std::uint8_t>& dst,
                            const std::span<const std::uint8_t> ciphertext) {
            cs.DecryptWithAd(dst, h, ciphertext);
            MixHash(ciphertext);
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
            Hkdf({}, 2);

            // k1, k2 = the first 32 bytes of out1 and out2 (truncated when HASHLEN is 64)
            const std::span<const std::uint8_t> out{m_hkdfOut};
            // Built in place and returned by NRVO: two CipherState copies (of cs), not four.
            std::pair<CipherState, CipherState> pair{cs, cs};
            pair.first.InitializeKey(out.first(hashLen).first(SYMMETRIC_KEY_SIZE));
            pair.second.InitializeKey(out.subspan(hashLen, hashLen).first(SYMMETRIC_KEY_SIZE));

            ScrubHkdfBuffers();
            return pair;
        }

    private:
        friend class HandshakeState;   ///< For ScrubHkdfState() in HandshakeState::Reset().

        std::unique_ptr<Botan::HashFunction> m_hash;  ///< This state's own hash (a clone of the Protocol's; never shared).
        /// One HMAC over the same hash, created once; every derivation re-keys it (Noise spec Section 4.3 HKDF).
        /// mutable, with the two buffers below, because Split() is const and uses them as scratch.
        mutable std::unique_ptr<Botan::MessageAuthenticationCode> m_hmac;
        mutable Botan::secure_vector<std::uint8_t> m_hkdfOut;   ///< HKDF outputs, contiguous; reserved to 3 * HASHLEN.
        mutable Botan::secure_vector<std::uint8_t> m_tempKey;   ///< HKDF temp key (the PRK); reserved to HASHLEN.

        /** The source's hash object for the copy constructor; a moved-from source throws instead of a null dereference. */
        static const Botan::HashFunction& LiveHash(const SymmetricState& other) {
            if (!other.m_hash || !other.m_hmac) [[unlikely]] {
                throw NoiseError("noisepqc++/SymmetricState: copy of a moved-from state");
            }
            return *other.m_hash;
        }

        /** Builds the HMAC for the state's hash; Botan failures become NoiseError (cannot fail for the four Noise hashes). */
        static std::unique_ptr<Botan::MessageAuthenticationCode> CreateHmac(const Botan::HashFunction& hash) {
            try {
                return Botan::MessageAuthenticationCode::create_or_throw("HMAC(" + hash.name() + ")");
            }
            catch (const Botan::Exception& e) {
                // Botan types never escape the library (NoiseError model)
                throw NoiseError(std::string("noisepqc++/SymmetricState: ") + e.what());
            }
        }

        /** Reserves the HKDF scratch buffers so that no derivation allocates in steady state. */
        void ReserveHkdfBuffers() {
            m_hkdfOut.reserve(3 * hashLen);
            m_tempKey.reserve(hashLen);
        }

        /**
         * HKDF exactly as Noise spec Section 4.3 writes it, with ck as the HMAC key:
         *   temp = HMAC(ck, ikm); out1 = HMAC(temp, 0x01); out2 = HMAC(temp, out1 || 0x02);
         *   out3 = HMAC(temp, out2 || 0x03) when outputs == 3.
         * The outputs land contiguously in m_hkdfOut (outputs * HASHLEN bytes); the 0x0i byte is
         * fed with update(uint8_t), not by concatenation. No allocation in steady state.
         *
         * @param ikm Input keying material (DH/KEM shared secret, PSK, or empty for Split).
         * @param outputs 2 or 3.
         */
        void Hkdf(const std::span<const std::uint8_t> ikm, const std::size_t outputs) const {
            m_tempKey.resize(hashLen);
            m_hmac->set_key(ck);
            m_hmac->update(ikm);
            m_hmac->final(m_tempKey);

            m_hkdfOut.resize(outputs * hashLen);
            const std::span<std::uint8_t> out{m_hkdfOut};
            m_hmac->set_key(m_tempKey);
            m_hmac->update(std::uint8_t{0x01});
            m_hmac->final(out.first(hashLen));
            for (std::size_t i = 1; i < outputs; ++i) {
                m_hmac->update(out.subspan((i - 1) * hashLen, hashLen));
                m_hmac->update(static_cast<std::uint8_t>(i + 1));
                m_hmac->final(out.subspan(i * hashLen, hashLen));
            }
        }

        /** Scrubs the HKDF outputs and the temp key after a derivation (capacity is kept). */
        void ScrubHkdfBuffers() const {
            Botan::secure_scrub_memory(m_hkdfOut);
            m_hkdfOut.clear();
            Botan::secure_scrub_memory(m_tempKey);
            m_tempKey.clear();
        }

        /**
         * Clears the HMAC's keyed state (the pads derived from the last temp key; after Split
         * that is the PRK of both transport keys) and scrubs the HKDF buffers. Called from
         * HandshakeState::Reset(); the destructor needs nothing extra, because Botan zeroizes
         * its secure_vectors on destruction.
         */
        void ScrubHkdfState() const {
            m_hmac->clear();
            ScrubHkdfBuffers();
        }
    };
}
