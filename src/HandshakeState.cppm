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

export module noise:handshakestate;

import :common;
import :dh;
import :symmetricstate;
import :cipherstate;
import :protocol;
import :pattern;
import :errors;

export namespace Noise
{
    // Forward declarations
    class HandshakeState;

    /**
     * Observer interface for monitoring handshake progress and validating peer keys.
     *
     * Implementations receive callbacks as remote public keys are received during
     * the handshake. This allows applications to perform identity verification
     * (e.g., checking a key against an allowlist) and abort on failure.
     *
     * @see Noise spec Section 11.4 (application responsibilities)
     */
    class HandshakeObserver {
    public:
        virtual ~HandshakeObserver() = default;

        /**
         * Called when a public key is received from the remote peer.
         *
         * @param token The handshake token that triggered the key receipt (e, s, e1).
         * @param pubKey The received public key bytes.
         * @return std::nullopt to accept the key, or an error message string to abort the handshake.
         */
        virtual std::optional<std::string> OnPeerPublicKey(Token token, const PublicKey& pubKey) = 0;
    };

    /**
     * Tracks the current state and results of a Noise handshake.
     *
     * The @c err field uses a tri-state convention:
     * - @c nullptr — handshake is in progress
     * - HandshakeComplete — handshake completed successfully
     * - Any other exception — handshake failed
     *
     * @c state records the same three cases as a plain enum, so IsComplete() and HasError()
     * classify the status without rethrowing @c err. The two fields are always set together
     * and never disagree.
     *
     * After successful completion, @c cipherStates contains the two transport
     * CipherState objects (cs1 for initiator→responder, cs2 for responder→initiator),
     * and @c handshakeHash contains the final transcript hash for channel binding.
     * HandshakeState::TakeCipherStates() moves them out, leaving @c cipherStates empty.
     */
    class HandshakeStatus {
    public:
        /** Progress of the handshake; kept in step with @c err. */
        enum class State : std::uint8_t { InProgress, Done, Failed };

        /** Handshake state: nullptr=in-progress, HandshakeComplete=success, other=failure. */
        std::exception_ptr err{nullptr};

        /** InProgress until the final message is processed, then Done; Failed after any error. */
        State state{State::InProgress};

        /** Public keys discovered during handshake. */
        PublicKey localEphemeral{};
        PublicKey remoteStatic{};
        PublicKey remoteEphemeral{};

        /** Transport cipher states, populated on successful completion (cs1, cs2). */
        std::optional<std::pair<CipherState, CipherState>> cipherStates{};

        /** Final handshake hash for channel binding (Noise spec Section 11.2). */
        std::vector<std::uint8_t> handshakeHash{};

        /** @return true if the handshake completed successfully. Never throws. */
        [[nodiscard]] bool IsComplete() const noexcept {
            return state == State::Done;
        }

        /** @return true if the handshake encountered a non-completion error. Never throws. */
        [[nodiscard]] bool HasError() const noexcept {
            return state == State::Failed;
        }
    };

    /**
     * Configuration for constructing a HandshakeState.
     *
     * Aggregates all inputs required by the Noise spec Initialize() function
     * (Section 5.3): the protocol definition, role, prologue, key material,
     * pre-shared keys, and an optional observer for peer key validation.
     */
    class HandshakeConfig {
    public:
        /** The Noise protocol definition (pattern + algorithms). */
        const Protocol& protocol;
        /** True if this party initiates the handshake (sends the first message). */
        bool isInitiator = false;
        /** Application-specific prologue data mixed into the handshake hash (Noise spec Section 6). */
        std::vector<std::uint8_t> prologue = {};
        /** Local static keypair (required by patterns that use 's' tokens). */
        KeyPair localStatic = {};
        /** Local ephemeral keypair (optional; auto-generated if empty). */
        KeyPair localEphemeral = {};
        /** Remote party's known static public key (required by patterns with a pre-message `s` for the peer, e.g. N, NK, IK, KK). */
        PublicKey remoteStatic = {};
        /** Remote party's known ephemeral public key (rare; for pre-message patterns). */
        PublicKey remoteEphemeral = {};
        /** Pre-shared symmetric keys for PSK patterns (Noise spec Section 9). Each must be exactly 32 bytes. */
        std::vector<std::array<std::uint8_t, SYMMETRIC_KEY_SIZE>> preSharedKeys = {};
        /** Optional observer for peer public key validation callbacks. */
        HandshakeObserver* observer = nullptr;
        /** Maximum handshake message size: 0=default (65535), negative=no limit. Noise spec Section 3. */
        int maxMessageSize = 0;

        /** @return The effective maximum message size in bytes, or 0 if unlimited. */
        [[nodiscard]] int GetMaxMessageSize() const {
            if (maxMessageSize > 0) return maxMessageSize;
            if (maxMessageSize == 0) return NOISE_MAX_MESSAGE_SIZE;
            return 0; // negative means no limit
        }
    };

    /**
     * Implements the Noise handshake state machine (Noise spec Section 5.3).
     *
     * Processes handshake token sequences defined by the chosen pattern,
     * performing DH or KEM key exchanges and symmetric state transitions.
     * Supports classical Noise patterns, PQNoise post-quantum patterns
     * (PQNoise paper), and Hybrid Forward Secrecy patterns (Noise Protocol HFS spec extension).
     *
     * Typical usage:
     * 1. Construct with a HandshakeConfig
     * 2. Call WriteMessage() / ReadMessage() alternately per the pattern
     * 3. On completion, take the transport CipherStates with TakeCipherStates()
     *    (or copy them from GetStatus().cipherStates)
     *
     * The handshake signals completion by setting HandshakeStatus::state to Done and
     * storing a HandshakeComplete in the status (the final message is returned; nothing
     * is thrown). After completion, the HandshakeState cleans up sensitive key material.
     *
     * This class is neither copyable nor movable to prevent accidental
     * duplication of handshake state.
     */
    class HandshakeState {
    public:
        /**
         * Constructs and initializes the handshake state (Noise spec Section 5.3 Initialize).
         *
         * Performs the full initialization sequence: hashes the protocol name into
         * the symmetric state, mixes the prologue, and processes any pre-message
         * public keys. Validates that the correct number of PSKs are provided.
         *
         * @param cfg The handshake configuration containing protocol, keys, and options. The
         *        state keeps a reference to it, so the config, and the Protocol it refers to,
         *        must outlive the state.
         * @throws MissingPSKError If the PSK count does not match the pattern requirement.
         * @throws BadPSKError If any PSK is not exactly 32 bytes.
         * @throws PreMessageError If a required pre-message key is missing.
         */
        explicit HandshakeState(const HandshakeConfig& cfg)
            : m_cfg{cfg},
              m_dh{cfg.protocol.dh},
              m_patterns{cfg.protocol.pattern.messages},
              m_ss{cfg.protocol.cipher, cfg.protocol.hash},
              m_s{cfg.localStatic},
              m_e{cfg.localEphemeral},
              m_rs{cfg.remoteStatic},
              m_re{cfg.remoteEphemeral},
              m_status{},
              m_patternIndex{0},
              m_pskIndex{0},
              m_maxMessageSize{cfg.GetMaxMessageSize()},
              m_dhLen{cfg.protocol.dh.Size()},
              m_isInitiator{cfg.isInitiator}
        {
            // Validate PSKs
            if (cfg.protocol.pattern.numPSKs != cfg.preSharedKeys.size()) {
                throw MissingPSKError();
            }
            for (const auto& psk : cfg.preSharedKeys) {
                // ReSharper disable once CppIfCanBeReplacedByConstexprIf
                if (psk.size() != SYMMETRIC_KEY_SIZE) {
                    throw BadPSKError();
                }
            }

            // Initialize status with known remote keys
            m_status.remoteStatic = cfg.remoteStatic;
            m_status.remoteEphemeral = cfg.remoteEphemeral;
            if (!cfg.localEphemeral.IsEmpty()) {
                m_status.localEphemeral = cfg.localEphemeral.public_key;
            }

            // Initialize symmetric state from the protocol name's bytes
            m_ss.InitializeSymmetric(cfg.protocol.String());
            m_ss.MixHash(cfg.prologue);

            // Handle pre-messages
            HandlePreMessages();
        }

        /// A temporary config would dangle: the state keeps a reference to it.
        explicit HandshakeState(HandshakeConfig&&) = delete;

        /// @name Non-copyable, non-movable
        /// @{
        HandshakeState(const HandshakeState&) = delete;
        HandshakeState(HandshakeState&&) = delete;
        HandshakeState& operator=(const HandshakeState&) = delete;
        HandshakeState& operator=(HandshakeState&&) = delete;
        /// @}

        /** Destructor. Scrubs sensitive key material via Reset(). */
        ~HandshakeState() {
            Reset();
        }

        /** @return The current handshake status including keys and completion state. */
        [[nodiscard]] const HandshakeStatus& GetStatus() const {
            return m_status;
        }

        /**
         * Moves the transport CipherStates out of the status (the Split() output: cs1 for
         * initiator→responder, cs2 for responder→initiator). Afterwards GetStatus().cipherStates
         * is empty, while the handshake hash and IsComplete() are unchanged. Prefer this over
         * copying GetStatus().cipherStates: each copy constructs two more AEAD objects.
         *
         * @return The (cs1, cs2) pair, or std::nullopt before completion or on a second call.
         */
        [[nodiscard]] std::optional<std::pair<CipherState, CipherState>> TakeCipherStates() noexcept {
            return std::exchange(m_status.cipherStates, std::nullopt);
        }

        /** @return The encapsulated SymmetricState (for advanced inspection). */
        [[nodiscard]] const SymmetricState& GetSymmetricState() const {
            return m_ss;
        }

        /** @return The HandshakeConfig used to construct this state. */
        [[nodiscard]] const HandshakeConfig& GetConfig() const {
            return m_cfg;
        }

        /** @return True if this party is the handshake initiator. */
        [[nodiscard]] bool IsInitiator() const {
            return m_isInitiator;
        }

        /**
         * Scrubs the library's own copies of secret material: the chaining key (then cleared),
         * the handshake hash (cleared), the embedded CipherState's key, and all three local
         * keypairs (m_e, m_s and the HFS m_e1), whether they were generated here or copied from
         * the HandshakeConfig. The caller's HandshakeConfig is never read or modified here.
         * Idempotent: runs on completion and again in the destructor.
         */
        void Reset() {
            Botan::secure_scrub_memory(m_ss.ck);
            m_ss.ck.clear();
            m_ss.h.clear();
            m_ss.cs.Reset();
            m_ss.ScrubHkdfState();   // HMAC pads from the last temp key, HKDF outputs, temp key

            ScrubKeyPair(m_e);
            ScrubKeyPair(m_s);
            ScrubKeyPair(m_e1);
            m_eKey.reset();   // Botan zeroizes the loaded key data with the last owner
            m_sKey.reset();
            m_reKem.reset();  // the decoded remote ML-KEM keys (public, nothing to scrub)
            m_rsKem.reset();
            m_re1Kem.reset();
        }

        /**
         * Processes a write (send) step of the handshake (Noise spec Section 5.4.2).
         *
         * Executes all tokens in the current message pattern, then encrypts and
         * appends the payload. On the final message of the pattern, the handshake
         * completes: transport CipherStates are derived via Split() and stored
         * in the status.
         *
         * @param payload Application data to encrypt and include (may be empty).
         * @return The handshake message bytes to send to the peer.
         * @throws OutOfOrderError If called when it is the peer's turn.
         * @throws MessageSizeError If the resulting message exceeds maxMessageSize.
         * @throws MissingKeyError If a required key is not set for a token.
         * @throws InvalidPublicKeyError If a DH token uses a low-order remote key, or a KEM token
         *         encapsulates to an invalid pre-message key.
         * @throws HandshakeComplete If called after the handshake has completed.
         */
        std::vector<std::uint8_t> WriteMessage(const std::span<const std::uint8_t> payload) {
            // Check if we have an error
            if (m_status.err) [[unlikely]] {
                std::rethrow_exception(m_status.err);
            }

            // Check if it's our turn to write: the initiator writes the even-indexed messages
            const bool ourTurn = m_isInitiator == ((m_patternIndex & 1) == 0);
            if (!ourTurn) [[unlikely]] {
                Fail(std::make_exception_ptr(OutOfOrderError()));
                std::rethrow_exception(m_status.err);
            }

            std::vector<std::uint8_t> dst{};
            dst.reserve(EstimateWriteMessageSize(payload.size()));
            const std::size_t baseLen = dst.size();

            // Process tokens in current pattern
            for (const auto token : m_patterns[m_patternIndex].tokens) {
                try {
                    switch (token) {
                    case Token::Token_e:
                        onWriteTokenE(dst);  // Now modifies dst in place
                        break;
                    case Token::Token_s:
                        onWriteTokenS(dst);  // Now modifies dst in place
                        break;
                    case Token::Token_ee:
                        onTokenEE();
                        break;
                    case Token::Token_es:
                        onTokenES();
                        break;
                    case Token::Token_se:
                        onTokenSE();
                        break;
                    case Token::Token_ss:
                        onTokenSS();
                        break;
                    case Token::Token_psk:
                        onTokenPsk();
                        break;
                    case Token::Token_ekem:
                        onWriteTokenEKEM(dst);
                        break;
                    case Token::Token_skem:
                        onWriteTokenSKEM(dst);
                        break;
                    case Token::Token_e1:
                        onWriteTokenE1(dst);
                        break;
                    case Token::Token_ekem1:
                        onWriteTokenEKEM1(dst);
                        break;
                    default:
                        throw InvalidTokenError(std::string(to_string(token)));
                    }
                } catch (...) {
                    Fail(std::current_exception());
                    throw;
                }

                if (m_status.err) {
                    std::rethrow_exception(m_status.err);
                }
            }

            // Encrypt and hash the payload, appended to dst in place. Inside the store-and-rethrow
            // block like every other mutating call, so a failure here is sticky too.
            try {
                m_ss.EncryptAndHash(dst, payload);
            } catch (...) {
                Fail(std::current_exception());
                throw;
            }

            // Check message size
            if (m_maxMessageSize > 0 && dst.size() - baseLen > static_cast<std::size_t>(m_maxMessageSize)) {
                Fail(std::make_exception_ptr(MessageSizeError()));
                std::rethrow_exception(m_status.err);
            }

            // Advance; on the final message this derives the transport states and marks the
            // status Done. The message is returned either way, with no copy.
            onDone();
            return dst;
        }

        /**
         * Processes a read (receive) step of the handshake (Noise spec Section 5.4.3).
         *
         * Parses and processes all tokens from the received message, then decrypts
         * the trailing payload. On the final message of the pattern, the handshake
         * completes: transport CipherStates are derived via Split() and stored
         * in the status.
         *
         * @param message The handshake message bytes received from the peer.
         * @return The decrypted application payload (may be empty).
         * @throws OutOfOrderError If called when it is our turn to write.
         * @throws MessageSizeError If the message exceeds maxMessageSize.
         * @throws TruncatedMessageError If the message is too short for expected tokens.
         * @throws MissingKeyError If a required key is not set for decapsulation.
         * @throws DecryptionError If an encrypted field or the payload fails authentication.
         * @throws InvalidPublicKeyError If a received ML-KEM key fails the FIPS 203 check, or a DH
         *         token uses a low-order remote key.
         * @throws NoiseError If the observer rejects a peer key.
         * @throws HandshakeComplete If called after the handshake has completed.
         */
        std::vector<std::uint8_t> ReadMessage(std::span<const std::uint8_t> message) {
            // Check if we have an error
            if (m_status.err) [[unlikely]] {
                std::rethrow_exception(m_status.err);
            }

            // Check message size
            if (m_maxMessageSize > 0 && message.size() > static_cast<std::size_t>(m_maxMessageSize)) [[unlikely]] {
                Fail(std::make_exception_ptr(MessageSizeError()));
                std::rethrow_exception(m_status.err);
            }

            // Check if it's our turn to read: the initiator reads the odd-indexed messages
            const bool theirTurn = m_isInitiator == ((m_patternIndex & 1) != 0);
            if (!theirTurn) [[unlikely]] {
                Fail(std::make_exception_ptr(OutOfOrderError()));
                std::rethrow_exception(m_status.err);
            }

            // Process tokens in current pattern
            for (const auto token : m_patterns[m_patternIndex].tokens) {
                try {
                    switch (token) {
                    case Token::Token_e:
                        message = onReadTokenE(message);
                        break;
                    case Token::Token_s:
                        message = onReadTokenS(message);
                        break;
                    case Token::Token_ee:
                        onTokenEE();
                        break;
                    case Token::Token_es:
                        onTokenES();
                        break;
                    case Token::Token_se:
                        onTokenSE();
                        break;
                    case Token::Token_ss:
                        onTokenSS();
                        break;
                    case Token::Token_psk:
                        onTokenPsk();
                        break;
                    case Token::Token_ekem:
                        message = onReadTokenEKEM(message);
                        break;
                    case Token::Token_skem:
                        message = onReadTokenSKEM(message);
                        break;
                    case Token::Token_e1:
                        message = onReadTokenE1(message);
                        break;
                    case Token::Token_ekem1:
                        message = onReadTokenEKEM1(message);
                        break;
                    default:
                        throw InvalidTokenError(std::string(to_string(token)));
                    }
                } catch (...) {
                    Fail(std::current_exception());
                    throw;
                }

                if (m_status.err) {
                    std::rethrow_exception(m_status.err);
                }
            }

            // Decrypt and hash the payload into dst
            std::vector<std::uint8_t> dst;
            try {
                m_ss.DecryptAndHash(dst, message);
            } catch (...) {
                Fail(std::current_exception());
                throw;
            }

            // Advance; on the final message this derives the transport states and marks the
            // status Done. The decrypted payload is returned either way.
            onDone();
            return dst;
        }

    private:
        const HandshakeConfig& m_cfg;   ///< Immutable configuration reference; the config outlives the state (its rvalue constructor is deleted).
        const Dh& m_dh;                 ///< DH/KEM algorithm from the protocol, which m_cfg refers to and which therefore outlives the state too.
        const std::vector<MessagePattern>& m_patterns; ///< The protocol's message patterns (same lifetime as m_dh).
        SymmetricState m_ss;            ///< Symmetric state (chaining key, hash, cipher).
        KeyPair m_s;                    ///< Local static keypair.
        KeyPair m_e;                    ///< Local ephemeral keypair.
        std::optional<DhPrivateKey> m_eKey; ///< Loaded e (DH algorithms only): generated with m_e, or loaded from it on first use.
        std::optional<DhPrivateKey> m_sKey; ///< Loaded s (DH algorithms only): loaded from m_s at the first static DH token.
        PublicKey m_rs;                 ///< Remote static public key.
        PublicKey m_re;                 ///< Remote ephemeral public key.
        std::optional<KemPublicKey> m_rsKem; ///< Decoded rs (KEM algorithms only): loaded when s was read, or from m_rs at the first skem (a config-provided remote static).
        std::optional<KemPublicKey> m_reKem; ///< Decoded re (KEM algorithms only): loaded when e was read, or from m_re at the first ekem.
        HandshakeStatus m_status;       ///< Current handshake status and results.
        std::uint32_t m_patternIndex;   ///< Index of the current message in the pattern.
        std::uint32_t m_pskIndex;       ///< Index of the next PSK to consume.
        int m_maxMessageSize;           ///< Maximum message size (0=unlimited).
        std::uint8_t m_dhLen;           ///< Shared secret size in bytes (Dh::Size(); also the DH public key size).
        bool m_isInitiator;             ///< True if this party is the initiator.

        /// @name HFS (Hybrid Forward Secrecy) state (Noise Protocol HFS spec extension)
        /// @{
        KeyPair m_e1;                   ///< Local KEM ephemeral keypair for HFS.
        PublicKey m_re1;                ///< Remote KEM ephemeral public key for HFS.
        std::optional<KemPublicKey> m_re1Kem; ///< Decoded re1: loaded when e1 was read, or from m_re1 at ekem1.
        /// @}

        /**
         * Scrubs a shared secret when its scope ends, including during exception unwinding.
         * Declared right after the vector holds its final value, so the span cannot dangle.
         */
        class ScrubGuard {
        public:
            explicit ScrubGuard(std::vector<std::uint8_t>& secret) : m_bytes{secret} {}
            ~ScrubGuard() { Botan::secure_scrub_memory(m_bytes); }
            ScrubGuard(const ScrubGuard&) = delete;
            ScrubGuard& operator=(const ScrubGuard&) = delete;

        private:
            std::span<std::uint8_t> m_bytes;
        };

        /** Scrubs a keypair's private key, then empties both keys. */
        static void ScrubKeyPair(KeyPair& keypair) {
            Botan::secure_scrub_memory(keypair.private_key);
            keypair = {};
        }

        /** Estimates the output message size for pre-allocation, avoiding vector reallocations. */
        [[nodiscard]] std::size_t EstimateWriteMessageSize(std::size_t payloadSize) const {
            std::size_t size = 0;
            const auto& tokens = m_patterns[m_patternIndex].tokens;
            const bool hasKey = m_ss.cs.HasKey();
            const std::size_t overhead = m_ss.cs.aeadOverhead;

            for (const auto token : tokens) {
                switch (token) {
                case Token::Token_e:
                    size += m_dh.PublicKeySize();  // Ephemeral public key (800 to 1,568 bytes for ML-KEM)
                    break;
                case Token::Token_s:
                    size += m_dh.PublicKeySize();  // Static public key
                    if (hasKey) size += overhead;  // Encrypted
                    break;
                case Token::Token_ekem:
                    if (m_dh.IsKEM()) {
                        size += m_dh.CiphertextSize();
                    }
                    break;
                case Token::Token_skem:
                    if (m_dh.IsKEM()) {
                        size += m_dh.CiphertextSize();
                        if (hasKey) size += overhead;
                    }
                    break;
                case Token::Token_e1:
                    // HFS: KEM public key (requires HFS KEM from config)
                    if (m_cfg.protocol.kem.has_value()) {
                        size += m_cfg.protocol.kem->PublicKeySize();
                        if (hasKey) size += overhead;
                    }
                    break;
                case Token::Token_ekem1:
                    // HFS: KEM ciphertext
                    if (m_cfg.protocol.kem.has_value()) {
                        size += m_cfg.protocol.kem->CiphertextSize();
                    }
                    break;
                default:
                    // DH tokens (ee, es, se, ss) and psk don't add to message size
                    break;
                }
            }

            // Add payload size + AEAD overhead (payload is always encrypted at end)
            size += payloadSize;
            if (hasKey) size += overhead;

            return size;
        }

        /**
         * The loaded ephemeral key for the DH tokens. Set by onWriteTokenE when the key is
         * generated here; a config-provided ephemeral is loaded (one multiplication) on first use
         * and cached, so every DH token costs one multiplication.
         */
        [[nodiscard]] const DhPrivateKey& EKey() {
            if (!m_eKey) {
                m_eKey.emplace(m_dh.LoadPrivateKey(m_e.private_key));
            }
            return *m_eKey;
        }

        /** The loaded static key for the DH tokens: loaded from m_s on first use and cached. */
        [[nodiscard]] const DhPrivateKey& SKey() {
            if (!m_sKey) {
                m_sKey.emplace(m_dh.LoadPrivateKey(m_s.private_key));
            }
            return *m_sKey;
        }

        /**
         * The decoded remote ephemeral ML-KEM key for ekem. Loaded (and so checked) when the e
         * token was read; a config-provided remote ephemeral is loaded on first use, so an
         * invalid one fails that WriteMessage with InvalidPublicKeyError.
         */
        [[nodiscard]] const KemPublicKey& ReKem() {
            if (!m_reKem) {
                m_reKem.emplace(m_dh.LoadPublicKey(m_re));
            }
            return *m_reKem;
        }

        /** The decoded remote static ML-KEM key for skem: loaded when s was read, or from the
         *  config's pre-message static on first use (pqIK/pqKK initiator), where an invalid key
         *  fails the skem write with InvalidPublicKeyError as before. */
        [[nodiscard]] const KemPublicKey& RsKem() {
            if (!m_rsKem) {
                m_rsKem.emplace(m_dh.LoadPublicKey(m_rs));
            }
            return *m_rsKem;
        }

        /** The decoded remote HFS ephemeral key for ekem1: loaded when e1 was read. */
        [[nodiscard]] const KemPublicKey& Re1Kem() {
            if (!m_re1Kem) {
                m_re1Kem.emplace(m_cfg.protocol.kem->LoadPublicKey(m_re1));
            }
            return *m_re1Kem;
        }

        /// @name Classical Noise Token Handlers (Noise spec Section 5.4)
        /// @{

        /** Token 'e' (write): Generate ephemeral keypair, send public key, MixHash(e.pub). */
        void onWriteTokenE(std::vector<std::uint8_t>& dst) {
            // Generate ephemeral key if not pre-generated. For a DH algorithm the loaded key
            // object comes with it, so the public key is derived exactly once.
            if (m_e.IsEmpty()) {
                if (m_dh.IsKEM()) {
                    m_e = m_dh.GenerateKeypair();
                }
                else {
                    auto [keypair, key] = m_dh.GenerateKeypairWithKey();
                    m_e = std::move(keypair);
                    m_eKey.emplace(std::move(key));
                }
            }

            const auto& eBytes = m_e.public_key;

            m_ss.MixHash(eBytes);

            if (m_cfg.protocol.pattern.numPSKs > 0) {
                m_ss.MixKey(eBytes);
            }
            m_status.localEphemeral = m_e.public_key;

            dst.insert(dst.end(), eBytes.begin(), eBytes.end());
        }

        /** Token 'e' (read): Receive remote ephemeral public key, MixHash(re.pub). */
        std::span<const std::uint8_t> onReadTokenE(std::span<const std::uint8_t> payload) {
            // Use PublicKeySize() which handles both DH (32/56 bytes) and KEM (800/1184/1568 bytes)
            const auto pubKeyLen = m_dh.PublicKeySize();
            if (payload.size() < pubKeyLen) {
                throw TruncatedMessageError("e");
            }

            const auto eBytes = payload.subspan(0, pubKeyLen);
            const auto tail = payload.subspan(pubKeyLen);

            // An ML-KEM key is checked on receipt (FIPS 203 Section 7.2), before it is
            // stored, shown to the observer, or mixed in; a bad key fails this ReadMessage.
            // The decoded key is kept for the ekem token (one decode per received key)
            if (m_dh.IsKEM()) {
                m_reKem.emplace(m_dh.LoadPublicKey(eBytes));
            }

            m_re.assign(eBytes.begin(), eBytes.end());
            m_status.remoteEphemeral = m_re;   // one copy into each destination

            // Call observer if present
            if (m_cfg.observer) {
                if (auto err = m_cfg.observer->OnPeerPublicKey(Token::Token_e, m_re)) {
                    throw NoiseError(*err);
                }
            }

            m_ss.MixHash(eBytes);

            if (m_cfg.protocol.pattern.numPSKs > 0) {
                m_ss.MixKey(eBytes);
            }

            return tail;
        }

        /** Token 's' (write): Send local static public key via EncryptAndHash (encrypted if key established). */
        void onWriteTokenS(std::vector<std::uint8_t>& dst) {
            if (m_s.IsEmpty()) {
                throw MissingKeyError("s");
            }

            const auto& sBytes = m_s.public_key;

            // Appends the static key (encrypted once a key is set) directly to dst
            m_ss.EncryptAndHash(dst, sBytes);
        }

        /** Token 's' (read): Receive remote static public key via DecryptAndHash. */
        std::span<const std::uint8_t> onReadTokenS(std::span<const std::uint8_t> payload) {
            // Use PublicKeySize() which handles both DH (32/56 bytes) and KEM (800/1184/1568 bytes)
            std::size_t tempLen = m_dh.PublicKeySize();
            if (m_ss.cs.HasKey()) {
                tempLen += m_ss.cs.aeadOverhead;
            }

            if (payload.size() < tempLen) {
                throw TruncatedMessageError("s");
            }

            const auto temp = payload.subspan(0, tempLen);
            const auto tail = payload.subspan(tempLen);

            std::vector<std::uint8_t> sBytes;
            m_ss.DecryptAndHash(sBytes, temp);

            // A KEM static is encapsulated to later, like e: check it on receipt and keep the
            // decoded key for the skem token
            if (m_dh.IsKEM()) {
                m_rsKem.emplace(m_dh.LoadPublicKey(sBytes));
            }

            m_rs = std::move(sBytes);
            m_status.remoteStatic = m_rs;

            // Call observer if present
            if (m_cfg.observer) {
                if (auto err = m_cfg.observer->OnPeerPublicKey(Token::Token_s, m_rs)) {
                    throw NoiseError(*err);
                }
            }

            return tail;
        }

        /** Token 'ee': DH(e, re) and MixKey with the shared secret. */
        void onTokenEE() {
            auto eeBytes = m_dh.DH(EKey(), m_re);
            const ScrubGuard eeGuard{eeBytes};

            m_ss.MixKey(eeBytes);
        }

        /** Token 'es': DH(e, rs) if initiator, DH(s, re) if responder, then MixKey. */
        void onTokenES() {
            auto esBytes = m_isInitiator ? m_dh.DH(EKey(), m_rs)
                                         : m_dh.DH(SKey(), m_re);
            const ScrubGuard esGuard{esBytes};

            m_ss.MixKey(esBytes);
        }

        /** Token 'se': DH(s, re) if initiator, DH(e, rs) if responder, then MixKey. */
        void onTokenSE() {
            auto seBytes = m_isInitiator ? m_dh.DH(SKey(), m_re)
                                         : m_dh.DH(EKey(), m_rs);
            const ScrubGuard seGuard{seBytes};

            m_ss.MixKey(seBytes);
        }

        /** Token 'ss': DH(s, rs) and MixKey with the shared secret. */
        void onTokenSS() {
            auto ssBytes = m_dh.DH(SKey(), m_rs);
            const ScrubGuard ssGuard{ssBytes};

            m_ss.MixKey(ssBytes);
        }

        /** Token 'psk': MixKeyAndHash with the next pre-shared key (Noise spec Section 9). */
        void onTokenPsk() {
            m_ss.MixKeyAndHash(m_cfg.preSharedKeys[m_pskIndex]);

            m_pskIndex++;
        }

        /// @}

        /// @name PQNoise KEM Token Handlers (PQNoise paper)
        /// Implements post-quantum key exchange via ML-KEM encapsulation/decapsulation.
        /// - ekem: Encapsulate to peer's ephemeral public key (m_re)
        /// - skem: Encapsulate to peer's static public key (m_rs)
        /// @{

        /**
         * Token 'ekem' (write): Encapsulate to remote ephemeral, send ciphertext.
         *
         * Per PQNoise paper: the ciphertext is sent in the clear (not encrypted),
         * and the ordering is MixHash(ct) then MixKey(shared_secret). This ensures
         * the ciphertext is bound into the transcript hash before the shared secret
         * is mixed into the chaining key.
         */
        void onWriteTokenEKEM(std::vector<std::uint8_t>& dst) {
            if (!m_dh.IsKEM()) {
                throw NoiseError("ekem token requires KEM algorithm");
            }
            if (m_re.empty()) {
                throw MissingKeyError("remote ephemeral (re) for ekem");
            }

            // Encapsulate to peer's ephemeral public key, decoded when e was read
            auto [ciphertext, shared_secret] = m_dh.Encapsulate(ReKem());
            const ScrubGuard secretGuard{shared_secret};

            // Per PQNoise: MixHash(ct) then MixKey(k)
            m_ss.MixHash(ciphertext);
            m_ss.MixKey(shared_secret);

            // Output the ciphertext (unencrypted - ekem is always in the clear)
            dst.insert(dst.end(), ciphertext.begin(), ciphertext.end());
        }

        /** Token 'ekem' (read): Receive ciphertext, decapsulate with local ephemeral private key. */
        std::span<const std::uint8_t> onReadTokenEKEM(std::span<const std::uint8_t> payload) {
            if (!m_dh.IsKEM()) {
                throw NoiseError("ekem token requires KEM algorithm");
            }

            const auto ctLen = m_dh.CiphertextSize();
            if (payload.size() < ctLen) {
                throw TruncatedMessageError("ekem");
            }

            const auto ciphertext = payload.subspan(0, ctLen);
            const auto tail = payload.subspan(ctLen);

            // Per PQNoise: MixHash(ct) first
            m_ss.MixHash(ciphertext);

            if (m_e.IsEmpty()) {
                throw MissingKeyError("local ephemeral (e) for ekem decapsulation");
            }

            // Decapsulate using local ephemeral private key
            auto shared_secret = m_dh.Decapsulate(m_e.private_key, ciphertext);
            const ScrubGuard secretGuard{shared_secret};

            // Then MixKey(k)
            m_ss.MixKey(shared_secret);

            return tail;
        }

        /**
         * Token 'skem' (write): Encapsulate to remote static, send encrypted ciphertext.
         *
         * Per PQNoise paper: EncryptAndHash(ct) is called BEFORE MixKeyAndHash(shared_secret).
         * This means the KEM ciphertext is encrypted under the current symmetric state,
         * and the shared secret is then bound into both the chaining key and hash via
         * MixKeyAndHash, providing stronger transcript binding than ekem.
         */
        void onWriteTokenSKEM(std::vector<std::uint8_t>& dst) {
            if (!m_dh.IsKEM()) {
                throw NoiseError("skem token requires KEM algorithm");
            }
            if (m_rs.empty()) {
                throw MissingKeyError("remote static (rs) for skem");
            }

            // Encapsulate to peer's static public key, decoded when s was read (or now, for a
            // pre-message static from the config)
            auto [ciphertext, shared_secret] = m_dh.Encapsulate(RsKem());
            const ScrubGuard secretGuard{shared_secret};

            // Per PQNoise: EncryptAndHash(ct) BEFORE MixKeyAndHash(k)
            // The reader will decrypt with current state, then MixKeyAndHash
            m_ss.EncryptAndHash(dst, ciphertext);

            // MixKeyAndHash binds the shared secret into both ck and h
            m_ss.MixKeyAndHash(shared_secret);
        }

        /** Token 'skem' (read): Receive encrypted ciphertext, decrypt, decapsulate with local static. */
        std::span<const std::uint8_t> onReadTokenSKEM(std::span<const std::uint8_t> payload) {
            if (!m_dh.IsKEM()) {
                throw NoiseError("skem token requires KEM algorithm");
            }

            // Calculate length: ciphertext + possible AEAD overhead
            auto ctLen = m_dh.CiphertextSize();
            if (m_ss.cs.HasKey()) {
                ctLen += m_ss.cs.aeadOverhead;
            }

            if (payload.size() < ctLen) {
                throw TruncatedMessageError("skem");
            }

            const auto temp = payload.subspan(0, ctLen);
            const auto tail = payload.subspan(ctLen);

            // Decrypt the ciphertext if needed
            std::vector<std::uint8_t> ciphertext;
            m_ss.DecryptAndHash(ciphertext, temp);

            if (m_s.IsEmpty()) {
                throw MissingKeyError("local static (s) for skem decapsulation");
            }

            // Decapsulate using local static private key
            auto shared_secret = m_dh.Decapsulate(m_s.private_key, ciphertext);
            const ScrubGuard secretGuard{shared_secret};

            // Per PQNoise: MixKeyAndHash binds the shared secret into both ck and h
            m_ss.MixKeyAndHash(shared_secret);

            return tail;
        }

        /// @}

        /// @name HFS (Hybrid Forward Secrecy) Token Handlers (Noise Protocol HFS spec extension)
        /// Implements defense-in-depth hybrid key exchange by combining classical DH
        /// with a secondary KEM. The e1/ekem1 tokens operate on a separate KEM algorithm
        /// (protocol.kem) from the primary DH algorithm.
        /// - e1: Generate KEM keypair, send public key (encrypted if key available)
        /// - ekem1: Encapsulate to peer's e1, MixKey(kem_output)
        /// @{

        /**
         * Token 'e1' (write): Generate KEM ephemeral keypair, send public key.
         *
         * Per the Noise Protocol HFS spec extension: the KEM public key is "transferred
         * as if it was a static DH public key" — i.e., via EncryptAndHash (encrypted if a
         * symmetric key has been established).
         */
        void onWriteTokenE1(std::vector<std::uint8_t>& dst) {
            if (!m_cfg.protocol.IsHFS()) {
                throw NoiseError("e1 token requires HFS protocol with KEM algorithm");
            }

            const auto& kem = *m_cfg.protocol.kem;

            // Generate KEM ephemeral keypair
            m_e1 = kem.GenerateKeypair();

            // Per spec: "transferred as if it was a static DH public key
            // (i.e. using EncryptAndHash() if a key is available)"
            m_ss.EncryptAndHash(dst, m_e1.public_key);
        }

        /** Token 'e1' (read): Receive and decrypt KEM ephemeral public key from peer. */
        std::span<const std::uint8_t> onReadTokenE1(std::span<const std::uint8_t> payload) {
            if (!m_cfg.protocol.IsHFS()) {
                throw NoiseError("e1 token requires HFS protocol with KEM algorithm");
            }

            const auto& kem = *m_cfg.protocol.kem;

            // Calculate expected length (public key + possible AEAD overhead)
            auto pubKeyLen = kem.PublicKeySize();
            if (m_ss.cs.HasKey()) {
                pubKeyLen += m_ss.cs.aeadOverhead;
            }

            if (payload.size() < pubKeyLen) {
                throw TruncatedMessageError("e1");
            }

            const auto temp = payload.subspan(0, pubKeyLen);
            const auto tail = payload.subspan(pubKeyLen);

            // Decrypt if needed
            std::vector<std::uint8_t> pubKey;
            m_ss.DecryptAndHash(pubKey, temp);

            // Check the KEM key on receipt (FIPS 203 Section 7.2), before storing it, and keep
            // the decoded key for ekem1
            m_re1Kem.emplace(kem.LoadPublicKey(pubKey));

            // Store remote KEM ephemeral public key
            m_re1 = std::move(pubKey);

            // Call observer if present
            if (m_cfg.observer) {
                if (auto err = m_cfg.observer->OnPeerPublicKey(Token::Token_e1, m_re1)) {
                    throw NoiseError(*err);
                }
            }

            return tail;
        }

        /** Token 'ekem1' (write): Encapsulate to peer's e1 public key, send ciphertext, MixKey(kem_output). */
        void onWriteTokenEKEM1(std::vector<std::uint8_t>& dst) {
            if (!m_cfg.protocol.IsHFS()) {
                throw NoiseError("ekem1 token requires HFS protocol with KEM algorithm");
            }
            if (m_re1.empty()) {
                throw MissingKeyError("remote KEM ephemeral (re1) for ekem1");
            }

            const auto& kem = *m_cfg.protocol.kem;

            // Encapsulate to peer's KEM ephemeral public key, decoded when e1 was read
            auto [ciphertext, kem_output] = kem.Encapsulate(Re1Kem());
            const ScrubGuard secretGuard{kem_output};

            // Per spec: "transferred as if it was a static DH public key
            // (i.e. using EncryptAndHash() if a key is available)"
            m_ss.EncryptAndHash(dst, ciphertext);

            // Mix the KEM output into the chaining key
            // Per spec: "the parties call MixKey(kem_output)"
            m_ss.MixKey(kem_output);
        }

        /** Token 'ekem1' (read): Receive ciphertext, decrypt if needed, decapsulate with local e1. */
        std::span<const std::uint8_t> onReadTokenEKEM1(std::span<const std::uint8_t> payload) {
            if (!m_cfg.protocol.IsHFS()) {
                throw NoiseError("ekem1 token requires HFS protocol with KEM algorithm");
            }
            if (m_e1.IsEmpty()) {
                throw MissingKeyError("local KEM ephemeral (e1) for ekem1 decapsulation");
            }

            const auto& kem = *m_cfg.protocol.kem;

            // Calculate expected length (ciphertext + possible AEAD overhead)
            auto ctLen = kem.CiphertextSize();
            if (m_ss.cs.HasKey()) {
                ctLen += m_ss.cs.aeadOverhead;
            }

            if (payload.size() < ctLen) {
                throw TruncatedMessageError("ekem1");
            }

            const auto temp = payload.subspan(0, ctLen);
            const auto tail = payload.subspan(ctLen);

            // Decrypt if needed
            std::vector<std::uint8_t> ciphertext;
            m_ss.DecryptAndHash(ciphertext, temp);

            // Decapsulate using local KEM ephemeral private key
            auto kem_output = kem.Decapsulate(m_e1.private_key, ciphertext);
            const ScrubGuard secretGuard{kem_output};

            // Mix the KEM output into the chaining key
            m_ss.MixKey(kem_output);

            return tail;
        }

        /// @}

        /**
         * Advances the pattern index and completes the handshake if all messages are processed.
         *
         * On completion (Noise spec Section 5.3): calls Split() to derive transport
         * CipherStates (cs1, cs2), saves the handshake hash for channel binding,
         * scrubs sensitive key material, and marks the status Done (MarkDone()). Nothing is
         * thrown on the success path. For one-way patterns, cs2 is reset since only one
         * direction of transport is used.
         *
         * @return true if this call completed the handshake, false if messages remain.
         * @throws NoiseError (and stores it as the sticky failure) if deriving the transport
         *         states fails.
         */
        bool onDone() {
            m_patternIndex++;

            if (m_patternIndex < m_patterns.size()) {
                return false;
            }

            try {
                auto [cs1, cs2] = m_ss.Split();

                // For one-way patterns, clear cs2
                if (IsOneWayPattern()) {
                    cs2.Reset();
                }

                m_status.cipherStates.emplace(std::move(cs1), std::move(cs2));
                m_status.handshakeHash = m_ss.GetHandshakeHash();

                // Clean up sensitive data, then record completion
                Reset();
                MarkDone();
            } catch (...) {
                Fail(std::current_exception());
                throw;
            }
            return true;
        }

        /**
         * Records a failure: @c err holds the exception and @c state becomes Failed. Every
         * error path sets the status through here (or MarkDone()), so the two fields agree.
         */
        void Fail(std::exception_ptr e) noexcept {
            m_status.err = std::move(e);
            m_status.state = HandshakeStatus::State::Failed;
        }

        /**
         * Records completion: @c err holds a HandshakeComplete (the documented tri-state, one
         * make_exception_ptr, nothing thrown) and @c state becomes Done.
         */
        void MarkDone() {
            m_status.err = std::make_exception_ptr(HandshakeComplete());
            m_status.state = HandshakeStatus::State::Done;
        }

        /**
         * Processes pre-message public keys (Noise spec Section 5.3).
         *
         * Pre-messages are public keys known before the handshake begins (e.g., in
         * NK patterns where the responder's static key is known to the initiator).
         * Each pre-message key is mixed into the handshake hash via MixHash.
         *
         * Because patterns are always written from the initiator's perspective,
         * the responder must swap local/remote keys before processing.
         */
        void HandlePreMessages() {
            const auto& preInitiator = m_cfg.protocol.pattern.pre_initiator;
            const auto& preResponder = m_cfg.protocol.pattern.pre_responder;

            if (preInitiator.empty() && preResponder.empty()) {
                return;
            }

            // Gather public keys from initiator's point of view
            PublicKey s{}, e{}, rs{}, re{};
            rs = m_rs;
            re = m_re;
            if (!m_s.IsEmpty()) {
                s = m_s.public_key;
            }
            if (!m_e.IsEmpty()) {
                e = m_e.public_key;
            }

            // Patterns are written from the initiator's viewpoint, so the responder
            // must swap local/remote keys to process pre-messages correctly.
            if (!m_isInitiator) {
                std::swap(s, rs);
                std::swap(e, re);
            }

            // Process initiator pre-messages
            if (!preInitiator.empty()) {
                for (const auto token : preInitiator) {
                    switch (token) {
                    case Token::Token_e:
                        if (e.empty()) {
                            throw PreMessageError("initiator", "e");
                        }
                        m_ss.MixHash(e);
                        if (m_cfg.protocol.pattern.numPSKs > 0) {
                            m_ss.MixKey(e);
                        }
                        break;
                    case Token::Token_s:
                        if (s.empty()) {
                            throw PreMessageError("initiator", "s");
                        }
                        m_ss.MixHash(s);
                        break;
                    default:
                        throw InvalidTokenError("pre-message token: " + std::string(to_string(token)));
                    }
                }
            }

            // Process responder pre-messages
            if (!preResponder.empty()) {
                for (const auto token : preResponder) {
                    switch (token) {
                    case Token::Token_e:
                        if (re.empty()) {
                            throw PreMessageError("responder", "e");
                        }
                        m_ss.MixHash(re);
                        if (m_cfg.protocol.pattern.numPSKs > 0) {
                            m_ss.MixKey(re);
                        }
                        break;
                    case Token::Token_s:
                        if (rs.empty()) {
                            throw PreMessageError("responder", "s");
                        }
                        m_ss.MixHash(rs);
                        break;
                    default:
                        throw InvalidTokenError("pre-message token: " + std::string(to_string(token)));
                    }
                }
            }
        }

        /** @return True if this is a one-way pattern (N, K, X, pqN and their psk variants): a single message. */
        [[nodiscard]] bool IsOneWayPattern() const {
            return m_patterns.size() == 1;
        }
    };
}
