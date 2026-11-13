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

export module noise:handshakestate.debug;

import :common;
import :dh;
import :symmetricstate.debug;
import :cipherstate.debug;
import :protocol;
import :pattern;
import :errors;

export namespace Noise
{
    // Forward declarations
    class HandshakeState;

    // HandshakeObserver interface for monitoring handshake status
    class HandshakeObserver {
    public:
        virtual ~HandshakeObserver() = default;

        // OnPeerPublicKey will be called when a public key is received from the peer
        // Returns an optional error to abort the handshake
        virtual std::optional<std::string> OnPeerPublicKey(Token token, const PublicKey& pubKey) = 0;
    };

    // HandshakeStatus represents the current state of the handshake
    class HandshakeStatus {
    public:
        // Progress of the handshake; kept in step with err
        enum class State : std::uint8_t { InProgress, Done, Failed };

        // Error status: nullptr if in progress, HandshakeComplete if complete, any other for failure
        std::exception_ptr err{nullptr};

        // InProgress until the final message is processed, then Done; Failed after any error
        State state{State::InProgress};

        // Public keys discovered during handshake
        PublicKey localEphemeral{};
        PublicKey remoteStatic{};
        PublicKey remoteEphemeral{};

        // Resulting cipher states after handshake completion (cs1, cs2)
        std::optional<std::pair<CipherState, CipherState>> cipherStates{};

        // Handshake hash - set once handshake is complete
        std::vector<std::uint8_t> handshakeHash{};

        // Never throws: reads state instead of rethrowing err
        [[nodiscard]] bool IsComplete() const noexcept {
            return state == State::Done;
        }

        // Never throws: reads state instead of rethrowing err
        [[nodiscard]] bool HasError() const noexcept {
            return state == State::Failed;
        }
    };

    // HandshakeConfig is the configuration for a handshake
    class HandshakeConfig {
    public:
        const Protocol& protocol;
        bool isInitiator = false;
        std::vector<std::uint8_t> prologue = {};
        KeyPair localStatic = {};
        KeyPair localEphemeral = {};
        PublicKey remoteStatic = {};
        PublicKey remoteEphemeral = {};
        std::vector<std::array<std::uint8_t, SYMMETRIC_KEY_SIZE>> preSharedKeys = {};
        HandshakeObserver* observer = nullptr;
        int maxMessageSize = 0; // 0 uses NOISE_MAX_MESSAGE_SIZE, negative disables check

        [[nodiscard]] int GetMaxMessageSize() const {
            if (maxMessageSize > 0) return maxMessageSize;
            if (maxMessageSize == 0) return NOISE_MAX_MESSAGE_SIZE;
            return 0; // negative means no limit
        }
    };

    // HandshakeState is the per-handshake state
    class HandshakeState {
    public:
        // Constructor - equivalent to NewHandshake in Go
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

        // A temporary config would dangle: the state keeps a reference to it
        explicit HandshakeState(HandshakeConfig&&) = delete;

        // Delete copy and move constructors/assignments
        HandshakeState(const HandshakeState&) = delete;
        HandshakeState(HandshakeState&&) = delete;
        HandshakeState& operator=(const HandshakeState&) = delete;
        HandshakeState& operator=(HandshakeState&&) = delete;

        // Destructor
        ~HandshakeState() {
            Reset();
        }

        // GetStatus returns the current handshake status
        [[nodiscard]] const HandshakeStatus& GetStatus() const {
            return m_status;
        }

        // Move the transport CipherStates out of the status; GetStatus().cipherStates is empty afterwards
        [[nodiscard]] std::optional<std::pair<CipherState, CipherState>> TakeCipherStates() noexcept {
            return std::exchange(m_status.cipherStates, std::nullopt);
        }

        // SymmetricState returns the encapsulated SymmetricState
        [[nodiscard]] const SymmetricState& GetSymmetricState() const {
            return m_ss;
        }

        [[nodiscard]] const HandshakeConfig& GetConfig() const {
            return m_cfg;
        }

        [[nodiscard]] bool IsInitiator() const {
            return m_isInitiator;
        }

        // Reset scrubs the library's own copies of secret material: the chaining key (then
        // cleared), the handshake hash (cleared), the embedded CipherState's key, and all three
        // local keypairs (m_e, m_s, HFS m_e1), generated here or copied from the config. The
        // caller's HandshakeConfig is never read or modified here. Idempotent (completion + destructor).
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

        // WriteMessage processes a write step of the handshake protocol
        // Returns the handshake message (may throw on error)
        std::vector<std::uint8_t> WriteMessage(const std::span<const std::uint8_t> payload) {
            LogFunction(Color::BrightGreen, "WriteMessage",
                std::format("ENTER (pattern index: {}, payload size: {} bytes)", m_patternIndex, payload.size()));

            // Check if we have an error
            if (m_status.err) [[unlikely]] {
                Log(Color::Red, "WriteMessage: ERROR - existing error state");
                std::rethrow_exception(m_status.err);
            }

            // Check if it's our turn to write: the initiator writes the even-indexed messages
            const bool ourTurn = m_isInitiator == ((m_patternIndex & 1) == 0);
            if (!ourTurn) [[unlikely]] {
                Log(Color::Red, "WriteMessage: ERROR - out of order (not our turn to write)");
                Fail(std::make_exception_ptr(OutOfOrderError()));
                std::rethrow_exception(m_status.err);
            }

            std::vector<std::uint8_t> dst{};
            dst.reserve(EstimateWriteMessageSize(payload.size()));
            const std::size_t baseLen = dst.size();

            LogFunction(Color::Green, "WriteMessage",
                std::format("Processing {} tokens from pattern", m_patterns[m_patternIndex].tokens.size()));

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
                    Log(Color::Red, std::format("WriteMessage: ERROR processing token {}", to_string(token)));
                    Fail(std::current_exception());
                    throw;
                }

                if (m_status.err) {
                    std::rethrow_exception(m_status.err);
                }
            }

            // Encrypt and hash the payload - now appends directly to dst
            LogFunction(Color::Green, "WriteMessage",
                std::format("Encrypting payload ({} bytes)", payload.size()));
            try {
                m_ss.EncryptAndHash(dst, payload);
            } catch (...) {
                Log(Color::Red, "WriteMessage: ERROR - payload encryption failed");
                Fail(std::current_exception());
                throw;
            }
            LogFunction(Color::Green, "WriteMessage",
                std::format("Total message size after encryption: {} bytes", dst.size()));

            // Check message size
            if (m_maxMessageSize > 0 && dst.size() - baseLen > static_cast<std::size_t>(m_maxMessageSize)) {
                Log(Color::Red, std::format("WriteMessage: ERROR - message too large ({} > {})",
                    dst.size() - baseLen, m_maxMessageSize));
                Fail(std::make_exception_ptr(MessageSizeError()));
                std::rethrow_exception(m_status.err);
            }

            LogFunction(Color::BrightGreen, "WriteMessage",
                std::format("Total message size: {} bytes", dst.size()));

            // Advance; on the final message this derives the transport states and marks Done
            if (onDone()) {
                LogFunction(Color::BrightGreen, "WriteMessage", "EXIT (handshake complete)");
            }
            return dst;
        }

        // ReadMessage processes a read step of the handshake protocol
        // Returns the decrypted payload (may throw on error)
        std::vector<std::uint8_t> ReadMessage(std::span<const std::uint8_t> message) {
            LogFunction(Color::ExtraBrightBlue, "ReadMessage",
                std::format("ENTER (pattern index: {}, message size: {} bytes)", m_patternIndex, message.size()));

            // Check if we have an error
            if (m_status.err) [[unlikely]] {
                Log(Color::Red, "ReadMessage: ERROR - existing error state");
                std::rethrow_exception(m_status.err);
            }

            // Check message size
            if (m_maxMessageSize > 0 && message.size() > static_cast<std::size_t>(m_maxMessageSize)) [[unlikely]] {
                Log(Color::Red, std::format("ReadMessage: ERROR - message too large ({} > {})",
                    message.size(), m_maxMessageSize));
                Fail(std::make_exception_ptr(MessageSizeError()));
                std::rethrow_exception(m_status.err);
            }

            // Check if it's our turn to read: the initiator reads the odd-indexed messages
            const bool theirTurn = m_isInitiator == ((m_patternIndex & 1) != 0);
            if (!theirTurn) [[unlikely]] {
                Log(Color::Red, "ReadMessage: ERROR - out of order (not our turn to read)");
                Fail(std::make_exception_ptr(OutOfOrderError()));
                std::rethrow_exception(m_status.err);
            }

            LogFunction(Color::Blue, "ReadMessage",
                std::format("Processing {} tokens from pattern", m_patterns[m_patternIndex].tokens.size()));

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
                    Log(Color::Red, std::format("ReadMessage: ERROR processing token {}", to_string(token)));
                    Fail(std::current_exception());
                    throw;
                }

                if (m_status.err) {
                    std::rethrow_exception(m_status.err);
                }
            }

            // Decrypt and hash the payload - now uses dst accumulation
            LogFunction(Color::Blue, "ReadMessage",
                std::format("Decrypting payload ({} bytes remaining)", message.size()));
            std::vector<std::uint8_t> dst;  // Empty dst like Go passes
            try {
                m_ss.DecryptAndHash(dst, message);  // Now modifies dst in place
                LogFunction(Color::Blue, "ReadMessage",
                    std::format("Decrypted payload size: {} bytes", dst.size()));
            } catch (...) {
                Log(Color::Red, "ReadMessage: ERROR - decryption failed");
                Fail(std::current_exception());
                throw;
            }

            // Advance; on the final message this derives the transport states and marks Done
            if (onDone()) {
                LogFunction(Color::ExtraBrightBlue, "ReadMessage", "EXIT (handshake complete)");
            } else {
                LogFunction(Color::ExtraBrightBlue, "ReadMessage", "EXIT");
            }
            return dst;
        }

    private:
        const HandshakeConfig& m_cfg;
        const Dh& m_dh;
        const std::vector<MessagePattern>& m_patterns;   // the Protocol's messages; the config, and the Protocol it refers to, outlive the state
        SymmetricState m_ss;
        KeyPair m_s;
        KeyPair m_e;
        std::optional<DhPrivateKey> m_eKey;   // Loaded e (DH only): generated with m_e, or loaded from it on first use
        std::optional<DhPrivateKey> m_sKey;   // Loaded s (DH only): loaded from m_s at the first static DH token
        PublicKey m_rs;
        PublicKey m_re;
        std::optional<KemPublicKey> m_rsKem;   // Decoded rs (KEM only): loaded when s was read, or from m_rs at the first skem (config static)
        std::optional<KemPublicKey> m_reKem;   // Decoded re (KEM only): loaded when e was read, or from m_re at the first ekem
        HandshakeStatus m_status;
        std::uint32_t m_patternIndex;
        std::uint32_t m_pskIndex;
        int m_maxMessageSize;
        std::uint8_t m_dhLen;
        bool m_isInitiator;

        // HFS (Hybrid Forward Secrecy) state
        KeyPair m_e1;          // Local KEM ephemeral keypair
        PublicKey m_re1;       // Remote KEM ephemeral public key
        std::optional<KemPublicKey> m_re1Kem;  // Decoded re1: loaded when e1 was read, or from m_re1 at ekem1

        // Scrubs a shared secret when its scope ends (also during unwinding). Declared right
        // after the vector holds its final value, so the span cannot dangle.
        class ScrubGuard {
        public:
            explicit ScrubGuard(std::vector<std::uint8_t>& secret) : m_bytes{secret} {}
            ~ScrubGuard() { Botan::secure_scrub_memory(m_bytes); }
            ScrubGuard(const ScrubGuard&) = delete;
            ScrubGuard& operator=(const ScrubGuard&) = delete;

        private:
            std::span<std::uint8_t> m_bytes;
        };

        // Scrubs a keypair's private key, then empties both keys
        static void ScrubKeyPair(KeyPair& keypair) {
            Botan::secure_scrub_memory(keypair.private_key);
            keypair = {};
        }

        // Logging helpers
        [[nodiscard]] std::string_view GetRoleColor() const {
            return m_isInitiator ? Color::BrightCyan : Color::BrightMagenta;
        }

        [[nodiscard]] std::string_view GetRoleName() const {
            return m_isInitiator ? "INITIATOR" : "RESPONDER";
        }

        void Log(std::string_view color, const std::string& message) const {
            if (!g_EnableHandshakeLogging) return;
            std::println("{}[{}] {}{}{}",
                GetRoleColor(), GetRoleName(), color, message, Color::Reset);
        }

        void LogFunction(std::string_view funcColor, const std::string& funcName, const std::string& message) const {
            if (!g_EnableHandshakeLogging) return;
            std::println("{}[{}] {}{}: {}{}{}",
                GetRoleColor(), GetRoleName(), funcColor, funcName, Color::White, message, Color::Reset);
        }

        void LogToken(Token token, const std::string& action) const {
            if (!g_EnableHandshakeLogging) return;
            std::println("{}[{}] {}  Token {}: {}{}{}",
                GetRoleColor(), GetRoleName(), Color::Yellow, to_string(token), Color::White, action, Color::Reset);
        }

        // Estimates the message size for the current pattern to pre-allocate buffer
        // This avoids vector reallocations during message construction
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

        // Token handlers

        // The loaded ephemeral key for the DH tokens: set by onWriteTokenE when the key is
        // generated here; a config-provided ephemeral is loaded (one multiplication) on first use
        // and cached, so every DH token costs one multiplication.
        [[nodiscard]] const DhPrivateKey& EKey() {
            if (!m_eKey) {
                Log(Color::Yellow, "  Loading the ephemeral key once for this handshake");
                m_eKey.emplace(m_dh.LoadPrivateKey(m_e.private_key));
            }
            return *m_eKey;
        }

        // The loaded static key for the DH tokens: loaded from m_s on first use and cached.
        // The decoded remote ML-KEM keys for ekem / skem / ekem1: loaded, and so checked,
        // when the key was read; a config-provided key is loaded on first use, so an invalid one
        // fails that WriteMessage with InvalidPublicKeyError as before.
        [[nodiscard]] const KemPublicKey& ReKem() {
            if (!m_reKem) {
                Log(Color::Magenta, "  Loading the config-provided remote ephemeral ML-KEM key (first use)");
                m_reKem.emplace(m_dh.LoadPublicKey(m_re));
            }
            return *m_reKem;
        }

        [[nodiscard]] const KemPublicKey& RsKem() {
            if (!m_rsKem) {
                Log(Color::Magenta, "  Loading the config-provided remote static ML-KEM key (first use)");
                m_rsKem.emplace(m_dh.LoadPublicKey(m_rs));
            }
            return *m_rsKem;
        }

        [[nodiscard]] const KemPublicKey& Re1Kem() {
            if (!m_re1Kem) {
                Log(Color::Cyan, "  Loading the remote HFS ephemeral ML-KEM key (first use)");
                m_re1Kem.emplace(m_cfg.protocol.kem->LoadPublicKey(m_re1));
            }
            return *m_re1Kem;
        }

        [[nodiscard]] const DhPrivateKey& SKey() {
            if (!m_sKey) {
                Log(Color::Yellow, "  Loading the static key once for this handshake");
                m_sKey.emplace(m_dh.LoadPrivateKey(m_s.private_key));
            }
            return *m_sKey;
        }

        void onWriteTokenE(std::vector<std::uint8_t>& dst) {
            LogToken(Token::Token_e, "Writing ephemeral key");

            // Generate ephemeral key if not pre-generated
            if (m_e.IsEmpty()) {
                if (m_dh.IsKEM()) {
                    Log(Color::Yellow, "  Generating new ephemeral keypair");
                    m_e = m_dh.GenerateKeypair();
                }
                else {
                    // The loaded key object comes with the keypair: one derivation
                    Log(Color::Yellow, "  Generating new ephemeral keypair with its loaded key");
                    auto [keypair, key] = m_dh.GenerateKeypairWithKey();
                    m_e = std::move(keypair);
                    m_eKey.emplace(std::move(key));
                }
            } else {
                Log(Color::Yellow, "  Using pre-generated ephemeral keypair");
            }

            const auto& eBytes = m_e.public_key;
            Log(Color::Yellow, std::format("  Ephemeral public key size: {} bytes", eBytes.size()));

            m_ss.MixHash(eBytes);
            Log(Color::Yellow, "  Mixed ephemeral key into handshake hash");

            if (m_cfg.protocol.pattern.numPSKs > 0) {
                m_ss.MixKey(eBytes);
                Log(Color::Yellow, "  Mixed ephemeral key into chaining key (PSK mode)");
            }
            m_status.localEphemeral = m_e.public_key;

            dst.insert(dst.end(), eBytes.begin(), eBytes.end());
            Log(Color::Yellow, std::format("  Appended {} bytes to message (total: {} bytes)", eBytes.size(), dst.size()));
        }

        std::span<const std::uint8_t> onReadTokenE(std::span<const std::uint8_t> payload) {
            LogToken(Token::Token_e, "Reading ephemeral key");

            // Use PublicKeySize() which handles both DH (32/56 bytes) and KEM (800/1184/1568 bytes)
            const auto pubKeyLen = m_dh.PublicKeySize();
            if (payload.size() < pubKeyLen) {
                Log(Color::Red, std::format("  ERROR: Message truncated (expected {} bytes, got {})", pubKeyLen, payload.size()));
                throw TruncatedMessageError("e");
            }

            const auto eBytes = payload.subspan(0, pubKeyLen);
            const auto tail = payload.subspan(pubKeyLen);

            Log(Color::Yellow, std::format("  Read {} bytes of ephemeral key", pubKeyLen));

            // An ML-KEM key is checked on receipt (FIPS 203 Section 7.2), before it is
            // stored, shown to the observer, or mixed in; a bad key fails this ReadMessage.
            // The decoded key is kept for the ekem token (one decode per received key)
            if (m_dh.IsKEM()) {
                m_reKem.emplace(m_dh.LoadPublicKey(eBytes));
                Log(Color::Yellow, "  Checked and decoded the remote ML-KEM ephemeral key");
            }

            m_re.assign(eBytes.begin(), eBytes.end());
            m_status.remoteEphemeral = m_re;   // one copy into each destination
            Log(Color::Yellow, "  Stored remote ephemeral key");

            // Call observer if present
            if (m_cfg.observer) {
                Log(Color::Yellow, "  Calling observer for peer public key");
                if (auto err = m_cfg.observer->OnPeerPublicKey(Token::Token_e, m_re)) {
                    Log(Color::Red, "  ERROR: Observer rejected peer public key");
                    throw NoiseError(*err);
                }
            }

            m_ss.MixHash(eBytes);
            Log(Color::Yellow, "  Mixed ephemeral key into handshake hash");

            if (m_cfg.protocol.pattern.numPSKs > 0) {
                m_ss.MixKey(eBytes);
                Log(Color::Yellow, "  Mixed ephemeral key into chaining key (PSK mode)");
            }

            Log(Color::Yellow, std::format("  {} bytes remaining in message", tail.size()));
            return tail;
        }

        void onWriteTokenS(std::vector<std::uint8_t>& dst) {
            LogToken(Token::Token_s, "Writing static key");

            if (m_s.IsEmpty()) {
                Log(Color::Red, "  ERROR: Local static key not available");
                throw MissingKeyError("s");
            }

            const auto& sBytes = m_s.public_key;
            Log(Color::Yellow, std::format("  Static public key size: {} bytes", sBytes.size()));
            Log(Color::Yellow, std::format("  dst size before encryption: {} bytes", dst.size()));

            // Appends the static key (encrypted once a key is set) directly to dst
            m_ss.EncryptAndHash(dst, sBytes);

            Log(Color::Yellow, std::format("  dst size after encryption: {} bytes", dst.size()));
        }

        std::span<const std::uint8_t> onReadTokenS(std::span<const std::uint8_t> payload) {
            LogToken(Token::Token_s, "Reading static key");

            // Use PublicKeySize() which handles both DH (32/56 bytes) and KEM (800/1184/1568 bytes)
            std::size_t tempLen = m_dh.PublicKeySize();
            if (m_ss.cs.HasKey()) {
                tempLen += m_ss.cs.aeadOverhead;
                Log(Color::Yellow, std::format("  Expected encrypted static key size: {} bytes (key: {}, overhead: {})",
                    tempLen, m_dh.PublicKeySize(), m_ss.cs.aeadOverhead));
            } else {
                Log(Color::Yellow, std::format("  Expected plaintext static key size: {} bytes", tempLen));
            }

            if (payload.size() < tempLen) {
                Log(Color::Red, std::format("  ERROR: Message truncated (expected {} bytes, got {})", tempLen, payload.size()));
                throw TruncatedMessageError("s");
            }

            const auto temp = payload.subspan(0, tempLen);
            const auto tail = payload.subspan(tempLen);

            Log(Color::Yellow, std::format("  Reading {} bytes of static key data", tempLen));

            std::vector<std::uint8_t> sBytes;
            m_ss.DecryptAndHash(sBytes, temp);
            Log(Color::Yellow, std::format("  Decrypted static key size: {} bytes", sBytes.size()));

            // A KEM static is encapsulated to later, like e: check it on receipt and keep the
            // decoded key for the skem token
            if (m_dh.IsKEM()) {
                m_rsKem.emplace(m_dh.LoadPublicKey(sBytes));
                Log(Color::Yellow, "  Checked and decoded the remote ML-KEM static key");
            }

            m_rs = std::move(sBytes);
            m_status.remoteStatic = m_rs;
            Log(Color::Yellow, "  Stored remote static key");

            // Call observer if present
            if (m_cfg.observer) {
                Log(Color::Yellow, "  Calling observer for peer public key");
                if (auto err = m_cfg.observer->OnPeerPublicKey(Token::Token_s, m_rs)) {
                    Log(Color::Red, "  ERROR: Observer rejected peer public key");
                    throw NoiseError(*err);
                }
            }

            Log(Color::Yellow, std::format("  {} bytes remaining in message", tail.size()));
            return tail;
        }

        void onTokenEE() {
            LogToken(Token::Token_ee, "Performing DH(e, re)");
            Log(Color::Yellow, "  Computing ephemeral-ephemeral DH");

            auto eeBytes = m_dh.DH(EKey(), m_re);
            const ScrubGuard eeGuard{eeBytes};
            Log(Color::Yellow, std::format("  DH result: {} bytes", eeBytes.size()));

            m_ss.MixKey(eeBytes);
            Log(Color::Yellow, "  Mixed DH result into chaining key");
        }

        void onTokenES() {
            LogToken(Token::Token_es, "Performing DH(e, rs) or DH(s, re)");

            auto esBytes = [this] {
                if (m_isInitiator) {
                    Log(Color::Yellow, "  Initiator: Computing DH(e, rs)");
                    return m_dh.DH(EKey(), m_rs);
                }
                Log(Color::Yellow, "  Responder: Computing DH(s, re)");
                return m_dh.DH(SKey(), m_re);
            }();
            const ScrubGuard esGuard{esBytes};
            Log(Color::Yellow, std::format("  DH result: {} bytes", esBytes.size()));

            m_ss.MixKey(esBytes);
            Log(Color::Yellow, "  Mixed DH result into chaining key");
        }

        void onTokenSE() {
            LogToken(Token::Token_se, "Performing DH(s, re) or DH(e, rs)");

            auto seBytes = [this] {
                if (m_isInitiator) {
                    Log(Color::Yellow, "  Initiator: Computing DH(s, re)");
                    return m_dh.DH(SKey(), m_re);
                }
                Log(Color::Yellow, "  Responder: Computing DH(e, rs)");
                return m_dh.DH(EKey(), m_rs);
            }();
            const ScrubGuard seGuard{seBytes};
            Log(Color::Yellow, std::format("  DH result: {} bytes", seBytes.size()));

            m_ss.MixKey(seBytes);
            Log(Color::Yellow, "  Mixed DH result into chaining key");
        }

        void onTokenSS() {
            LogToken(Token::Token_ss, "Performing DH(s, rs)");
            Log(Color::Yellow, "  Computing static-static DH");

            auto ssBytes = m_dh.DH(SKey(), m_rs);
            const ScrubGuard ssGuard{ssBytes};
            Log(Color::Yellow, std::format("  DH result: {} bytes", ssBytes.size()));

            m_ss.MixKey(ssBytes);
            Log(Color::Yellow, "  Mixed DH result into chaining key");
        }

        void onTokenPsk() {
            LogToken(Token::Token_psk, std::format("Mixing PSK #{}", m_pskIndex));

            Log(Color::Yellow, std::format("  PSK size: {} bytes", m_cfg.preSharedKeys[m_pskIndex].size()));
            m_ss.MixKeyAndHash(m_cfg.preSharedKeys[m_pskIndex]);
            Log(Color::Yellow, "  Mixed PSK into chaining key and handshake hash");

            m_pskIndex++;
        }

        // ==========================================
        // PQNoise KEM Token Handlers
        // ==========================================
        // Per PQNoise paper semantics:
        // - ekem: Encapsulate TO peer's ephemeral (m_re)
        // - skem: Encapsulate TO peer's static (m_rs)

        // ekem (write): Encapsulate TO remote ephemeral, send ciphertext
        void onWriteTokenEKEM(std::vector<std::uint8_t>& dst) {
            LogToken(Token::Token_ekem, "Encapsulating to remote ephemeral");

            if (!m_dh.IsKEM()) {
                Log(Color::Red, "  ERROR: ekem token requires KEM algorithm");
                throw NoiseError("ekem token requires KEM algorithm");
            }
            if (m_re.empty()) {
                Log(Color::Red, "  ERROR: remote ephemeral key not available");
                throw MissingKeyError("remote ephemeral (re) for ekem");
            }

            Log(Color::Magenta, std::format("  Remote ephemeral key size: {} bytes", m_re.size()));

            // Encapsulate to peer's ephemeral public key, decoded when e was read
            auto [ciphertext, shared_secret] = m_dh.Encapsulate(ReKem());
            const ScrubGuard secretGuard{shared_secret};
            Log(Color::Magenta, std::format("  Generated ciphertext: {} bytes", ciphertext.size()));
            Log(Color::Magenta, std::format("  Shared secret: {} bytes", shared_secret.size()));

            // Per PQNoise: MixHash(ct) then MixKey(k)
            m_ss.MixHash(ciphertext);
            Log(Color::Magenta, "  Mixed ciphertext into handshake hash");
            m_ss.MixKey(shared_secret);
            Log(Color::Magenta, "  Mixed shared secret into chaining key");

            // Output the ciphertext (unencrypted - ekem is always in the clear)
            dst.insert(dst.end(), ciphertext.begin(), ciphertext.end());
            Log(Color::Magenta, std::format("  Appended unencrypted ciphertext to message (total: {} bytes)", dst.size()));
        }

        // ekem (read): Receive ciphertext, decapsulate using local ephemeral
        std::span<const std::uint8_t> onReadTokenEKEM(std::span<const std::uint8_t> payload) {
            LogToken(Token::Token_ekem, "Decapsulating with local ephemeral");

            if (!m_dh.IsKEM()) {
                Log(Color::Red, "  ERROR: ekem token requires KEM algorithm");
                throw NoiseError("ekem token requires KEM algorithm");
            }

            const auto ctLen = m_dh.CiphertextSize();
            Log(Color::Magenta, std::format("  Expected ciphertext size: {} bytes", ctLen));

            if (payload.size() < ctLen) {
                Log(Color::Red, std::format("  ERROR: payload too short ({} < {})", payload.size(), ctLen));
                throw TruncatedMessageError("ekem");
            }

            const auto ciphertext = payload.subspan(0, ctLen);
            const auto tail = payload.subspan(ctLen);

            if (m_e.IsEmpty()) {
                Log(Color::Red, "  ERROR: local ephemeral key not available");
                throw MissingKeyError("local ephemeral (e) for ekem decapsulation");
            }

            Log(Color::Magenta, std::format("  Received ciphertext: {} bytes", ciphertext.size()));

            // Per PQNoise: MixHash(ct) first
            m_ss.MixHash(ciphertext);
            Log(Color::Magenta, "  Mixed ciphertext into handshake hash");

            // Decapsulate using local ephemeral private key
            auto shared_secret = m_dh.Decapsulate(m_e.private_key, ciphertext);
            const ScrubGuard secretGuard{shared_secret};
            Log(Color::Magenta, std::format("  Decapsulated shared secret: {} bytes", shared_secret.size()));

            // Then MixKey(k)
            m_ss.MixKey(shared_secret);
            Log(Color::Magenta, "  Mixed shared secret into chaining key");

            Log(Color::Magenta, std::format("  {} bytes remaining in message", tail.size()));
            return tail;
        }

        // skem (write): Encapsulate TO remote static, send (possibly encrypted) ciphertext
        void onWriteTokenSKEM(std::vector<std::uint8_t>& dst) {
            LogToken(Token::Token_skem, "Encapsulating to remote static");

            if (!m_dh.IsKEM()) {
                Log(Color::Red, "  ERROR: skem token requires KEM algorithm");
                throw NoiseError("skem token requires KEM algorithm");
            }
            if (m_rs.empty()) {
                Log(Color::Red, "  ERROR: remote static key not available");
                throw MissingKeyError("remote static (rs) for skem");
            }

            Log(Color::Magenta, std::format("  Remote static key size: {} bytes", m_rs.size()));

            // Encapsulate to peer's static public key, decoded when s was read (or now, for a
            // pre-message static from the config)
            auto [ciphertext, shared_secret] = m_dh.Encapsulate(RsKem());
            const ScrubGuard secretGuard{shared_secret};
            Log(Color::Magenta, std::format("  Generated ciphertext: {} bytes", ciphertext.size()));
            Log(Color::Magenta, std::format("  Shared secret: {} bytes", shared_secret.size()));

            // Per PQNoise: EncryptAndHash(ct) BEFORE MixKeyAndHash(k)
            // The reader will decrypt with current state, then MixKeyAndHash
            m_ss.EncryptAndHash(dst, ciphertext);
            Log(Color::Magenta, std::format("  Encrypted and appended ciphertext (total: {} bytes)", dst.size()));

            // MixKeyAndHash binds the shared secret into both ck and h
            m_ss.MixKeyAndHash(shared_secret);
            Log(Color::Magenta, "  Mixed shared secret into chaining key and handshake hash");
        }

        // skem (read): Receive (possibly encrypted) ciphertext, decapsulate using local static
        std::span<const std::uint8_t> onReadTokenSKEM(std::span<const std::uint8_t> payload) {
            LogToken(Token::Token_skem, "Decapsulating with local static");

            if (!m_dh.IsKEM()) {
                Log(Color::Red, "  ERROR: skem token requires KEM algorithm");
                throw NoiseError("skem token requires KEM algorithm");
            }

            // Calculate length: ciphertext + possible AEAD overhead
            auto ctLen = m_dh.CiphertextSize();
            if (m_ss.cs.HasKey()) {
                ctLen += m_ss.cs.aeadOverhead;
                Log(Color::Magenta, std::format("  Expected encrypted ciphertext size: {} bytes (ct {} + overhead {})",
                    ctLen, m_dh.CiphertextSize(), m_ss.cs.aeadOverhead));
            } else {
                Log(Color::Magenta, std::format("  Expected ciphertext size: {} bytes (unencrypted)", ctLen));
            }

            if (payload.size() < ctLen) {
                Log(Color::Red, std::format("  ERROR: payload too short ({} < {})", payload.size(), ctLen));
                throw TruncatedMessageError("skem");
            }

            const auto temp = payload.subspan(0, ctLen);
            const auto tail = payload.subspan(ctLen);

            // Decrypt the ciphertext if needed
            std::vector<std::uint8_t> ciphertext;
            m_ss.DecryptAndHash(ciphertext, temp);
            Log(Color::Magenta, std::format("  Decrypted ciphertext: {} bytes", ciphertext.size()));

            if (m_s.IsEmpty()) {
                Log(Color::Red, "  ERROR: local static key not available");
                throw MissingKeyError("local static (s) for skem decapsulation");
            }

            // Decapsulate using local static private key
            auto shared_secret = m_dh.Decapsulate(m_s.private_key, ciphertext);
            const ScrubGuard secretGuard{shared_secret};
            Log(Color::Magenta, std::format("  Decapsulated shared secret: {} bytes", shared_secret.size()));

            // Per PQNoise: MixKeyAndHash binds the shared secret into both ck and h
            m_ss.MixKeyAndHash(shared_secret);
            Log(Color::Magenta, "  Mixed shared secret into chaining key and handshake hash");

            Log(Color::Magenta, std::format("  {} bytes remaining in message", tail.size()));
            return tail;
        }

        // ==========================================
        // HFS (Hybrid Forward Secrecy) Token Handlers
        // ==========================================
        // Per the Noise Protocol HFS spec extension:
        // - e1: Generate KEM keypair, send public key (encrypted if key available)
        // - ekem1: Encapsulate to peer's e1, send ciphertext (encrypted if key available), MixKey(kem_output)

        // e1 (write): Generate KEM ephemeral keypair, send public key
        // This provides the KEM component of Hybrid Forward Secrecy
        void onWriteTokenE1(std::vector<std::uint8_t>& dst) {
            LogToken(Token::Token_e1, "Generating HFS KEM ephemeral keypair");

            if (!m_cfg.protocol.IsHFS()) {
                Log(Color::Red, "  ERROR: e1 token requires HFS protocol (pattern must use 'hfs' modifier)");
                throw NoiseError("e1 token requires HFS protocol with KEM algorithm");
            }

            const auto& kem = *m_cfg.protocol.kem;
            Log(Color::Cyan, std::format("  HFS KEM algorithm: {} (provides post-quantum security layer)", kem.String()));

            // Generate KEM ephemeral keypair for hybrid forward secrecy
            m_e1 = kem.GenerateKeypair();
            Log(Color::Cyan, std::format("  Generated HFS ephemeral keypair (public key: {} bytes, private key: {} bytes)",
                m_e1.public_key.size(), m_e1.private_key.size()));

            // Per the Noise Protocol HFS spec extension: "transferred as if it was a static DH public key
            // (i.e. using EncryptAndHash() if a key is available)"
            const bool encrypted = m_ss.cs.HasKey();
            Log(Color::Cyan, std::format("  Transmitting e1 public key ({}, dst before: {} bytes)",
                encrypted ? "encrypted" : "plaintext", dst.size()));
            m_ss.EncryptAndHash(dst, m_e1.public_key);
            Log(Color::Cyan, std::format("  e1 public key transmitted (dst after: {} bytes, added: {} bytes)",
                dst.size(), encrypted ? m_e1.public_key.size() + m_ss.cs.aeadOverhead : m_e1.public_key.size()));
        }

        // e1 (read): Receive peer's HFS KEM ephemeral public key (decrypt if encrypted)
        // Will be used later by ekem1 for KEM encapsulation
        std::span<const std::uint8_t> onReadTokenE1(std::span<const std::uint8_t> payload) {
            LogToken(Token::Token_e1, "Receiving peer's HFS KEM ephemeral public key");

            if (!m_cfg.protocol.IsHFS()) {
                Log(Color::Red, "  ERROR: e1 token requires HFS protocol (pattern must use 'hfs' modifier)");
                throw NoiseError("e1 token requires HFS protocol with KEM algorithm");
            }

            const auto& kem = *m_cfg.protocol.kem;
            Log(Color::Cyan, std::format("  HFS KEM algorithm: {}", kem.String()));

            // Calculate expected length (public key + possible AEAD overhead)
            const bool encrypted = m_ss.cs.HasKey();
            auto pubKeyLen = kem.PublicKeySize();
            if (encrypted) {
                pubKeyLen += m_ss.cs.aeadOverhead;
                Log(Color::Cyan, std::format("  Expecting encrypted e1 public key: {} bytes (key: {} + overhead: {})",
                    pubKeyLen, kem.PublicKeySize(), m_ss.cs.aeadOverhead));
            } else {
                Log(Color::Cyan, std::format("  Expecting plaintext e1 public key: {} bytes", pubKeyLen));
            }

            if (payload.size() < pubKeyLen) {
                Log(Color::Red, std::format("  ERROR: Payload truncated (need {} bytes, have {})", pubKeyLen, payload.size()));
                throw TruncatedMessageError("e1");
            }

            const auto temp = payload.subspan(0, pubKeyLen);
            const auto tail = payload.subspan(pubKeyLen);

            // Decrypt and hash (decrypts if we have a key, otherwise just hashes)
            std::vector<std::uint8_t> pubKey;
            m_ss.DecryptAndHash(pubKey, temp);
            Log(Color::Cyan, std::format("  Received peer's e1 public key: {} bytes ({})",
                pubKey.size(), encrypted ? "decrypted" : "plaintext"));

            // Check the KEM key on receipt (FIPS 203 Section 7.2), before storing it, and keep
            // the decoded key for ekem1
            m_re1Kem.emplace(kem.LoadPublicKey(pubKey));

            // Store remote KEM ephemeral public key for later use in ekem1
            m_re1 = std::move(pubKey);
            Log(Color::Cyan, "  Stored peer's HFS ephemeral key as re1 (for ekem1 encapsulation)");

            // Call observer if present
            if (m_cfg.observer) {
                Log(Color::Cyan, "  Notifying observer of peer's HFS KEM public key");
                if (auto err = m_cfg.observer->OnPeerPublicKey(Token::Token_e1, m_re1)) {
                    Log(Color::Red, "  ERROR: Observer rejected peer's HFS KEM public key");
                    throw NoiseError(*err);
                }
            }

            Log(Color::Cyan, std::format("  Payload remaining: {} bytes", tail.size()));
            return tail;
        }

        // ekem1 (write): Encapsulate to peer's e1, send ciphertext, mix shared secret
        // This completes the HFS KEM exchange - peer will decapsulate to derive same shared secret
        void onWriteTokenEKEM1(std::vector<std::uint8_t>& dst) {
            LogToken(Token::Token_ekem1, "Performing HFS KEM encapsulation to peer's e1");

            if (!m_cfg.protocol.IsHFS()) {
                Log(Color::Red, "  ERROR: ekem1 token requires HFS protocol (pattern must use 'hfs' modifier)");
                throw NoiseError("ekem1 token requires HFS protocol with KEM algorithm");
            }
            if (m_re1.empty()) {
                Log(Color::Red, "  ERROR: Peer's HFS ephemeral key (re1) not received - e1 token must precede ekem1");
                throw MissingKeyError("remote KEM ephemeral (re1) for ekem1");
            }

            const auto& kem = *m_cfg.protocol.kem;
            Log(Color::Cyan, std::format("  HFS KEM algorithm: {}", kem.String()));
            Log(Color::Cyan, std::format("  Encapsulating to peer's re1 ({} bytes)", m_re1.size()));

            // Encapsulate to peer's KEM ephemeral public key, decoded when e1 was read
            // This generates a ciphertext that only the peer can decapsulate, plus a shared secret
            auto [ciphertext, kem_output] = kem.Encapsulate(Re1Kem());
            const ScrubGuard secretGuard{kem_output};
            Log(Color::Cyan, std::format("  KEM encapsulation complete:"));
            Log(Color::Cyan, std::format("    Ciphertext: {} bytes (to transmit)", ciphertext.size()));
            Log(Color::Cyan, std::format("    Shared secret: {} bytes (for key derivation)", kem_output.size()));

            // Per the Noise Protocol HFS spec extension: "transferred as if it was a static DH public key"
            const bool encrypted = m_ss.cs.HasKey();
            Log(Color::Cyan, std::format("  Transmitting ciphertext ({}, dst before: {} bytes)",
                encrypted ? "encrypted" : "plaintext", dst.size()));
            m_ss.EncryptAndHash(dst, ciphertext);
            Log(Color::Cyan, std::format("  Ciphertext transmitted (dst after: {} bytes)", dst.size()));

            // Mix the KEM output into the chaining key
            // Per the Noise Protocol HFS spec extension: "the parties call MixKey(kem_output)"
            // This derives new encryption keys incorporating the post-quantum shared secret
            m_ss.MixKey(kem_output);
            Log(Color::Cyan, "  MixKey(kem_output) - HFS shared secret mixed into chaining key");
        }

        // ekem1 (read): Receive ciphertext, decapsulate using our e1 private key, mix shared secret
        // This completes the HFS KEM exchange - we derive the same shared secret as the peer
        std::span<const std::uint8_t> onReadTokenEKEM1(std::span<const std::uint8_t> payload) {
            LogToken(Token::Token_ekem1, "Performing HFS KEM decapsulation with local e1");

            if (!m_cfg.protocol.IsHFS()) {
                Log(Color::Red, "  ERROR: ekem1 token requires HFS protocol (pattern must use 'hfs' modifier)");
                throw NoiseError("ekem1 token requires HFS protocol with KEM algorithm");
            }
            if (m_e1.IsEmpty()) {
                Log(Color::Red, "  ERROR: Local HFS ephemeral key (e1) not generated - e1 token must precede ekem1");
                throw MissingKeyError("local KEM ephemeral (e1) for ekem1 decapsulation");
            }

            const auto& kem = *m_cfg.protocol.kem;
            Log(Color::Cyan, std::format("  HFS KEM algorithm: {}", kem.String()));

            // Calculate expected length (ciphertext + possible AEAD overhead)
            const bool encrypted = m_ss.cs.HasKey();
            auto ctLen = kem.CiphertextSize();
            if (encrypted) {
                ctLen += m_ss.cs.aeadOverhead;
                Log(Color::Cyan, std::format("  Expecting encrypted ciphertext: {} bytes (ct: {} + overhead: {})",
                    ctLen, kem.CiphertextSize(), m_ss.cs.aeadOverhead));
            } else {
                Log(Color::Cyan, std::format("  Expecting plaintext ciphertext: {} bytes", ctLen));
            }

            if (payload.size() < ctLen) {
                Log(Color::Red, std::format("  ERROR: Payload truncated (need {} bytes, have {})", ctLen, payload.size()));
                throw TruncatedMessageError("ekem1");
            }

            const auto temp = payload.subspan(0, ctLen);
            const auto tail = payload.subspan(ctLen);

            // Decrypt and hash (decrypts if we have a key, otherwise just hashes)
            std::vector<std::uint8_t> ciphertext;
            m_ss.DecryptAndHash(ciphertext, temp);
            Log(Color::Cyan, std::format("  Received ciphertext: {} bytes ({})",
                ciphertext.size(), encrypted ? "decrypted" : "plaintext"));

            // Decapsulate using our e1 private key to recover the shared secret
            // Only we can do this since we hold the e1 private key
            Log(Color::Cyan, std::format("  Decapsulating with local e1 private key ({} bytes)", m_e1.private_key.size()));
            auto kem_output = kem.Decapsulate(m_e1.private_key, ciphertext);
            const ScrubGuard secretGuard{kem_output};
            Log(Color::Cyan, std::format("  KEM decapsulation complete:"));
            Log(Color::Cyan, std::format("    Shared secret: {} bytes (matches peer's)", kem_output.size()));

            // Mix the KEM output into the chaining key
            // Per the Noise Protocol HFS spec extension: "the parties call MixKey(kem_output)"
            // This derives new encryption keys incorporating the post-quantum shared secret
            m_ss.MixKey(kem_output);
            Log(Color::Cyan, "  MixKey(kem_output) - HFS shared secret mixed into chaining key");

            Log(Color::Cyan, std::format("  Payload remaining: {} bytes", tail.size()));
            return tail;
        }

        // Advance the pattern index; on the final message derive the transport states, scrub,
        // and mark the status Done. Returns true if this call completed the handshake.
        bool onDone() {
            m_patternIndex++;
            Log(Color::BrightWhite, std::format("Pattern index incremented to {}", m_patternIndex));

            if (m_patternIndex < m_patterns.size()) {
                Log(Color::BrightWhite, std::format("More patterns remaining ({}/{})", m_patternIndex + 1, m_patterns.size()));
                return false;
            }

            // Handshake is complete
            Log(Color::BrightWhite, std::format("{}=== HANDSHAKE COMPLETE ===", Color::Bold));
            try {
                Log(Color::BrightWhite, "Splitting cipher states...");
                auto [cs1, cs2] = m_ss.Split();

                // For one-way patterns, clear cs2
                if (IsOneWayPattern()) {
                    Log(Color::BrightWhite, "One-way pattern detected, clearing second cipher state");
                    cs2.Reset();
                }

                m_status.cipherStates.emplace(std::move(cs1), std::move(cs2));
                Log(Color::BrightWhite, "Cipher states stored in status");

                m_status.handshakeHash = m_ss.GetHandshakeHash();
                Log(Color::BrightWhite, std::format("Handshake hash captured ({} bytes)", m_status.handshakeHash.size()));

                // Clean up sensitive data, then record completion
                Log(Color::BrightWhite, "Cleaning up sensitive handshake data");
                Reset();
                MarkDone();
            } catch (...) {
                Log(Color::Red, "onDone: ERROR - deriving the transport states failed");
                Fail(std::current_exception());
                throw;
            }
            return true;
        }

        // Record a failure: err holds the exception, state becomes Failed
        void Fail(std::exception_ptr e) noexcept {
            m_status.err = std::move(e);
            m_status.state = HandshakeStatus::State::Failed;
        }

        // Record completion: err holds a HandshakeComplete (tri-state kept, nothing thrown), state becomes Done
        void MarkDone() {
            m_status.err = std::make_exception_ptr(HandshakeComplete());
            m_status.state = HandshakeStatus::State::Done;
        }

        void HandlePreMessages() {
            const auto& preInitiator = m_cfg.protocol.pattern.pre_initiator;
            const auto& preResponder = m_cfg.protocol.pattern.pre_responder;

            if (preInitiator.empty() && preResponder.empty()) {
                Log(Color::White, "No pre-messages to process");
                return;
            }

            Log(Color::BrightWhite, "Processing pre-messages...");

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

            // Swap if we're the responder
            if (!m_isInitiator) {
                Log(Color::White, "  Swapping keys (responder view)");
                std::swap(s, rs);
                std::swap(e, re);
            }

            // Process initiator pre-messages
            if (!preInitiator.empty()) {
                Log(Color::White, std::format("  Processing {} initiator pre-message token(s)", preInitiator.size()));
                for (const auto token : preInitiator) {
                    switch (token) {
                    case Token::Token_e:
                        if (e.empty()) {
                            Log(Color::Red, "    ERROR: Initiator ephemeral key missing");
                            throw PreMessageError("initiator", "e");
                        }
                        Log(Color::White, "    Pre-message token 'e': mixing initiator ephemeral into hash");
                        m_ss.MixHash(e);
                        if (m_cfg.protocol.pattern.numPSKs > 0) {
                            m_ss.MixKey(e);
                            Log(Color::White, "    Also mixed into chaining key (PSK mode)");
                        }
                        break;
                    case Token::Token_s:
                        if (s.empty()) {
                            Log(Color::Red, "    ERROR: Initiator static key missing");
                            throw PreMessageError("initiator", "s");
                        }
                        Log(Color::White, "    Pre-message token 's': mixing initiator static into hash");
                        m_ss.MixHash(s);
                        break;
                    default:
                        throw InvalidTokenError("pre-message token: " + std::string(to_string(token)));
                    }
                }
            }

            // Process responder pre-messages
            if (!preResponder.empty()) {
                Log(Color::White, std::format("  Processing {} responder pre-message token(s)", preResponder.size()));
                for (const auto token : preResponder) {
                    switch (token) {
                    case Token::Token_e:
                        if (re.empty()) {
                            Log(Color::Red, "    ERROR: Responder ephemeral key missing");
                            throw PreMessageError("responder", "e");
                        }
                        Log(Color::White, "    Pre-message token 'e': mixing responder ephemeral into hash");
                        m_ss.MixHash(re);
                        if (m_cfg.protocol.pattern.numPSKs > 0) {
                            m_ss.MixKey(re);
                            Log(Color::White, "    Also mixed into chaining key (PSK mode)");
                        }
                        break;
                    case Token::Token_s:
                        if (rs.empty()) {
                            Log(Color::Red, "    ERROR: Responder static key missing");
                            throw PreMessageError("responder", "s");
                        }
                        Log(Color::White, "    Pre-message token 's': mixing responder static into hash");
                        m_ss.MixHash(rs);
                        break;
                    default:
                        throw InvalidTokenError("pre-message token: " + std::string(to_string(token)));
                    }
                }
            }
            Log(Color::BrightWhite, "Pre-message processing complete");
        }

        [[nodiscard]] bool IsOneWayPattern() const {
            // One-way patterns (N, K, X, pqN and their psk variants) have exactly one message
            return m_patterns.size() == 1;
        }
    };
}