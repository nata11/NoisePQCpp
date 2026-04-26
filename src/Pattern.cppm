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

export module noise:pattern;

import :common;
import :errors;

export namespace Noise
{
    /**
     * Handshake pattern tokens representing key exchange operations.
     *
     * Classical tokens (e, s, ee, es, se, ss) are defined by the Noise spec Section 7.
     * PQ tokens (ekem, skem) are defined by the PQNoise paper for post-quantum KEM.
     * HFS tokens (e1, ekem1) are defined by noise-kem-hfs.pdf for hybrid forward secrecy.
     */
    enum class Token : std::uint8_t {
        Token_invalid,  ///< Invalid/sentinel token.
        Token_e,        ///< Generate and send ephemeral public key (Noise spec Section 5.4).
        Token_s,        ///< Send static public key (encrypted if key established).
        Token_ee,       ///< DH(e, re) — ephemeral-ephemeral key agreement.
        Token_es,       ///< DH(e, rs) or DH(s, re) — ephemeral-static key agreement.
        Token_se,       ///< DH(s, re) or DH(e, rs) — static-ephemeral key agreement.
        Token_ss,       ///< DH(s, rs) — static-static key agreement.
        Token_ekem,     ///< PQNoise: KEM encapsulation to peer's ephemeral key (ML-KEM).
        Token_skem,     ///< PQNoise: KEM encapsulation to peer's static key (ML-KEM).
        Token_e1,       ///< HFS: Generate and send KEM ephemeral public key (noise-kem-hfs.pdf).
        Token_ekem1,    ///< HFS: KEM encapsulation to peer's e1 key (noise-kem-hfs.pdf).
        Token_psk       ///< Mix pre-shared symmetric key (Noise spec Section 9).
    };

    constexpr std::string_view to_string(const Token t) {
        switch (t) {
        case Token::Token_invalid: return "invalid";
        case Token::Token_e: return "e";
        case Token::Token_s: return "s";
        case Token::Token_ee: return "ee";
        case Token::Token_es: return "es";
        case Token::Token_se: return "se";
        case Token::Token_ss: return "ss";
        case Token::Token_ekem: return "ekem";
        case Token::Token_skem: return "skem";
        case Token::Token_e1: return "e1";
        case Token::Token_ekem1: return "ekem1";
        case Token::Token_psk: return "psk";
        }
        return "?";
    }

    /** A single handshake message consisting of an ordered sequence of tokens. */
    struct MessagePattern {
        std::vector<Token> tokens;  ///< Token sequence, e.g., {Token_e, Token_ee, Token_s, Token_es}.
    };

    /**
     * Complete handshake pattern definition including pre-messages and message sequences.
     *
     * Defines the structure of a Noise handshake: which keys are known beforehand
     * (pre-messages), and what operations occur in each message exchange. Supports
     * classical patterns (Noise spec Sections 7-8), PSK patterns (Section 9),
     * post-quantum patterns (PQNoise paper), and hybrid forward secrecy patterns
     * (noise-kem-hfs.pdf).
     *
     * Pattern validity rules are enforced by IsValid() per Noise spec Section 7.3.
     */
    struct HandshakePattern {
        using enum Token;
        std::string m_patternName;              ///< Pattern name, e.g., "XX", "pqXX", "XXhfs".
        std::vector<Token> pre_initiator;       ///< Initiator's pre-message tokens (e.g., {s} for K patterns).
        std::vector<Token> pre_responder;       ///< Responder's pre-message tokens (e.g., {s} for NK patterns).
        std::vector<MessagePattern> messages;   ///< Ordered handshake message sequences.
        bool isOneWay{false};                   ///< True for one-way patterns (N, K, X).
        std::uint8_t numPSKs{};                 ///< Number of pre-shared keys required.

        [[nodiscard]] std::string_view String() const {
            return m_patternName;
        }

        // Tiny helper to pretty-print (optional)
        void describe(std::ostream& os) const {
            // Use colors from Common.cppm
            using Color::BrightCyan;      // Initiator
            using Color::BrightMagenta;   // Responder
            using Color::BrightYellow;    // Separator
            using Color::Reset;

            os << m_patternName << ":\n";
            if (!pre_initiator.empty() || !pre_responder.empty()) {
                // Pre-messages with directional arrows (color-coded)
                if (!pre_initiator.empty()) {
                    os << "  " << BrightCyan << "-> ";
                    for (std::size_t i = 0; i < pre_initiator.size(); ++i) {
                        if (i) os << ", ";
                        os << to_string(pre_initiator[i]);
                    }
                    os << Reset << '\n';
                }
                if (!pre_responder.empty()) {
                    os << "  " << BrightMagenta << "<- ";
                    for (std::size_t i = 0; i < pre_responder.size(); ++i) {
                        if (i) os << ", ";
                        os << to_string(pre_responder[i]);
                    }
                    os << Reset << '\n';
                }
                os << "  " << BrightYellow << "..." << Reset << '\n';
            }
            // Handshake messages with directional arrows (color-coded)
            // Messages alternate: even index = initiator (->), odd index = responder (<-)
            for (std::size_t msg_idx = 0; msg_idx < messages.size(); ++msg_idx) {
                const auto& m = messages[msg_idx];
                // Even index (0, 2, 4...) = initiator sends (->)
                // Odd index (1, 3, 5...) = responder sends (<-)
                const bool isInitiator = (msg_idx % 2 == 0);
                const std::string_view color = isInitiator ? BrightCyan : BrightMagenta;
                const std::string_view arrow = isInitiator ? "->" : "<-";

                os << "  " << color << arrow << " ";
                for (std::size_t i = 0; i < m.tokens.size(); ++i) {
                    if (i) os << ", ";
                    os << to_string(m.tokens[i]);
                }
                os << Reset << '\n';
            }
        }

        /// @name Pattern Validation (Noise spec Section 7.3)
        /// @{

        /** @return True if the pattern has only one message (one-way: N, K, X). */
        static constexpr bool IsOneWay(const HandshakePattern& pattern) {
            return pattern.messages.size() == 1;
        }

        /**
         * Validates a pattern against handshake pattern validity rules (Noise spec Section 7.3).
         *
         * Checks all rules including: no duplicate key transmissions (Rule 2),
         * no duplicate DH operations (Rule 3), DH only with possessed keys (Rule 1),
         * static-key DH requires ephemeral DH first (Rule 4), PSK requires ephemeral
         * key, and at least one key exchange operation must exist. Extended for
         * PQNoise KEM tokens and HFS tokens.
         *
         * @param pa The pattern to validate.
         * @return Success, or an error message describing the violation.
         */
        static std::expected<void, std::string> IsValid(const HandshakePattern& pa) {
            std::unordered_map<Token, bool> initTokens;
            std::unordered_map<Token, bool> respTokens;

            // Helper: Check if token exists in either side
            auto inEither = [&](Token t) -> bool {
                return initTokens.contains(t) || respTokens.contains(t);
            };

            // Helper: Check if token exists in both sides
            auto inBoth = [&](Token t) -> bool {
                return initTokens.contains(t) && respTokens.contains(t);
            };

            // Sanity-check the pre-messages
            const auto& preMessages = std::vector<std::vector<Token>>{
                pa.pre_initiator,
                pa.pre_responder
            };

            if (preMessages.size() > 2) {
                return std::unexpected("excessive pre-messages");
            }

            for (std::size_t i = 0; i < preMessages.size(); ++i) {
                const bool isInitiator = (i % 2 == 0);
                auto& m = isInitiator ? initTokens : respTokens;
                const std::string_view side = isInitiator ? "initiator" : "responder";

                for (const auto v : preMessages[i]) {
                    switch (v) {
                    case Token_e:
                    case Token_s:
                        // 2. Parties must not send their static public key or ephemeral
                        // public key more than once per handshake.
                        if (m.contains(v)) {
                            return std::unexpected(std::format("redundant pre-message token ({}): {}",
                                                               side, to_string(v)));
                        }
                        m[v] = true;
                        break;
                    default:
                        return std::unexpected(std::format("invalid pre-message token: {}",
                                                           to_string(v)));
                    }
                }
            }

            // Validate the messages
            const auto& messages = pa.messages;
            if (messages.empty()) {
                return std::unexpected("no handshake messages");
            }
            if (IsOneWay(pa) && messages.size() != 1) {
                return std::unexpected("excessive messages for one-way pattern");
            }

            int numDHs = 0;
            int numKEMs = 0;
            int numPSKs = 0;

            for (std::size_t i = 0; i < messages.size(); ++i) {
                const bool isInitiator = (i % 2 == 0);
                auto& m = isInitiator ? initTokens : respTokens;
                const std::string_view side = isInitiator ? "initiator" : "responder";

                for (const auto v : messages[i].tokens) {
                    switch (v) {
                    case Token_e:
                    case Token_s:
                        // 2. Parties must not send their static public key or ephemeral
                        // public key more than once per handshake.
                        if (m.contains(v)) {
                            return std::unexpected(std::format("redundant public key ({}): {}",
                                                               side, to_string(v)));
                        }
                        break;
                    case Token_e1:
                        // HFS: e1 can only be sent once per party (KEM ephemeral)
                        // Must also have sent 'e' in same message or earlier
                        if (m.contains(v)) {
                            return std::unexpected(std::format("redundant HFS KEM public key ({}): {}",
                                                               side, to_string(v)));
                        }
                        break;
                    case Token_ee:
                    case Token_es:
                    case Token_se:
                    case Token_ss:
                        // 3. Parties must not perform a DH calculation more than once
                        // per handshake.
                        if (inEither(v)) {
                            return std::unexpected(std::format("redundant DH calculation: {}",
                                                               to_string(v)));
                        }
                        numDHs++;
                        break;
                    case Token_ekem:
                    case Token_skem:
                        // KEM operations (NoisePQC++): Each party can perform ekem/skem once
                        // Unlike DH, KEM is directional - each party encapsulates TO the other
                        // So initiator can do ekem AND responder can do ekem (different operations)
                        if (m.contains(v)) {
                            return std::unexpected(std::format("redundant KEM operation ({}): {}",
                                                               side, to_string(v)));
                        }
                        numKEMs++;
                        break;
                    case Token_ekem1:
                        // HFS: ekem1 can only appear once per handshake (global, not per-party)
                        // Unlike NoisePQC++ ekem/skem, there's only one ekem1 operation
                        if (inEither(v)) {
                            return std::unexpected(std::format("redundant HFS KEM operation: {}",
                                                               to_string(v)));
                        }
                        numKEMs++;
                        break;
                    case Token_psk:
                        numPSKs++;
                        break;
                    default:
                        return std::unexpected(std::format("invalid message token: {}",
                                                           to_string(v)));
                    }

                    // 1. Parties can only perform DH between private keys and public
                    // keys they possess.
                    Token impossibleDH = Token_invalid;
                    switch (v) {
                    case Token_ee:
                        if (!inBoth(Token_e)) {
                            impossibleDH = v;
                        }
                        break;
                    case Token_ss:
                        if (!inBoth(Token_s)) {
                            impossibleDH = v;
                        }
                        break;
                    case Token_es:
                        if (!initTokens.contains(Token_e) || !respTokens.contains(Token_s)) {
                            impossibleDH = v;
                        }
                        break;
                    case Token_se:
                        if (!initTokens.contains(Token_s) || !respTokens.contains(Token_e)) {
                            impossibleDH = v;
                        }
                        break;
                    default:
                        break;
                    }
                    if (impossibleDH != Token_invalid) {
                        return std::unexpected(std::format("impossible DH: {}", to_string(v)));
                    }

                    // KEM operations require the target key to be available
                    // ekem: Encapsulate TO peer's ephemeral - peer must have sent 'e'
                    // skem: Encapsulate TO peer's static - peer must have sent 's' (or pre-message)
                    Token impossibleKEM = Token_invalid;
                    switch (v) {
                    case Token_ekem:
                        // ekem encapsulates TO the OTHER party's ephemeral
                        if (isInitiator) {
                            if (!respTokens.contains(Token_e)) {
                                impossibleKEM = v;
                            }
                        } else {
                            if (!initTokens.contains(Token_e)) {
                                impossibleKEM = v;
                            }
                        }
                        break;
                    case Token_skem:
                        // skem encapsulates TO the OTHER party's static
                        if (isInitiator) {
                            if (!respTokens.contains(Token_s)) {
                                impossibleKEM = v;
                            }
                        } else {
                            if (!initTokens.contains(Token_s)) {
                                impossibleKEM = v;
                            }
                        }
                        break;
                    case Token_e1:
                        // HFS e1: Requires 'e' to have been sent by same party first
                        if (!m.contains(Token_e)) {
                            return std::unexpected(std::format("HFS e1 requires 'e' to be sent first ({})",
                                                               side));
                        }
                        break;
                    case Token_ekem1:
                        // HFS ekem1: Encapsulates TO the OTHER party's e1
                        // Also requires 'ee' to have been computed (per spec)
                        if (!inEither(Token_ee)) {
                            return std::unexpected("HFS ekem1 requires 'ee' to be computed first");
                        }
                        if (isInitiator) {
                            if (!respTokens.contains(Token_e1)) {
                                impossibleKEM = v;
                            }
                        } else {
                            if (!initTokens.contains(Token_e1)) {
                                impossibleKEM = v;
                            }
                        }
                        break;
                    default:
                        break;
                    }
                    if (impossibleKEM != Token_invalid) {
                        return std::unexpected(std::format("impossible KEM (target key not available): {}",
                                                           to_string(v)));
                    }

                    m[v] = true;
                }

                // 4. After performing a DH between a remote public key (either static
                // or ephemeral) and the local static key, the local party must not
                // call ENCRYPT() unless it has also performed a DH between its local
                // ephemeral key and the remote public key.
                Token missingDH = Token_invalid;
                if (isInitiator) {
                    if (inEither(Token_se) && !inEither(Token_ee)) {
                        missingDH = Token_ee;
                    }
                    if (inEither(Token_ss) && !inEither(Token_es)) {
                        missingDH = Token_es;
                    }
                }
                else {
                    if (inEither(Token_es) && !inEither(Token_ee)) {
                        missingDH = Token_ee;
                    }
                    if (inEither(Token_ss) && !inEither(Token_se)) {
                        missingDH = Token_se;
                    }
                }
                if (missingDH != Token_invalid) {
                    return std::unexpected(std::format("missing DH calculation ({}): {}",
                                                       side, to_string(missingDH)));
                }

                if (inEither(Token_psk)) {
                    // A party may not send any encrypted data after it processes a
                    // "psk" token unless it has previously sent an ephemeral public
                    // key (an "e" token), either before or after the "psk" token.
                    if (!m.contains(Token_e)) {
                        return std::unexpected(std::format(
                            "payload after pre-shared key without ephemeral ({})", side));
                    }
                }
            }

            // Patterns without any DH or KEM calculations may be "valid", but are
            // nonsensical. A pattern must have at least one key exchange operation.
            if (numDHs == 0 && numKEMs == 0) {
                return std::unexpected("no DH or KEM calculations at all");
            }

            // Make sure the PSK hint interface function is implemented correctly.
            if (numPSKs != pa.numPSKs) {
                return std::unexpected("NumPSKs() mismatch with (pre-)messages");
            }

            return {};
        }
        /// @}
    };

    using enum Token;

    /// @name Pattern Modifiers
    /// @{

    /**
     * Transforms a classical pattern into an HFS (Hybrid Forward Secrecy) variant
     * by inserting e1/ekem1 tokens per noise-kem-hfs.pdf.
     *
     * Transformation rules:
     * 1. Insert 'e1' after the first 'e' token. If a DH operation exists in the same
     *    message, place 'e1' after the last DH instead.
     * 2. Insert 'ekem1' after the first 'ee' token.
     *
     * @param base The classical pattern to transform (e.g., PatternXX).
     * @return A new pattern with "hfs" suffix and inserted KEM tokens.
     */
    [[nodiscard]] inline HandshakePattern ApplyHFSModifier(const HandshakePattern& base) {
        HandshakePattern hfs = base;
        hfs.m_patternName = std::string(base.m_patternName) + "hfs";

        bool e1_added = false;
        bool ekem1_added = false;

        for (auto& msg : hfs.messages) {
            // Find position of first 'e' token in this message
            auto e_pos = std::find(msg.tokens.begin(), msg.tokens.end(), Token_e);

            // Rule 1: Add e1 after first 'e' (or after last DH if DH in same message)
            if (!e1_added && e_pos != msg.tokens.end()) {
                // Check if there's a DH operation in this message (ee, es, se, ss)
                auto last_dh = msg.tokens.end();
                for (auto it = msg.tokens.begin(); it != msg.tokens.end(); ++it) {
                    if (*it == Token_ee || *it == Token_es ||
                        *it == Token_se || *it == Token_ss) {
                        last_dh = it;
                    }
                }

                if (last_dh != msg.tokens.end()) {
                    // Insert e1 after the last DH operation in this message
                    msg.tokens.insert(last_dh + 1, Token_e1);
                } else {
                    // Insert e1 directly after 'e'
                    msg.tokens.insert(e_pos + 1, Token_e1);
                }
                e1_added = true;
            }

            // Rule 2: Add ekem1 after first 'ee'
            // Note: Must re-find since tokens may have shifted from e1 insertion
            if (!ekem1_added) {
                auto ee_pos = std::find(msg.tokens.begin(), msg.tokens.end(), Token_ee);
                if (ee_pos != msg.tokens.end()) {
                    msg.tokens.insert(ee_pos + 1, Token_ekem1);
                    ekem1_added = true;
                }
            }
        }

        return hfs;
    }

    /**
     * Applies a PSK modifier to a base pattern (Noise spec Section 9).
     *
     * Creates a new pattern with a 'psk' token inserted at the position indicated
     * by the modifier: "psk0" prepends to the first message, "pskN" (N>0) appends
     * to message N-1.
     *
     * @param templatePattern The base pattern (must have numPSKs == 0).
     * @param modifier The PSK modifier string, e.g., "psk0", "psk1", "psk2".
     * @return A new pattern with the PSK token inserted and numPSKs set to 1.
     * @throws NoiseError If the modifier is invalid or the template already has PSKs.
     */
    inline HandshakePattern MakePSK(const HandshakePattern& templatePattern, std::string_view modifier) {
        if (templatePattern.numPSKs > 0) {
            throw NoiseError("PSK template pattern already has PSKs");
        }

        HandshakePattern result = templatePattern;
        result.m_patternName = std::string(templatePattern.m_patternName) + std::string(modifier);

        // Parse PSK index from modifier (e.g., "psk0" -> 0, "psk1" -> 1)
        constexpr std::string_view prefix = "psk";
        if (!modifier.starts_with(prefix)) {
            throw NoiseError("Invalid PSK modifier: " + std::string(modifier));
        }

        const auto index_str = modifier.substr(prefix.size());
        int pskIndex = 0;
        auto [ptr, ec] = std::from_chars(index_str.data(), index_str.data() + index_str.size(), pskIndex);
        if (ec != std::errc()) {
            throw NoiseError("Failed to parse PSK index: " + std::string(modifier));
        }

        if (pskIndex < 0 || pskIndex > static_cast<int>(templatePattern.messages.size())) {
            throw NoiseError(std::format("Invalid PSK index {} for pattern {} with {} messages",
                                         pskIndex, templatePattern.m_patternName,
                                         templatePattern.messages.size()));
        }

        // Apply PSK modifier
        // psk0: insert at beginning of first message
        // pskN (N>0): append to end of message N-1
        if (pskIndex == 0) {
            result.messages[0].tokens.insert(result.messages[0].tokens.begin(), Token_psk);
        }
        else {
            const std::size_t idx = pskIndex - 1;
            result.messages[idx].tokens.push_back(Token_psk);
        }

        result.numPSKs = 1;
        return result;
    }

    /// @}

    /// @name One-Way Patterns (Noise spec Section 7.4)
    /// Patterns with a single message from initiator to responder.
    /// @{

    /** Pattern N: No initiator static key. @code <- s ... -> e, es @endcode */
    inline const HandshakePattern N{
        "N",
        {},
        {Token_s},
        {
            {{Token_e, Token_es}}
        },
        true
    };

    /** Pattern K: Both static keys known. @code -> s <- s ... -> e, es, ss @endcode */
    inline const HandshakePattern K{
        "K",
        {Token_s},
        {Token_s},
        {
            {{Token_e, Token_es, Token_ss}}
        },
        true
    };

    /** Pattern X: Initiator authenticates via static key. @code <- s ... -> e, es, s, ss @endcode */
    inline const HandshakePattern X{
        "X",
        {},
        {Token_s},
        {
            {{Token_e, Token_es, Token_s, Token_ss}}
        },
        true
    };

    /// @}

    /// @name Fundamental Interactive Patterns (Noise spec Section 7.5)
    /// Two-way patterns with various authentication combinations.
    /// @{

    // NN: -> e <- e, ee
    inline const HandshakePattern NN{
        "NN",
        {},
        {},
        {
            {{Token_e}},
            {{Token_e, Token_ee}}
        }
    };

    // NK: <- s ... -> e, es <- e, ee
    inline const HandshakePattern NK{
        "NK",
        {},
        {Token_s},
        {
            {{Token_e, Token_es}},
            {{Token_e, Token_ee}}
        }
    };

    // NX: -> e <- e, ee, s, es
    inline const HandshakePattern NX{
        "NX",
        {},
        {},
        {
            {{Token_e}},
            {{Token_e, Token_ee, Token_s, Token_es}}
        }
    };

    // KN: -> s ... -> e <- e, ee, se
    inline const HandshakePattern KN{
        "KN",
        {Token_s},
        {},
        {
            {{Token_e}},
            {{Token_e, Token_ee, Token_se}}
        }
    };

    // KK: -> s <- s ... -> e, es, ss <- e, ee, se
    inline const HandshakePattern KK{
        "KK",
        {Token_s},
        {Token_s},
        {
            {{Token_e, Token_es, Token_ss}},
            {{Token_e, Token_ee, Token_se}}
        }
    };

    // KX: -> s ... -> e <- e, ee, se, s, es
    inline const HandshakePattern KX{
        "KX",
        {Token_s},
        {},
        {
            {{Token_e}},
            {{Token_e, Token_ee, Token_se, Token_s, Token_es}}
        }
    };

    // XN: -> e <- e, ee -> s, se
    inline const HandshakePattern XN{
        "XN",
        {},
        {},
        {
            {{Token_e}},
            {{Token_e, Token_ee}},
            {{Token_s, Token_se}}
        }
    };

    // XK: <- s ... -> e, es <- e, ee -> s, se
    inline const HandshakePattern XK{
        "XK",
        {},
        {Token_s},
        {
            {{Token_e, Token_es}},
            {{Token_e, Token_ee}},
            {{Token_s, Token_se}}
        }
    };

    // XX: -> e <- e, ee, s, es -> s, se
    inline const HandshakePattern XX{
        "XX",
        {},
        {},
        {
            {{Token_e}},
            {{Token_e, Token_ee, Token_s, Token_es}},
            {{Token_s, Token_se}}
        }
    };

    // IN: -> e, s <- e, ee, se
    inline const HandshakePattern IN{
        "IN",
        {},
        {},
        {
            {{Token_e, Token_s}},
            {{Token_e, Token_ee, Token_se}}
        }
    };

    // IK: <- s ... -> e, es, s, ss <- e, ee, se
    inline const HandshakePattern IK{
        "IK",
        {},
        {Token_s},
        {
            {{Token_e, Token_es, Token_s, Token_ss}},
            {{Token_e, Token_ee, Token_se}}
        }
    };

    // IX: -> e, s <- e, ee, se, s, es
    inline const HandshakePattern IX{
        "IX",
        {},
        {},
        {
            {{Token_e, Token_s}},
            {{Token_e, Token_ee, Token_se, Token_s, Token_es}}
        }
    };

    /// @}

    /// @name Deferred Patterns (Noise spec Section 7.6)
    /// Patterns that defer DH operations to later messages for weaker but more flexible authentication.
    /// @{

    // NK1
    inline const HandshakePattern NK1{
        "NK1",
        {},
        {Token_s},
        {
            {{Token_e}},
            {{Token_e, Token_ee, Token_es}}
        }
    };

    // NX1
    inline const HandshakePattern NX1{
        "NX1",
        {},
        {},
        {
            {{Token_e}},
            {{Token_e, Token_ee, Token_s}},
            {{Token_es}}
        }
    };

    // X1N
    inline const HandshakePattern X1N{
        "X1N",
        {},
        {},
        {
            {{Token_e}},
            {{Token_e, Token_ee}},
            {{Token_s}},
            {{Token_se}}
        }
    };

    // X1K
    inline const HandshakePattern X1K{
        "X1K",
        {},
        {Token_s},
        {
            {{Token_e, Token_es}},
            {{Token_e, Token_ee}},
            {{Token_s}},
            {{Token_se}}
        }
    };

    // XK1
    inline const HandshakePattern XK1{
        "XK1",
        {},
        {Token_s},
        {
            {{Token_e}},
            {{Token_e, Token_ee, Token_es}},
            {{Token_s, Token_se}}
        }
    };

    // X1K1
    inline const HandshakePattern X1K1{
        "X1K1",
        {},
        {Token_s},
        {
            {{Token_e}},
            {{Token_e, Token_ee, Token_es}},
            {{Token_s}},
            {{Token_se}}
        }
    };

    // X1X
    inline const HandshakePattern X1X{
        "X1X",
        {},
        {},
        {
            {{Token_e}},
            {{Token_e, Token_ee, Token_s, Token_es}},
            {{Token_s}},
            {{Token_se}}
        }
    };

    // XX1
    inline const HandshakePattern XX1{
        "XX1",
        {},
        {},
        {
            {{Token_e}},
            {{Token_e, Token_ee, Token_s}},
            {{Token_es, Token_s, Token_se}}
        }
    };

    // X1X1
    inline const HandshakePattern X1X1{
        "X1X1",
        {},
        {},
        {
            {{Token_e}},
            {{Token_e, Token_ee, Token_s}},
            {{Token_es, Token_s}},
            {{Token_se}}
        }
    };

    // K1N
    inline const HandshakePattern K1N{
        "K1N",
        {Token_s},
        {},
        {
            {{Token_e}},
            {{Token_e, Token_ee}},
            {{Token_se}}
        }
    };

    // K1K
    inline const HandshakePattern K1K{
        "K1K",
        {Token_s},
        {Token_s},
        {
            {{Token_e, Token_es}},
            {{Token_e, Token_ee}},
            {{Token_se}}
        }
    };

    // KK1
    inline const HandshakePattern KK1{
        "KK1",
        {Token_s},
        {Token_s},
        {
            {{Token_e}},
            {{Token_e, Token_ee, Token_se, Token_es}}
        }
    };

    // K1K1
    inline const HandshakePattern K1K1{
        "K1K1",
        {Token_s},
        {Token_s},
        {
            {{Token_e}},
            {{Token_e, Token_ee, Token_es}},
            {{Token_se}}
        }
    };

    // K1X
    inline const HandshakePattern K1X{
        "K1X",
        {Token_s},
        {},
        {
            {{Token_e}},
            {{Token_e, Token_ee, Token_s, Token_es}},
            {{Token_se}}
        }
    };

    // KX1
    inline const HandshakePattern KX1{
        "KX1",
        {Token_s},
        {},
        {
            {{Token_e}},
            {{Token_e, Token_ee, Token_se, Token_s}},
            {{Token_es}}
        }
    };

    // K1X1
    inline const HandshakePattern K1X1{
        "K1X1",
        {Token_s},
        {},
        {
            {{Token_e}},
            {{Token_e, Token_ee, Token_s}},
            {{Token_se, Token_es}}
        }
    };

    // I1N
    inline const HandshakePattern I1N{
        "I1N",
        {},
        {},
        {
            {{Token_e, Token_s}},
            {{Token_e, Token_ee}},
            {{Token_se}}
        }
    };

    // I1K
    inline const HandshakePattern I1K{
        "I1K",
        {},
        {Token_s},
        {
            {{Token_e, Token_es, Token_s}},
            {{Token_e, Token_ee}},
            {{Token_se}}
        }
    };

    // IK1
    inline const HandshakePattern IK1{
        "IK1",
        {},
        {Token_s},
        {
            {{Token_e, Token_s}},
            {{Token_e, Token_ee, Token_se, Token_es}}
        }
    };

    // I1K1
    inline const HandshakePattern I1K1{
        "I1K1",
        {},
        {Token_s},
        {
            {{Token_e, Token_s}},
            {{Token_e, Token_ee, Token_es}},
            {{Token_se}}
        }
    };

    // I1X
    inline const HandshakePattern I1X{
        "I1X",
        {},
        {},
        {
            {{Token_e, Token_s}},
            {{Token_e, Token_ee, Token_s, Token_es}},
            {{Token_se}}
        }
    };

    // IX1
    inline const HandshakePattern IX1{
        "IX1",
        {},
        {},
        {
            {{Token_e, Token_s}},
            {{Token_e, Token_ee, Token_se, Token_s}},
            {{Token_es}}
        }
    };

    // I1X1
    inline const HandshakePattern I1X1{
        "I1X1",
        {},
        {},
        {
            {{Token_e, Token_s}},
            {{Token_e, Token_ee, Token_s}},
            {{Token_se, Token_es}}
        }
    };

    /// @}

    /// @name Post-Quantum Patterns (PQNoise paper)
    /// Patterns using KEM (ekem/skem) tokens instead of DH (ee/es/se/ss) for
    /// post-quantum security via ML-KEM encapsulation.
    /// @{
    // These patterns use KEM-based key exchange instead of DH.
    // Token semantics per PQNoise paper:
    // - e: Send ephemeral public key (encapsulation key for KEM)
    // - s: Send static public key (encapsulation key for KEM)
    // - ekem: Encapsulate TO peer's ephemeral public key
    // - skem: Encapsulate TO peer's static public key

    // pqNN: No authentication (anonymous/testing)
    // -> e
    // <- ekem
    inline const HandshakePattern pqNN{
        "pqNN",
        {},
        {},
        {
            {{Token_e}},
            {{Token_ekem}}
        }
    };

    // pqNK: Responder authentication (server auth, like HTTPS)
    // <- s
    // ...
    // -> skem, e
    // <- ekem
    inline const HandshakePattern pqNK{
        "pqNK",
        {},
        {Token_s},
        {
            {{Token_skem, Token_e}},
            {{Token_ekem}}
        }
    };

    // pqKK: Mutual pre-shared key authentication (both keys known)
    // -> s
    // <- s
    // ...
    // -> skem, e
    // <- ekem, skem
    inline const HandshakePattern pqKK{
        "pqKK",
        {Token_s},
        {Token_s},
        {
            {{Token_skem, Token_e}},
            {{Token_ekem, Token_skem}}
        }
    };

    // pqXK: Responder auth, deferred initiator auth
    // <- s
    // ...
    // -> skem, e
    // <- ekem
    // -> s
    // <- skem
    inline const HandshakePattern pqXK{
        "pqXK",
        {},
        {Token_s},
        {
            {{Token_skem, Token_e}},
            {{Token_ekem}},
            {{Token_s}},
            {{Token_skem}}
        }
    };

    // pqXX: Full mutual authentication, progressive
    // -> e
    // <- ekem, s
    // -> skem, s
    // <- skem
    inline const HandshakePattern pqXX{
        "pqXX",
        {},
        {},
        {
            {{Token_e}},
            {{Token_ekem, Token_s}},
            {{Token_skem, Token_s}},
            {{Token_skem}}
        }
    };

    // pqIK: Immediate mutual authentication (low latency)
    // <- s
    // ...
    // -> skem, e, s
    // <- ekem, skem
    inline const HandshakePattern pqIK{
        "pqIK",
        {},
        {Token_s},
        {
            {{Token_skem, Token_e, Token_s}},
            {{Token_ekem, Token_skem}}
        }
    };

    // pqN: One-way pattern, responder authentication
    // <- s
    // ...
    // -> skem
    inline const HandshakePattern pqN{
        "pqN",
        {},
        {Token_s},
        {
            {{Token_skem}}
        }
    };

    // pqNX: No auth initiator, responder sends static
    // -> e
    // <- ekem, s
    // -> skem
    inline const HandshakePattern pqNX{
        "pqNX",
        {},
        {},
        {
            {{Token_e}},
            {{Token_ekem, Token_s}},
            {{Token_skem}}
        }
    };

    // pqXN: Initiator sends static deferred
    // -> e
    // <- ekem
    // -> s
    // <- skem
    inline const HandshakePattern pqXN{
        "pqXN",
        {},
        {},
        {
            {{Token_e}},
            {{Token_ekem}},
            {{Token_s}},
            {{Token_skem}}
        }
    };

    // pqKN: Responder knows initiator's static key
    // -> s
    // ...
    // -> e
    // <- ekem, skem
    inline const HandshakePattern pqKN{
        "pqKN",
        {Token_s},
        {},
        {
            {{Token_e}},
            {{Token_ekem, Token_skem}}
        }
    };

    // pqKX: Initiator static known, responder sends
    // -> s
    // ...
    // -> e
    // <- ekem, skem, s
    // -> skem
    inline const HandshakePattern pqKX{
        "pqKX",
        {Token_s},
        {},
        {
            {{Token_e}},
            {{Token_ekem, Token_skem, Token_s}},
            {{Token_skem}}
        }
    };

    // pqIN: Initiator sends static immediately
    // -> e, s
    // <- ekem, skem
    inline const HandshakePattern pqIN{
        "pqIN",
        {},
        {},
        {
            {{Token_e, Token_s}},
            {{Token_ekem, Token_skem}}
        }
    };

    // pqIX: Initiator sends static first, responder responds
    // -> e, s
    // <- ekem, skem, s
    // -> skem
    inline const HandshakePattern pqIX{
        "pqIX",
        {},
        {},
        {
            {{Token_e, Token_s}},
            {{Token_ekem, Token_skem, Token_s}},
            {{Token_skem}}
        }
    };

    /// @}

    /// Expected number of patterns in the registry (base + deferred + PSK + PQ + HFS).
    constexpr std::size_t EXPECTED_PATTERN_COUNT = 110;

    /**
     * Creates the complete pattern registry containing all supported handshake patterns.
     *
     * Includes 57 classical patterns (one-way, fundamental, deferred), 13 PQ patterns,
     * 18 PSK variants, and 35 HFS variants. PSK and HFS patterns are created dynamically
     * via MakePSK() and ApplyHFSModifier() to avoid static initialization order issues.
     *
     * @return Map from pattern name string to HandshakePattern definition.
     */
    inline std::unordered_map<std::string, HandshakePattern> CreatePatternRegistry() {
        std::unordered_map<std::string, HandshakePattern> registry;
        registry.reserve(EXPECTED_PATTERN_COUNT);

        // Base one-way patterns
        registry.emplace(N.m_patternName, N);
        registry.emplace(K.m_patternName, K);
        registry.emplace(X.m_patternName, X);

        // Fundamental interactive patterns
        registry.emplace(NN.m_patternName, NN);
        registry.emplace(NK.m_patternName, NK);
        registry.emplace(NX.m_patternName, NX);
        registry.emplace(KN.m_patternName, KN);
        registry.emplace(KK.m_patternName, KK);
        registry.emplace(KX.m_patternName, KX);
        registry.emplace(XN.m_patternName, XN);
        registry.emplace(XK.m_patternName, XK);
        registry.emplace(XX.m_patternName, XX);
        registry.emplace(IN.m_patternName, IN);
        registry.emplace(IK.m_patternName, IK);
        registry.emplace(IX.m_patternName, IX);

        // Deferred patterns
        registry.emplace(NK1.m_patternName, NK1);
        registry.emplace(NX1.m_patternName, NX1);
        registry.emplace(X1N.m_patternName, X1N);
        registry.emplace(X1K.m_patternName, X1K);
        registry.emplace(XK1.m_patternName, XK1);
        registry.emplace(X1K1.m_patternName, X1K1);
        registry.emplace(X1X.m_patternName, X1X);
        registry.emplace(XX1.m_patternName, XX1);
        registry.emplace(X1X1.m_patternName, X1X1);
        registry.emplace(K1N.m_patternName, K1N);
        registry.emplace(K1K.m_patternName, K1K);
        registry.emplace(KK1.m_patternName, KK1);
        registry.emplace(K1K1.m_patternName, K1K1);
        registry.emplace(K1X.m_patternName, K1X);
        registry.emplace(KX1.m_patternName, KX1);
        registry.emplace(K1X1.m_patternName, K1X1);
        registry.emplace(I1N.m_patternName, I1N);
        registry.emplace(I1K.m_patternName, I1K);
        registry.emplace(IK1.m_patternName, IK1);
        registry.emplace(I1K1.m_patternName, I1K1);
        registry.emplace(I1X.m_patternName, I1X);
        registry.emplace(IX1.m_patternName, IX1);
        registry.emplace(I1X1.m_patternName, I1X1);

        // Post-Quantum (NoisePQC++) patterns - One-way
        registry.emplace(pqN.m_patternName, pqN);

        // Post-Quantum (NoisePQC++) patterns - Interactive
        registry.emplace(pqNN.m_patternName, pqNN);
        registry.emplace(pqNK.m_patternName, pqNK);
        registry.emplace(pqNX.m_patternName, pqNX);
        registry.emplace(pqXN.m_patternName, pqXN);
        registry.emplace(pqXK.m_patternName, pqXK);
        registry.emplace(pqXX.m_patternName, pqXX);
        registry.emplace(pqKN.m_patternName, pqKN);
        registry.emplace(pqKK.m_patternName, pqKK);
        registry.emplace(pqKX.m_patternName, pqKX);
        registry.emplace(pqIN.m_patternName, pqIN);
        registry.emplace(pqIK.m_patternName, pqIK);
        registry.emplace(pqIX.m_patternName, pqIX);

        // PSK patterns - created dynamically to avoid static init order issues
        // One-way PSK
        auto Npsk0 = MakePSK(N, "psk0");
        auto Kpsk0 = MakePSK(K, "psk0");
        auto Xpsk1 = MakePSK(X, "psk1");
        registry.emplace(Npsk0.m_patternName, std::move(Npsk0));
        registry.emplace(Kpsk0.m_patternName, std::move(Kpsk0));
        registry.emplace(Xpsk1.m_patternName, std::move(Xpsk1));

        // Interactive PSK
        auto NNpsk0 = MakePSK(NN, "psk0");
        auto NNpsk2 = MakePSK(NN, "psk2");
        auto NKpsk0 = MakePSK(NK, "psk0");
        auto NKpsk2 = MakePSK(NK, "psk2");
        auto NXpsk2 = MakePSK(NX, "psk2");
        auto XNpsk3 = MakePSK(XN, "psk3");
        auto XKpsk3 = MakePSK(XK, "psk3");
        auto XXpsk3 = MakePSK(XX, "psk3");
        auto KNpsk0 = MakePSK(KN, "psk0");
        auto KNpsk2 = MakePSK(KN, "psk2");
        auto KKpsk0 = MakePSK(KK, "psk0");
        auto KKpsk2 = MakePSK(KK, "psk2");
        auto KXpsk2 = MakePSK(KX, "psk2");
        auto INpsk1 = MakePSK(IN, "psk1");
        auto INpsk2 = MakePSK(IN, "psk2");
        auto IKpsk1 = MakePSK(IK, "psk1");
        auto IKpsk2 = MakePSK(IK, "psk2");
        auto IXpsk2 = MakePSK(IX, "psk2");

        registry.emplace(NNpsk0.m_patternName, std::move(NNpsk0));
        registry.emplace(NNpsk2.m_patternName, std::move(NNpsk2));
        registry.emplace(NKpsk0.m_patternName, std::move(NKpsk0));
        registry.emplace(NKpsk2.m_patternName, std::move(NKpsk2));
        registry.emplace(NXpsk2.m_patternName, std::move(NXpsk2));
        registry.emplace(XNpsk3.m_patternName, std::move(XNpsk3));
        registry.emplace(XKpsk3.m_patternName, std::move(XKpsk3));
        registry.emplace(XXpsk3.m_patternName, std::move(XXpsk3));
        registry.emplace(KNpsk0.m_patternName, std::move(KNpsk0));
        registry.emplace(KNpsk2.m_patternName, std::move(KNpsk2));
        registry.emplace(KKpsk0.m_patternName, std::move(KKpsk0));
        registry.emplace(KKpsk2.m_patternName, std::move(KKpsk2));
        registry.emplace(KXpsk2.m_patternName, std::move(KXpsk2));
        registry.emplace(INpsk1.m_patternName, std::move(INpsk1));
        registry.emplace(INpsk2.m_patternName, std::move(INpsk2));
        registry.emplace(IKpsk1.m_patternName, std::move(IKpsk1));
        registry.emplace(IKpsk2.m_patternName, std::move(IKpsk2));
        registry.emplace(IXpsk2.m_patternName, std::move(IXpsk2));

        // HFS (Hybrid Forward Secrecy) patterns - created dynamically using ApplyHFSModifier
        // HFS adds KEM-based hybrid forward secrecy to standard DH patterns
        // Only interactive patterns with 'ee' DH operation can use HFS

        // Fundamental interactive HFS patterns
        auto NNhfs = ApplyHFSModifier(NN);
        auto NKhfs = ApplyHFSModifier(NK);
        auto NXhfs = ApplyHFSModifier(NX);
        auto KNhfs = ApplyHFSModifier(KN);
        auto KKhfs = ApplyHFSModifier(KK);
        auto KXhfs = ApplyHFSModifier(KX);
        auto XNhfs = ApplyHFSModifier(XN);
        auto XKhfs = ApplyHFSModifier(XK);
        auto XXhfs = ApplyHFSModifier(XX);
        auto INhfs = ApplyHFSModifier(IN);
        auto IKhfs = ApplyHFSModifier(IK);
        auto IXhfs = ApplyHFSModifier(IX);

        registry.emplace(NNhfs.m_patternName, std::move(NNhfs));
        registry.emplace(NKhfs.m_patternName, std::move(NKhfs));
        registry.emplace(NXhfs.m_patternName, std::move(NXhfs));
        registry.emplace(KNhfs.m_patternName, std::move(KNhfs));
        registry.emplace(KKhfs.m_patternName, std::move(KKhfs));
        registry.emplace(KXhfs.m_patternName, std::move(KXhfs));
        registry.emplace(XNhfs.m_patternName, std::move(XNhfs));
        registry.emplace(XKhfs.m_patternName, std::move(XKhfs));
        registry.emplace(XXhfs.m_patternName, std::move(XXhfs));
        registry.emplace(INhfs.m_patternName, std::move(INhfs));
        registry.emplace(IKhfs.m_patternName, std::move(IKhfs));
        registry.emplace(IXhfs.m_patternName, std::move(IXhfs));

        // Deferred HFS patterns
        auto NK1hfs = ApplyHFSModifier(NK1);
        auto NX1hfs = ApplyHFSModifier(NX1);
        auto X1Nhfs = ApplyHFSModifier(X1N);
        auto X1Khfs = ApplyHFSModifier(X1K);
        auto XK1hfs = ApplyHFSModifier(XK1);
        auto X1K1hfs = ApplyHFSModifier(X1K1);
        auto X1Xhfs = ApplyHFSModifier(X1X);
        auto XX1hfs = ApplyHFSModifier(XX1);
        auto X1X1hfs = ApplyHFSModifier(X1X1);
        auto K1Nhfs = ApplyHFSModifier(K1N);
        auto K1Khfs = ApplyHFSModifier(K1K);
        auto KK1hfs = ApplyHFSModifier(KK1);
        auto K1K1hfs = ApplyHFSModifier(K1K1);
        auto K1Xhfs = ApplyHFSModifier(K1X);
        auto KX1hfs = ApplyHFSModifier(KX1);
        auto K1X1hfs = ApplyHFSModifier(K1X1);
        auto I1Nhfs = ApplyHFSModifier(I1N);
        auto I1Khfs = ApplyHFSModifier(I1K);
        auto IK1hfs = ApplyHFSModifier(IK1);
        auto I1K1hfs = ApplyHFSModifier(I1K1);
        auto I1Xhfs = ApplyHFSModifier(I1X);
        auto IX1hfs = ApplyHFSModifier(IX1);
        auto I1X1hfs = ApplyHFSModifier(I1X1);

        registry.emplace(NK1hfs.m_patternName, std::move(NK1hfs));
        registry.emplace(NX1hfs.m_patternName, std::move(NX1hfs));
        registry.emplace(X1Nhfs.m_patternName, std::move(X1Nhfs));
        registry.emplace(X1Khfs.m_patternName, std::move(X1Khfs));
        registry.emplace(XK1hfs.m_patternName, std::move(XK1hfs));
        registry.emplace(X1K1hfs.m_patternName, std::move(X1K1hfs));
        registry.emplace(X1Xhfs.m_patternName, std::move(X1Xhfs));
        registry.emplace(XX1hfs.m_patternName, std::move(XX1hfs));
        registry.emplace(X1X1hfs.m_patternName, std::move(X1X1hfs));
        registry.emplace(K1Nhfs.m_patternName, std::move(K1Nhfs));
        registry.emplace(K1Khfs.m_patternName, std::move(K1Khfs));
        registry.emplace(KK1hfs.m_patternName, std::move(KK1hfs));
        registry.emplace(K1K1hfs.m_patternName, std::move(K1K1hfs));
        registry.emplace(K1Xhfs.m_patternName, std::move(K1Xhfs));
        registry.emplace(KX1hfs.m_patternName, std::move(KX1hfs));
        registry.emplace(K1X1hfs.m_patternName, std::move(K1X1hfs));
        registry.emplace(I1Nhfs.m_patternName, std::move(I1Nhfs));
        registry.emplace(I1Khfs.m_patternName, std::move(I1Khfs));
        registry.emplace(IK1hfs.m_patternName, std::move(IK1hfs));
        registry.emplace(I1K1hfs.m_patternName, std::move(I1K1hfs));
        registry.emplace(I1Xhfs.m_patternName, std::move(I1Xhfs));
        registry.emplace(IX1hfs.m_patternName, std::move(IX1hfs));
        registry.emplace(I1X1hfs.m_patternName, std::move(I1X1hfs));

        return registry;
    }

    /** @return Singleton reference to the immutable pattern registry. */
    inline const auto& GetPatternRegistry() {
        static const auto registry = CreatePatternRegistry();
        return registry;
    }

}
