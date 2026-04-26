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

export module noise:errors;

import std;

export namespace Noise
{
    /// @name Error Hierarchy
    /// All library errors derive from NoiseError. HandshakeDoneError is a
    /// sentinel (not a true error) used to signal successful handshake completion.
    /// @{

    /** Base error type for all NoisePQC++ library errors. */
    struct NoiseError : std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    /** A received handshake message was shorter than expected for the current token. */
    struct TruncatedMessageError : NoiseError {
        explicit TruncatedMessageError(const std::string& token)
            : NoiseError("noisepqc++/HandshakeState/ReadMessage/" + token + ": truncated message") {}
    };

    /** A required key (static, ephemeral, or KEM) was not set when a token needed it. */
    struct MissingKeyError : NoiseError {
        explicit MissingKeyError(const std::string& token)
            : NoiseError("noisepqc++/HandshakeState/WriteMessage/" + token + ": key not set") {}
    };

    /** The number of provided PSKs does not match the pattern requirement. */
    struct MissingPSKError : NoiseError {
        MissingPSKError()
            : NoiseError("noisepqc++/New: missing or excessive PreSharedKey(s)") {}
    };

    /** A pre-shared key is not the required 32 bytes. */
    struct BadPSKError : NoiseError {
        BadPSKError()
            : NoiseError("noisepqc++/New: malformed PreSharedKey(s)") {}
    };

    /** WriteMessage/ReadMessage called out of turn (wrong party). */
    struct OutOfOrderError : NoiseError {
        OutOfOrderError()
            : NoiseError("noisepqc++/HandshakeState: out of order message") {}
    };

    /** A handshake message exceeds the configured maximum size (default 65535 bytes). */
    struct MessageSizeError : NoiseError {
        MessageSizeError()
            : NoiseError("noisepqc++/HandshakeState: message size exceeded") {}
    };

    /**
     * Sentinel exception signaling successful handshake completion — not an error.
     *
     * Thrown by HandshakeState when the final message is processed. Callers should
     * catch this and retrieve transport CipherStates from HandshakeStatus.
     */
    struct HandshakeDoneError : NoiseError {
        HandshakeDoneError()
            : NoiseError("noisepqc++/HandshakeState: handshake complete") {}
    };

    /** The protocol name string could not be parsed or the pattern/algorithm is unknown. */
    struct ProtocolNotSupportedError : NoiseError {
        ProtocolNotSupportedError()
            : NoiseError("noisepqc++/Protocol: protocol not supported") {}
    };

    /** An unrecognized token was encountered in a handshake pattern. */
    struct InvalidTokenError : NoiseError {
        explicit InvalidTokenError(const std::string& token)
            : NoiseError("noisepqc++/HandshakeState: invalid token: " + token) {}
    };

    /** A required pre-message public key was not provided in HandshakeConfig. */
    struct PreMessageError : NoiseError {
        explicit PreMessageError(const std::string& side, const std::string& token)
            : NoiseError("noisepqc++/New: " + side + " " + token + " not set") {}
    };
    /// @}

    /** Application exit signal (used by examples/sandboxes, not part of the protocol). */
    struct Exit final : std::runtime_error {
        Exit() : std::runtime_error("Exit") {}
    };

    /** @name Error Throwing Helpers */
    /// @{
    [[noreturn]] inline void ThrowNoiseError(const std::string& s)
    {
        throw NoiseError(s);
    }

    [[noreturn]] inline void ThrowNoiseError(const std::string& s, const std::string& s2) {
        ThrowNoiseError(s + s2);
    }

    [[noreturn]] inline void ThrowNoiseError(const std::string& s, const int i) {
        std::ostringstream os;
        os << s << ": " << i;
        ThrowNoiseError(os.str());
    }
}
