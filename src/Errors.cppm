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
    /// All library errors derive from NoiseError. HandshakeComplete is the completion
    /// marker, not a true error: HandshakeState stores it in HandshakeStatus::err when the
    /// handshake completes, and throws it only from a call made after completion.
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

    /** A handshake or transport message exceeds the configured maximum size (default 65535 bytes). */
    struct MessageSizeError : NoiseError {
        MessageSizeError()
            : NoiseError("noisepqc++: message size exceeded") {}
    };

    /**
     * AEAD decryption failed: the authentication tag did not verify, or the
     * ciphertext is shorter than the tag. Carries no detail from the cipher backend.
     */
    struct DecryptionError : NoiseError {
        DecryptionError()
            : NoiseError("noisepqc++/CipherState: decryption failed") {}
    };

    /**
     * The nonce has reached the reserved value 2^64-1 (Noise spec Section 5.1).
     * No further EncryptWithAd/DecryptWithAd call is allowed on this CipherState.
     */
    struct NonceExhaustedError : NoiseError {
        NonceExhaustedError()
            : NoiseError("noisepqc++/CipherState: nonce exhausted") {}
    };

    /**
     * A peer public key was rejected: a low-order DH point (X25519/X448), an ML-KEM
     * encapsulation key that fails the FIPS 203 Section 7.2 modulus check, or a public
     * key of the wrong length for the algorithm. Carries no detail from the backend.
     */
    struct InvalidPublicKeyError : NoiseError {
        InvalidPublicKeyError()
            : NoiseError("noisepqc++/Dh: invalid public key") {}
    };

    /**
     * Completion marker of a handshake — not an error.
     *
     * When the final handshake message is written or read, HandshakeState stores a
     * HandshakeComplete in HandshakeStatus::err (with state == Done) and the completing
     * call returns normally; HasError() is false. It is thrown only by a WriteMessage()
     * or ReadMessage() call made after completion. Callers take the transport
     * CipherStates with HandshakeState::TakeCipherStates().
     */
    struct HandshakeComplete : NoiseError {
        HandshakeComplete()
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
