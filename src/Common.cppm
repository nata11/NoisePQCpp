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

export module noise:common;

export import std;

export namespace Noise
{
#ifdef NOISE_DEBUG_BUILD
    // Debug build: Runtime toggling is available
    inline bool g_EnableHandshakeLogging = true;
    inline bool g_EnableSymmetricLogging = true;

    // Helper functions for logging control
    inline void DisableAllLogging() {
        g_EnableHandshakeLogging = false;
        g_EnableSymmetricLogging = false;
    }

    inline void EnableAllLogging() {
        g_EnableHandshakeLogging = true;
        g_EnableSymmetricLogging = true;
    }

    inline void SetHandshakeLogging(const bool enable) {
        g_EnableHandshakeLogging = enable;
    }

    inline void SetSymmetricLogging(const bool enable) {
        g_EnableSymmetricLogging = enable;
    }
#else
    // Production build: Logging is not available
    inline constexpr bool g_EnableHandshakeLogging = false;
    inline constexpr bool g_EnableSymmetricLogging = false;

    // Helper functions are no-ops in production mode (no warnings to avoid corrupting stdout)
    inline void DisableAllLogging() {
        // No-op: Logging not available in production builds
    }

    inline void EnableAllLogging() {
        // No-op: Logging not available in production builds
    }

    inline void SetHandshakeLogging([[maybe_unused]] const bool enable) {
        // No-op: Logging not available in production builds
    }

    inline void SetSymmetricLogging([[maybe_unused]] const bool enable) {
        // No-op: Logging not available in production builds
    }
#endif

    /// @name Protocol Constants
    /// @{
    constexpr auto MAX_NONCE = std::numeric_limits<std::uint64_t>::max();  ///< Maximum nonce value (Noise spec Section 5.1).
    constexpr std::uint8_t SYMMETRIC_KEY_SIZE = 32;          ///< Symmetric key size in bytes (Noise spec Section 4.2).
    constexpr std::uint16_t NOISE_MAX_MESSAGE_SIZE = 65535;  ///< Maximum message size in bytes (Noise spec Section 3).
    constexpr std::uint8_t MLKEM_SHARED_SECRET_SIZE = 32;    ///< ML-KEM shared secret size (FIPS 203).
    /// @}

    /// @name ML-KEM Sizes (FIPS 203 Table 3)
    /// @{
    constexpr std::size_t M512_PUBLIC_KEY_SIZE = 800;        ///< ML-KEM-512 encapsulation key size.
    constexpr std::size_t M768_PUBLIC_KEY_SIZE = 1184;       ///< ML-KEM-768 encapsulation key size.
    constexpr std::size_t M1024_PUBLIC_KEY_SIZE = 1568;      ///< ML-KEM-1024 encapsulation key size.
    constexpr std::size_t M512_CIPHERTEXT_SIZE = 768;        ///< ML-KEM-512 ciphertext size.
    constexpr std::size_t M768_CIPHERTEXT_SIZE = 1088;       ///< ML-KEM-768 ciphertext size.
    constexpr std::size_t M1024_CIPHERTEXT_SIZE = 1568;      ///< ML-KEM-1024 ciphertext size.
    /// @}
    constexpr std::string_view protocolPrefix = "Noise";
    constexpr std::string_view SHA256 = "SHA256";
    constexpr std::string_view SHA512 = "SHA512";
    constexpr std::string_view BLAKE2b = "BLAKE2b";
    constexpr std::string_view BLAKE2s = "BLAKE2s";
    constexpr std::string_view AESGCM = "AESGCM";
    constexpr std::string_view ChaChaPoly = "ChaChaPoly";
    constexpr std::string_view X25519 = "25519";
    constexpr std::string_view X448 = "448";
    constexpr std::string_view MLKEM = "ML-KEM";
    constexpr std::string_view M512 = "M512";
    constexpr std::string_view M768 = "M768";
    constexpr std::string_view M1024 = "M1024";

    // ANSI Color codes for logging
    namespace Color {
        constexpr std::string_view Reset = "\033[0m";
        constexpr std::string_view Bold = "\033[1m";
        constexpr std::string_view Red = "\033[31m";
        constexpr std::string_view Green = "\033[32m";
        constexpr std::string_view Yellow = "\033[33m";
        constexpr std::string_view Blue = "\033[34m";
        constexpr std::string_view Magenta = "\033[35m";
        constexpr std::string_view Cyan = "\033[36m";
        constexpr std::string_view White = "\033[37m";
        constexpr std::string_view BrightRed = "\033[91m";
        constexpr std::string_view BrightGreen = "\033[92m";
        constexpr std::string_view BrightYellow = "\033[93m";
        constexpr std::string_view BrightBlue = "\033[94m";
        constexpr std::string_view ExtraBrightBlue = "\033[38;5;81m"; // 256-color mode: very bright cyan-blue
        constexpr std::string_view BrightMagenta = "\033[95m";
        constexpr std::string_view BrightCyan = "\033[96m";
        constexpr std::string_view BrightWhite = "\033[97m";
    }



    // GCC -Wshadow: the enumerators repeat the namespace-scope name constants above (both are
    // public API); scoped enumerators are reachable only qualified, so nothing is shadowed in use.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    /** Supported hash algorithms (Noise spec Section 4.3). */
    enum class HashAlgo {
        SHA256,
        SHA512,
        BLAKE2b,
        BLAKE2s
    };
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

    constexpr std::array<std::pair<HashAlgo, std::string_view>, 4> HashAlgos{
        {
            {HashAlgo::SHA256, "SHA256"},
            {HashAlgo::SHA512, "SHA512"},
            {HashAlgo::BLAKE2b, "BLAKE2b"},
            {HashAlgo::BLAKE2s, "BLAKE2s"}
        }
    };

    constexpr std::string_view GetHashAlgorithmName(const HashAlgo algo) {
        for (const auto& [key, value] : HashAlgos) {
            if (key == algo) {
                return value;
            }
        }
        return "";
    }

    /**
     * Resolves a Noise hash name ("SHA256", "SHA512", "BLAKE2b", "BLAKE2s") to its enum.
     * Exact, case-sensitive match against HashAlgos; any other string is std::nullopt.
     */
    constexpr std::optional<HashAlgo> ParseHashAlgo(const std::string_view name) {
        for (const auto& [key, value] : HashAlgos) {
            if (value == name) {
                return key;
            }
        }
        return std::nullopt;
    }

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    /** Supported AEAD cipher algorithms (Noise spec Section 4.2). */
    enum class CipherAlgo {
        AESGCM,
        ChaChaPoly
    };
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

    constexpr std::array<std::pair<CipherAlgo, std::string_view>, 2> CipherAlgos{
        {
            {CipherAlgo::AESGCM, "AESGCM"},
            {CipherAlgo::ChaChaPoly, "ChaChaPoly"}
        }
    };

    constexpr std::string_view GetCipherAlgorithmName(const CipherAlgo algo) {
        for (const auto& [key, value] : CipherAlgos) {
            if (key == algo) {
                return value;
            }
        }
        return "";
    }

    /**
     * Resolves a Noise cipher name ("ChaChaPoly", "AESGCM") to its enum.
     * Exact, case-sensitive match against CipherAlgos; any other string is std::nullopt.
     */
    constexpr std::optional<CipherAlgo> ParseCipherAlgo(const std::string_view name) {
        for (const auto& [key, value] : CipherAlgos) {
            if (value == name) {
                return key;
            }
        }
        return std::nullopt;
    }

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
    /** Supported key exchange algorithms: DH (X25519, X448) and KEM (ML-KEM variants). */
    enum class KeyAlgo {
        X25519,
        X448,
        M512,
        M768,
        M1024,
    };
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

    constexpr std::array<std::pair<KeyAlgo, std::string_view>, 5> KeyAlgos{
        {
            {KeyAlgo::X25519, "25519"},
            {KeyAlgo::X448, "448"},
            {KeyAlgo::M512, "M512"},
            {KeyAlgo::M768, "M768"},
            {KeyAlgo::M1024, "M1024"},
        }
    };

    constexpr std::string_view GetKeyAlgorithmName(const KeyAlgo algo) {
        for (const auto& [key, value] : KeyAlgos) {
            if (key == algo) {
                return value;
            }
        }
        return "";
    }

    /** Resolves a Noise DH/KEM name ("25519", "448", "M512", "M768", "M1024"; exact,
     *  case-sensitive) through KeyAlgos, like ParseCipherAlgo and ParseHashAlgo. */
    constexpr std::optional<KeyAlgo> ParseKeyAlgo(const std::string_view name) {
        for (const auto& [key, value] : KeyAlgos) {
            if (value == name) {
                return key;
            }
        }
        return std::nullopt;
    }
}
